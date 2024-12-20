package vuls2

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/MaineK00n/vuls2/pkg/version"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

var cveRe = regexp.MustCompile("CVE-[0-9]{4}-[0-9]+")

func Detect(r *models.ScanResult, vuls2Cnf config.Vuls2DictConf, noProgress bool) error {
	switch r.Family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
	default:
		return nil
	}

	if vuls2Cnf.Repository == "" {
		vuls2Cnf.Repository = DefaultGHCRRepository
	}
	if vuls2Cnf.Path == "" {
		vuls2Cnf.Path = DefaultPath
	}

	dbc, err := newDBConnection(vuls2Cnf, noProgress)
	if err != nil {
		return xerrors.Errorf("Failed to get new db connection. err: %w", err)
	}
	if err := dbc.Open(); err != nil {
		return xerrors.Errorf("Failed to open db. err: %w", err)
	}
	defer dbc.Close()

	vuls2Scanned := preConvert(r)

	vuls2Detected, err := detect(dbc, vuls2Scanned)
	if err != nil {
		return xerrors.Errorf("Failed to detect. err: %w", err)
	}

	e, err := ecosystemTypes.GetEcosystem(r.Family, r.Release)
	if err != nil {
		return xerrors.Errorf("Failed to get ecosystem. family: %s, release: %s, err: %w", r.Family, r.Release, err)
	}

	vulnInfos, err := postConvert(e, r.Family, vuls2Detected, vuls2Scanned)
	if err != nil {
		return xerrors.Errorf("Failed to post convert. err: %w", err)
	}

	r.ScannedCves = vulnInfos
	logging.Log.Infof("%s: %d CVEs are detected with vuls2", r.FormatServerName(), len(vulnInfos))

	return nil
}

func preConvert(sr *models.ScanResult) scanTypes.ScanResult {
	pkgs := make(map[string]scanTypes.OSPackage)
	for _, p := range sr.SrcPackages {
		for _, bn := range p.BinaryNames {
			pkgs[bn] = scanTypes.OSPackage{
				SrcName:    p.Name,
				SrcVersion: p.Version,
			}
		}
	}
	for _, p := range sr.Packages {
		base := pkgs[p.Name]
		base.Name = p.Name
		base.Version = p.Version
		base.Release = p.Release
		base.NewVersion = p.NewVersion
		base.NewRelease = p.NewRelease
		base.Arch = p.Arch
		base.Repository = p.Repository
		base.ModularityLabel = p.ModularityLabel
		pkgs[p.Name] = base
	}

	return scanTypes.ScanResult{
		JSONVersion: 0,
		ServerName:  sr.ServerName,
		Family:      ecosystemTypes.Ecosystem(sr.Family),
		Release:     sr.Release,

		Kernel: scanTypes.Kernel{
			Release:        sr.RunningKernel.Release,
			Version:        sr.RunningKernel.Version,
			RebootRequired: sr.RunningKernel.RebootRequired,
		},
		OSPackages: slices.Collect(maps.Values(pkgs)),

		ScannedAt: time.Now(),
		ScannedBy: version.String(),
	}
}

// Almost copied from vuls2 pkg/detect/detect.go
func detect(dbc db.DB, sr scanTypes.ScanResult) (detectTypes.DetectResult, error) {
	detected := make(map[dataTypes.RootID]detectTypes.VulnerabilityData)

	if len(sr.OSPackages) > 0 {
		m, err := ospkg.Detect(dbc, sr)
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to detect os packages. err: %w", err)
		}
		for rootID, d := range m {
			base, ok := detected[rootID]
			if !ok {
				base = detectTypes.VulnerabilityData{ID: rootID}
			}
			base.Detections = append(base.Detections, d)
			detected[rootID] = base
		}
	}

	for rootID, base := range detected {
		d, err := dbc.GetVulnerabilityData(dbTypes.SearchDataRoot, string(rootID))
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get vulnerability data. RootID: %s, err: %w", rootID, err)
		}
		base.Advisories = d.Advisories
		base.Vulnerabilities = d.Vulnerabilities
		detected[rootID] = base
	}

	var sourceIDs []sourceTypes.SourceID
	for _, data := range detected {
		for _, a := range data.Advisories {
			for sourceID := range a.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, v := range data.Vulnerabilities {
			for sourceID := range v.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, d := range data.Detections {
			for sourceID := range d.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
	}

	datasources := make([]datasourceTypes.DataSource, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		s, err := dbc.GetDataSource(sourceID)
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get datasource. sourceID: %s, err: %w", sourceID, err)
		}
		datasources = append(datasources, *s)
	}

	return detectTypes.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,

		Detected:    slices.Collect(maps.Values(detected)),
		DataSources: datasources,

		DetectedAt: time.Now(),
		DetectedBy: version.String(),
	}, nil
}

type pack struct {
	name     string
	rootID   dataTypes.RootID
	sourceID sourceTypes.SourceID
	tag      segmentTypes.DetectionTag
	status   models.PackageFixStatus
}

type sourceVulnInfo struct {
	sourceID sourceTypes.SourceID
	rootID   dataTypes.RootID
	tags     []segmentTypes.DetectionTag
	vulnInfo models.VulnInfo
}

func postConvert(e ecosystemTypes.Ecosystem, family string, vuls2Detected detectTypes.DetectResult, vuls2Scanned scanTypes.ScanResult) (models.VulnInfos, error) {
	pm, err := collectPackages(e, family, vuls2Detected, vuls2Scanned.OSPackages)
	if err != nil {
		return nil, xerrors.Errorf("Failed to collect packages. server: %s, err: %w", vuls2Detected.ServerName, err)
	}

	// am := collectAdvisories(e, family, vuls2Detected)
	// cveMap := collectCVEs(e, family, vuls2Detected, am)

	pmmmmm := make(map[vcTypes.VulnerabilityID]map[string]map[sourceTypes.SourceID]map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack)
	for _, vulndata := range vuls2Detected.Detected {
		rootID := vulndata.ID
		for _, vdv := range vulndata.Vulnerabilities {
			vulnID := vdv.ID
			for sourceID, rm := range vdv.Contents {
				for _, vs := range rm {
					for _, v := range vs {
						if !includesEcosystem(v.Segments, e) {
							continue
						}

						pkgs := getPackages(rootID, sourceID, v.Segments, pm)
						for _, p := range pkgs {
							pmmmm, found := pmmmmm[vulnID]
							if !found {
								pmmmm = make(map[string]map[sourceTypes.SourceID]map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack)
							}
							pmmm, found := pmmmm[p.name]
							if !found {
								pmmm = make(map[sourceTypes.SourceID]map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack)
							}
							pmm, found := pmmm[sourceID]
							if !found {
								pmm = make(map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack)
							}
							pm, found := pmm[dataTypes.RootID(rootID)]
							if !found {
								pm = make(map[segmentTypes.DetectionTag]pack)
							}
							pm[p.tag] = p
							pmm[rootID] = pm
							pmmm[sourceID] = pmm
							pmmmm[p.name] = pmmm
							pmmmmm[vulnID] = pmmmm
						}
					}
				}
			}
		}
	}

	psm := make(map[vcTypes.VulnerabilityID][]pack)
	for vulnID, pmmmm := range pmmmmm {
		for _, pmmm := range pmmmm {
			pkgs := extractPkgs(family, pmmm)
			if len(pkgs) == 0 {
				continue
			}
			psm[vulnID] = append(psm[vulnID], pkgs[0])
		}
	}

	res := models.VulnInfos{}
	for vulnID, ps := range psm {
		res[string(vulnID)] = models.VulnInfo{
			CveID: string(vulnID),
			AffectedPackages: func() []models.PackageFixStatus {
				ss := make([]models.PackageFixStatus, 0, len(ps))
				for _, p := range ps {
					ss = append(ss, p.status)
				}
				return ss
			}(),
		}
	}
	return res, nil
}

func getPackages(rootID dataTypes.RootID, sourceID sourceTypes.SourceID, segments []segmentTypes.Segment, pmmmm map[dataTypes.RootID]map[sourceTypes.SourceID]map[segmentTypes.DetectionTag]map[string]pack) []pack {
	var ps []pack
	if _, found := pmmmm[rootID]; !found {
		return nil
	}
	if _, found := pmmmm[rootID][sourceID]; !found {
		return nil
	}
	for _, s := range segments {
		pm, found := pmmmm[rootID][sourceID][s.Tag]
		if !found {
			return nil
		}
		for _, p := range pm {
			ps = append(ps, p)
		}
	}
	return ps
}

func collectPackages(e ecosystemTypes.Ecosystem, family string, dres detectTypes.DetectResult, ospkgs []scanTypes.OSPackage) (map[dataTypes.RootID]map[sourceTypes.SourceID]map[segmentTypes.DetectionTag]map[string]pack, error) {
	pm := make(map[dataTypes.RootID]map[sourceTypes.SourceID]map[segmentTypes.DetectionTag]map[string]pack)
	for _, detected := range dres.Detected {

		if _, found := pm[detected.ID]; !found {
			pm[detected.ID] = make(map[sourceTypes.SourceID]map[segmentTypes.DetectionTag]map[string]pack)
		}
		for _, detections := range detected.Detections {
			if detections.Ecosystem != e {
				continue
			}

			for sourceID, fconds := range detections.Contents {
				if _, found := pm[detected.ID][sourceID]; !found {
					pm[detected.ID][sourceID] = make(map[segmentTypes.DetectionTag]map[string]pack)
				}
				for _, fcond := range fconds {
					if _, found := pm[detected.ID][sourceID][fcond.Tag]; !found {
						pm[detected.ID][sourceID][fcond.Tag] = make(map[string]pack)
					}

					statuses, ignoresAll, err := collectFixStatuses(family, detected.ID, fcond.Criteria, ospkgs)
					if err != nil {
						return nil, xerrors.Errorf("Failed to collect fix statuses. err: %w", err)
					}

					if ignoresAll {
						continue
					}
					for _, status := range statuses {
						// FIXME: redundant
						pm[detected.ID][sourceID][fcond.Tag][status.Name] = pack{
							name:     status.Name,
							rootID:   detected.ID,
							sourceID: sourceID,
							tag:      fcond.Tag,
							status:   status,
						}
					}
				}
			}
		}
	}
	return pm, nil
}

func collectFixStatuses(family string, rootID dataTypes.RootID, ca criteriaTypes.FilteredCriteria, ospkgs []scanTypes.OSPackage) ([]models.PackageFixStatus, bool, error) {
	var statuses []models.PackageFixStatus //nolint:prealloc
	for _, child := range ca.Criterias {   //nolint:misspell
		ss, ignoresAll, err := collectFixStatuses(family, rootID, child, ospkgs)
		if err != nil {
			return nil, false, xerrors.Errorf("Failed to collect fix statuses. err: %w", err)
		}
		if ignoresAll {
			return nil, ignoresAll, nil
		}
		statuses = append(statuses, ss...)
	}

	for _, cn := range ca.Criterions {
		if ignoresWholeCriteria(family, cn) {
			return nil, true, nil
		}

		if cn.Criterion.Type != criterionTypes.CriterionTypeVersion || cn.Criterion.Version == nil {
			continue
		}

		if ignoresCriterion(family, cn) {
			continue
		}

		fixedIn := func() string {
			if cn.Criterion.Version.Affected == nil || len(cn.Criterion.Version.Affected.Fixed) == 0 {
				return ""
			}
			return selectFixedIn(family, cn.Criterion.Version.Affected.Fixed)
		}()

		for _, index := range cn.Accepts.Version {
			if len(ospkgs) <= index {
				return nil, false, xerrors.Errorf("Too large OSPackage index. len(OSPackage): %d, index: %d", len(ospkgs), index)
			}
			statuses = append(statuses, models.PackageFixStatus{
				Name: affectedPackageName(family, ospkgs[index]),
				FixState: func() string {
					if cn.Criterion.Version.FixStatus == nil {
						return ""
					}
					return cn.Criterion.Version.FixStatus.Vendor
				}(),
				FixedIn:     fixedIn,
				NotFixedYet: fixedIn == "",
			})
		}

	}
	return statuses, false, nil
}

func collectVulns(e ecosystemTypes.Ecosystem, dres detectTypes.DetectResult) map[dataTypes.RootID]map[vcTypes.VulnerabilityID]map[sourceTypes.SourceID]vulnerabilityTypes.Vulnerability {
	mmm := make(map[dataTypes.RootID]map[vcTypes.VulnerabilityID]map[sourceTypes.SourceID]vulnerabilityTypes.Vulnerability)

	for _, detected := range dres.Detected {
		for _, dv := range detected.Vulnerabilities {
			for sourceID, rm := range dv.Contents {
				for rootID, vs := range rm {
					for _, v := range vs {
						if !includesEcosystem(v.Segments, e) {
							continue
						}
						mm, found := mmm[rootID]
						if !found {
							mm = make(map[vcTypes.VulnerabilityID]map[sourceTypes.SourceID]vulnerabilityTypes.Vulnerability)
						}
						m, found := mm[v.Content.ID]
						if !found {
							m = make(map[sourceTypes.SourceID]vulnerabilityTypes.Vulnerability)
						}

						m[sourceID] = v
						mm[v.Content.ID] = m
						mmm[rootID] = mm
					}
				}
			}
		}
	}

	return mmm
}

func collectCVEs(e ecosystemTypes.Ecosystem, family string, dres detectTypes.DetectResult, am map[dataTypes.RootID]map[sourceTypes.SourceID]advisoryTypes.Advisory) map[dataTypes.RootID]map[vcTypes.VulnerabilityID]sourceVulnInfo {
	m := make(map[dataTypes.RootID]map[vcTypes.VulnerabilityID]sourceVulnInfo)

	for _, detected := range dres.Detected {
		for _, dv := range detected.Vulnerabilities {
			for sourceID, rm := range dv.Contents {
				for rootID, vs := range rm {
					for _, v := range vs {
						if !includesEcosystem(v.Segments, e) {
							continue
						}
						if _, found := m[rootID]; !found {
							m[rootID] = make(map[vcTypes.VulnerabilityID]sourceVulnInfo)
						}

						a := func() *advisoryTypes.Advisory {
							sourceIDMap, found := am[rootID]
							if !found {
								return nil
							}
							a, found := sourceIDMap[sourceID]
							if !found {
								return nil
							}
							return &a
						}()
						da := toDistoAdvisory(a)
						if ignoresVulnerability(family, v, a) {
							continue
						}

						cvss2, cvss3 := toCvss(v, da)

						ccType := models.NewCveContentType(family)
						cc := models.CveContents{
							ccType: []models.CveContent{
								{
									Type:  ccType,
									CveID: string(v.Content.ID),
									Title: func() string {
										if a != nil {
											return a.Content.Title
										}
										return v.Content.Title
									}(),
									Summary: func() string {
										if a != nil {
											return a.Content.Description
										}
										return v.Content.Description
									}(),
									Cvss2Score:    cvss2.BaseScore,
									Cvss2Vector:   cvss2.Vector,
									Cvss2Severity: cvss2.NVDBaseSeverity,
									Cvss3Score:    cvss3.BaseScore,
									Cvss3Vector:   cvss3.Vector,
									Cvss3Severity: cvss3.BaseSeverity,
									SourceLink:    cveContentSourceLink(ccType, v),
									References: func() models.References {
										refs := v.Content.References
										if a != nil {
											refs = a.Content.References
										}
										rs := make([]models.Reference, 0, len(refs))
										for _, r := range refs {
											if a != nil && (strings.Contains(r.URL, string(a.Content.ID)) || strings.Contains(r.URL, strings.ReplaceAll(string(a.Content.ID), ":", "-"))) {
												rs = append(rs, models.Reference{
													Link:   r.URL,
													Source: advisoryReferenceSource(family, r),
													RefID:  string(a.Content.ID),
												})
											}
											if cveID := cveRe.FindString(r.URL); cveID != "" {
												rs = append(rs, models.Reference{
													Link:   r.URL,
													Source: "CVE",
													RefID:  cveID,
												})
											}
										}
										return rs
									}(),

									CweIDs: func() []string {
										var cs []string
										for _, cwe := range v.Content.CWE {
											cs = append(cs, cwe.CWE...)
										}
										return cs
									}(),
									Published: func() time.Time {
										if a != nil && a.Content.Published != nil {
											return *a.Content.Published
										}
										if v.Content.Modified != nil {
											return *v.Content.Modified
										}
										return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
									}(),
									LastModified: func() time.Time {
										if a != nil && a.Content.Modified != nil {
											return *a.Content.Modified
										}
										if v.Content.Modified != nil {
											return *v.Content.Modified
										}
										return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
									}(),
									Optional: cveContentOptional(family, rootID, sourceID),
								},
							},
						}

						svi := sourceVulnInfo{
							sourceID: sourceID,
							rootID:   rootID,
							tags:     toTags(v.Segments),
							vulnInfo: models.VulnInfo{
								CveID:       string(v.Content.ID),
								Confidences: models.Confidences{models.OvalMatch},
								DistroAdvisories: func() []models.DistroAdvisory {
									if da != nil {
										return []models.DistroAdvisory{*da}
									}
									return nil
								}(),
								CveContents: cc,
							},
						}
						if base, found := m[rootID][v.Content.ID]; found {
							svi = resolveSourceVulnInfo(family, base, svi)
						}
						m[rootID][v.Content.ID] = svi
					}
				}
			}
		}
	}

	return m
}

func collectAdvisories(e ecosystemTypes.Ecosystem, family string, dres detectTypes.DetectResult) map[dataTypes.RootID]map[sourceTypes.SourceID]advisoryTypes.Advisory {
	am := make(map[dataTypes.RootID]map[sourceTypes.SourceID]advisoryTypes.Advisory)
	for _, detected := range dres.Detected {
		for _, da := range detected.Advisories {
			for sid, rm := range da.Contents {
				for rid, as := range rm {
					if _, found := am[rid]; !found {
						am[rid] = make(map[sourceTypes.SourceID]advisoryTypes.Advisory)
					}
					for _, a := range as {
						if !includesEcosystem(a.Segments, e) {
							continue
						}

						base, found := am[rid][sid]
						if found {
							a = resolveAdvisoryByTag(family, base, a)
						}
						am[rid][sid] = a
					}
				}
			}
		}
	}

	return am
}

func toTags(ss []segmentTypes.Segment) []segmentTypes.DetectionTag {
	ts := make([]segmentTypes.DetectionTag, 0, len(ss))
	for _, s := range ss {
		ts = append(ts, s.Tag)
	}
	return ts
}

func toCvss(v vulnerabilityTypes.Vulnerability, da *models.DistroAdvisory) (v2.CVSSv2, v31.CVSSv31) {
	cvss2 := func() v2.CVSSv2 {
		for _, s := range v.Content.Severity {
			if s.Type == severityTypes.SeverityTypeCVSSv2 && s.CVSSv2 != nil {
				return *s.CVSSv2
			}
		}
		return v2.CVSSv2{}
	}()
	cvss3 := func() v31.CVSSv31 {
		for _, s := range v.Content.Severity {
			if s.Type == severityTypes.SeverityTypeCVSSv31 && s.CVSSv31 != nil {
				return *s.CVSSv31
			}
		}
		for _, s := range v.Content.Severity {
			if s.Type == severityTypes.SeverityTypeCVSSv30 && s.CVSSv30 != nil {
				return v31.CVSSv31{
					Vector:       s.CVSSv30.Vector,
					BaseScore:    s.CVSSv30.BaseScore,
					BaseSeverity: s.CVSSv30.BaseSeverity,
				}
			}
		}
		return v31.CVSSv31{}
	}()

	advisorySeverity := func() string {
		for _, s := range v.Content.Severity {
			if s.Type != severityTypes.SeverityTypeVendor || s.Vendor == nil || *s.Vendor == "" {
				continue
			}
			return *s.Vendor
		}
		if da != nil {
			return da.Severity
		}
		return ""
	}()
	if advisorySeverity != "None" {
		cvss3.BaseSeverity = advisorySeverity
		if cvss2.BaseScore != 0 {
			cvss2.NVDBaseSeverity = advisorySeverity
		}
	}

	return cvss2, cvss3
}

func toDistoAdvisory(a *advisoryTypes.Advisory) *models.DistroAdvisory {
	if a == nil {
		return nil
	}

	return &models.DistroAdvisory{
		AdvisoryID: string(a.Content.ID),
		Severity: func() string {
			for _, s := range a.Content.Severity {
				if s.Type == severityTypes.SeverityTypeVendor && s.Vendor != nil {
					return *s.Vendor
				}
			}
			return ""
		}(),
		Issued: func() time.Time {
			if a.Content.Published != nil {
				return *a.Content.Published
			}
			return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
		}(),
		Updated: func() time.Time {
			if a.Content.Modified != nil {
				return *a.Content.Modified
			}
			return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
		}(),
		Description: a.Content.Description,
	}
}

func includesEcosystem(s []segmentTypes.Segment, e ecosystemTypes.Ecosystem) bool {
	return slices.ContainsFunc(s, func(s segmentTypes.Segment) bool {
		return s.Ecosystem == e
	})
}
