package vuls2

import (
	"cmp"
	"encoding/json"
	"maps"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
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

// Detect detects vulnerabilities and fills ScanResult
func Detect(r *models.ScanResult, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	switch r.Family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
	default:
		return nil
	}

	if vuls2Conf.Repository == "" {
		vuls2Conf.Repository = DefaultGHCRRepository
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	dbc, err := newDBConnection(vuls2Conf, noProgress)
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

	vulnInfos, err := postConvert(vuls2Scanned, vuls2Detected)
	if err != nil {
		return xerrors.Errorf("Failed to post convert. err: %w", err)
	}

	for cveID, vi := range vulnInfos {
		viBase, found := r.ScannedCves[cveID]
		if !found {
			viBase = vi
		} else {
			viBase.AffectedPackages = append(viBase.AffectedPackages, vi.AffectedPackages...)
			for _, da := range vi.DistroAdvisories {
				viBase.DistroAdvisories.AppendIfMissing(&da)
			}
			for _, c := range vi.Confidences {
				viBase.Confidences.AppendIfMissing(c)
			}
			for ccType, cc := range vi.CveContents {
				viBase.CveContents[ccType] = append(viBase.CveContents[ccType], cc...)
			}
		}
		r.ScannedCves[cveID] = viBase
	}

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
		m, err := ospkg.Detect(dbc, sr, runtime.NumCPU())
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

type source struct {
	RootID   dataTypes.RootID     `json:"root_id,omitempty"`
	SourceID sourceTypes.SourceID `json:"source_id,omitempty"`
	Segment  segmentTypes.Segment `json:"segment,omitempty"`
}

type pack struct {
	sourceID sourceTypes.SourceID
	tags     []segmentTypes.DetectionTag

	status models.PackageFixStatus
}

func postConvert(scanned scanTypes.ScanResult, detected detectTypes.DetectResult) (models.VulnInfos, error) {
	sm, cm, err := walkVulnerabilityDetections(scanned, detected.Detected)
	if err != nil {
		return nil, xerrors.Errorf("Failed to walk detections. err: %w", err)
	}

	sm2 := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[string]pack)
	for src, statuses := range sm {
		if sm2[src.Segment.Ecosystem] == nil {
			sm2[src.Segment.Ecosystem] = make(map[dataTypes.RootID]map[string]pack)
		}
		if sm2[src.Segment.Ecosystem][src.RootID] == nil {
			sm2[src.Segment.Ecosystem][src.RootID] = make(map[string]pack)
		}
		for _, status := range statuses {
			base, ok := sm2[src.Segment.Ecosystem][src.RootID][status.Name]
			if ok {
				result, err := comparePack(src.Segment.Ecosystem, base, pack{
					sourceID: src.SourceID,
					tags:     []segmentTypes.DetectionTag{src.Segment.Tag},

					status: status,
				})
				if err != nil {
					return nil, xerrors.Errorf("Failed to compare pack. err: %w", err)
				}

				switch result {
				case 0:
					base.tags = append(base.tags, src.Segment.Tag)
				case +1:
					base = pack{
						sourceID: src.SourceID,
						tags:     []segmentTypes.DetectionTag{src.Segment.Tag},

						status: status,
					}
				case -1:
				default:
				}
			} else {
				base = pack{
					sourceID: src.SourceID,
					tags:     []segmentTypes.DetectionTag{src.Segment.Tag},

					status: status,
				}
			}
			sm2[src.Segment.Ecosystem][src.RootID][status.Name] = base
		}
	}

	var sources []source

	rsm := make(map[dataTypes.RootID]models.PackageFixStatuses)
	for e, m := range sm2 {
		for rootID, mm := range m {
			for _, p := range mm {
				rsm[rootID] = append(rsm[rootID], p.status)

				if len(p.tags) == 0 {
					sources = append(sources, source{
						RootID:   rootID,
						SourceID: p.sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: e,
						},
					})
				} else {
					for _, tag := range p.tags {
						sources = append(sources, source{
							RootID:   rootID,
							SourceID: p.sourceID,
							Segment: segmentTypes.Segment{
								Ecosystem: e,
								Tag:       tag,
							},
						})
					}
				}

			}
		}
	}

	rcm := make(map[dataTypes.RootID][]string)
	for src, cpes := range cm {
		for _, cpe := range cpes {
			if !slices.Contains(rcm[src.RootID], cpe) {
				rcm[src.RootID] = append(rcm[src.RootID], cpe)
			}
		}
		sources = append(sources, src)
	}

	vm := walkVulnerabilityDatas(detected.Detected, sources)

	type vulnsrcs struct {
		info    models.VulnInfo
		sources []source
	}

	rvm := make(map[string]vulnsrcs)
	for src, m := range vm {
		for _, i := range m {
			base, ok := rvm[i.CveID]
			if ok {
				merged, err := mergeVulnInfo(base.info, i)
				if err != nil {
					return nil, xerrors.Errorf("Failed to merge vuln info. err: %w", err)
				}
				base.info = merged
				base.sources = append(base.sources, src)
			} else {
				base = vulnsrcs{
					info:    i,
					sources: []source{src},
				}
			}
			rvm[i.CveID] = base
		}
	}

	m := make(models.VulnInfos)
	for cveID, v := range rvm {
		pkgs := make(map[string]models.PackageFixStatus)
		cpes := make(map[string]struct{})
		for _, src := range v.sources {
			v.info.Confidences.AppendIfMissing(toVuls0Confidence(src.Segment.Ecosystem, src.SourceID))

			for _, status := range rsm[src.RootID] {
				//
			}

			for _, c := range rcm[src.RootID] {
				cpes[c] = struct{}{}
			}
		}
		m[cveID] = v.info
	}

	return m, nil
}

func walkVulnerabilityDetections(scanned scanTypes.ScanResult, vs []detectTypes.VulnerabilityData) (map[source]models.PackageFixStatuses, map[source][]string, error) {
	sm := make(map[source]models.PackageFixStatuses)
	cm := make(map[source][]string)
	for _, v := range vs {
		for _, d := range v.Detections {
			for sourceID, fconds := range d.Contents {
				for _, fcond := range fconds {
					statuses, cpes, _, err := walkCriteria(d.Ecosystem, sourceID, fcond.Criteria, scanned)
					if err != nil {
						return nil, nil, xerrors.Errorf("Failed to collect fix statuses. err: %w", err)
					}
					sm[source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}] = append(sm[source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}], statuses...)
					cm[source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}] = append(cm[source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}], cpes...)
				}
			}
		}
	}
	return sm, cm, nil
}

func walkCriteria(e ecosystemTypes.Ecosystem, sourceID sourceTypes.SourceID, ca criteriaTypes.FilteredCriteria, scanned scanTypes.ScanResult) (models.PackageFixStatuses, []string, bool, error) {
	var (
		statuses models.PackageFixStatuses //nolint:prealloc
		cpes     []string
	)
	for _, child := range ca.Criterias { //nolint:misspell
		ss, cs, ignore, err := walkCriteria(e, sourceID, child, scanned)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("Failed to collect fix statuses. err: %w", err)
		}
		if ignore {
			switch ca.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return nil, nil, ignore, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return nil, nil, false, xerrors.Errorf("unexpected operator: %s", ca.Operator)
			}
		}
		statuses = append(statuses, ss...)
		cpes = append(cpes, cs...)
	}

	for _, cn := range ca.Criterions {
		if ignoreCriteria(e, sourceID, cn) {
			return nil, nil, true, nil
		}

		if cn.Criterion.Type != criterionTypes.CriterionTypeVersion || cn.Criterion.Version == nil {
			continue
		}

		if ignoreCriterion(e, cn) {
			continue
		}

		switch cn.Criterion.Version.Package.Type {
		case vcPackageTypes.PackageTypeBinary, vcPackageTypes.PackageTypeSource:
			fixedIn := func() string {
				if cn.Criterion.Version.Affected == nil || len(cn.Criterion.Version.Affected.Fixed) == 0 {
					return ""
				}
				return selectFixedIn(e, cn.Criterion.Version.Affected.Fixed)
			}()

			for _, index := range cn.Accepts.Version {
				if len(scanned.OSPackages) <= index {
					return nil, nil, false, xerrors.Errorf("Too large OSPackage index. len(OSPackage): %d, index: %d", len(scanned.OSPackages), index)
				}
				statuses = append(statuses, models.PackageFixStatus{
					Name: affectedPackageName(e, scanned.OSPackages[index]),
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
		case vcPackageTypes.PackageTypeCPE:
			for _, index := range cn.Accepts.Version {
				if len(scanned.CPE) <= index {
					return nil, nil, false, xerrors.Errorf("Too large CPE index. len(CPE): %d, index: %d", len(scanned.CPE), index)
				}
			}
			cpes = append(cpes, string(*cn.Criterion.Version.Package.CPE))
		default:
		}
	}
	return statuses, cpes, false, nil
}

func walkVulnerabilityDatas(vds []detectTypes.VulnerabilityData, sources []source) (map[source]models.VulnInfos, error) {
	vm := make(map[source]models.VulnInfos)

	for _, vd := range vds {
		am := make(map[source]models.DistroAdvisories)
		for _, vda := range vd.Advisories {
			for sid, rm := range vda.Contents {
				for rid, as := range rm {
					for _, a := range as {
						for _, segment := range a.Segments {
							src := source{
								RootID:   rid,
								SourceID: sid,
								Segment:  segment,
							}

							if !slices.Contains(sources, src) {
								continue
							}

							am[src] = append(am[src], models.DistroAdvisory{
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
							})
						}
					}
				}
			}
		}

		for _, vdv := range vd.Vulnerabilities {
			for sid, rm := range vdv.Contents {
				for rid, vs := range rm {
					for _, v := range vs {
						for _, segment := range v.Segments {
							src := source{
								RootID:   rid,
								SourceID: sid,
								Segment:  segment,
							}

							if !slices.Contains(sources, src) {
								continue
							}

							cctype := func() models.CveContentType {
								switch segment.Ecosystem {
								case ecosystemTypes.EcosystemTypeCPE:
									switch sid {
									case sourceTypes.NVDAPICVE, sourceTypes.NVDFeedCVE:
										return models.Nvd
									case sourceTypes.JVNFeedRSS, sourceTypes.JVNFeedDetail:
										return models.Jvn
									case sourceTypes.Fortinet:
										return models.Fortinet
									default:
										return models.Unknown
									}
								default:
									family, _, _ := strings.Cut(string(segment.Ecosystem), ":")
									return models.NewCveContentType(family)
								}
							}()

							cvss2, cvss3, cvss40 := toCvss(v.Content.Severity)

							if vm[src] == nil {
								vm[src] = make(models.VulnInfos)
							}

							vinfo, err := func() (models.VulnInfo, error) {
								bs, err := json.Marshal([]source{src})
								if err != nil {
									return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
								}

								return models.VulnInfo{
									CveID:            string(v.Content.ID),
									DistroAdvisories: am[src],
									CveContents: models.NewCveContents(models.CveContent{
										Type:           cctype,
										CveID:          string(v.Content.ID),
										Title:          v.Content.Title,
										Summary:        v.Content.Description,
										Cvss2Score:     cvss2.BaseScore,
										Cvss2Vector:    cvss2.Vector,
										Cvss2Severity:  cvss2.NVDBaseSeverity,
										Cvss3Score:     cvss3.BaseScore,
										Cvss3Vector:    cvss3.Vector,
										Cvss3Severity:  cvss3.BaseSeverity,
										Cvss40Score:    cvss40.Score,
										Cvss40Vector:   cvss40.Vector,
										Cvss40Severity: cvss40.Severity,
										SourceLink:     cveContentSourceLink(cctype, v),
										References: func() models.References {
											rs := make(models.References, 0, len(v.Content.References))
											for _, r := range v.Content.References {
												rs = append(rs, models.Reference{
													Link: r.URL,
												})
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
											if v.Content.Modified != nil {
												return *v.Content.Modified
											}
											return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
										}(),
										LastModified: func() time.Time {
											if v.Content.Modified != nil {
												return *v.Content.Modified
											}
											return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
										}(),
										Optional: map[string]string{"vuls2-sources": string(bs)},
									}),
								}, nil
							}()
							if err != nil {
								return nil, xerrors.Errorf("Failed to create vuln info. err: %w", err)
							}
							vm[src][string(v.Content.ID)] = vinfo
						}
					}
				}
			}
		}
	}

	return vm, nil
}

func comparePack(e ecosystemTypes.Ecosystem, a, b pack) (int, error) {
	if r := compareSourceID(e, a.sourceID, b.sourceID); r != 0 {
		return r, nil
	}

	for _, btag := range a.tags {
		for _, ntag := range b.tags {
			if r := compareTag(e, a.sourceID, btag, ntag); r != 0 {
				return r, nil
			}
		}
	}

	if a.status.Name != b.status.Name {
		return 0, xerrors.Errorf("Package names are different. a: %s, b: %s", a.status.Name, b.status.Name)
	}

	return cmp.Or(
		func() int {
			switch {
			case a.status.NotFixedYet && b.status.NotFixedYet:
				return 0
			case a.status.NotFixedYet && !b.status.NotFixedYet:
				return +1
			case !a.status.NotFixedYet && b.status.NotFixedYet:
				return -1
			default:
				return 0
			}
		}(),
		compareFixedIn(e, a.status.FixedIn, b.status.FixedIn),
	), nil
}

func mergeVulnInfo(a, b models.VulnInfo) (models.VulnInfo, error) {
	if a.CveID != b.CveID {
		return models.VulnInfo{}, xerrors.Errorf("CVE IDs are different. a: %s, b: %s", a.CveID, b.CveID)
	}

	info := models.VulnInfo{
		CveID: a.CveID,
	}

	am := make(map[string]models.DistroAdvisory)
	for _, a := range append(slices.Clone(a.DistroAdvisories), b.DistroAdvisories...) {
		base, ok := am[a.AdvisoryID]
		if ok {
			if cmp.Or(
				compareSeverity(base.Severity, a.Severity),
				base.Issued.Compare(a.Issued),
				base.Updated.Compare(a.Updated),
			) > 0 {
				base = a
			}
		} else {
			base = a
		}
		am[a.AdvisoryID] = base
	}
	info.DistroAdvisories = slices.Collect(maps.Values(am))

	ccm := make(map[models.CveContentType]models.CveContent)
	for _, cc := range append(slices.Collect(maps.Values(a.CveContents)), slices.Collect(maps.Values(b.CveContents))...) {
		for _, c := range cc {
			base, ok := ccm[c.Type]
			if ok {
				var src1 []source
				if err := json.Unmarshal([]byte(base.Optional["vuls2-sources"]), &src1); err != nil {
					return models.VulnInfo{}, xerrors.Errorf("Failed to unmarshal sources. err: %w", err)
				}
				var src2 []source
				if err := json.Unmarshal([]byte(c.Optional["vuls2-sources"]), &src2); err != nil {
					return models.VulnInfo{}, xerrors.Errorf("Failed to unmarshal sources. err: %w", err)
				}

				if cmp.Or(
					cmp.Compare(base.Cvss40Score, c.Cvss40Score),
					cmp.Compare(base.Cvss3Score, c.Cvss3Score),
					cmp.Compare(base.Cvss2Score, c.Cvss2Score),
				) > 0 {
					base = c
				}

				bs, err := json.Marshal(append(src1, src2...))
				if err != nil {
					return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
				}
				base.Optional["vuls2-sources"] = string(bs)
			} else {
				base = c
			}
			ccm[c.Type] = base
		}
	}
	ccs := make(models.CveContents)
	for cctype, cc := range ccm {
		ccs[cctype] = []models.CveContent{cc}
	}
	info.CveContents = ccs

	return info, nil
}

func compareSeverity(a, b string) int {
	rank := func(severity string) int {
		switch strings.ToUpper(severity) {
		case "CRITICAL":
			return 4
		case "IMPORTANT", "HIGH":
			return 3
		case "MODERATE", "MEDIUM":
			return 2
		case "LOW", "NEGLIGIBLE":
			return 1
		default:
			return 0
		}
	}

	return cmp.Compare(rank(a), rank(b))
}

func toCvss(ss []severityTypes.Severity) (v2.CVSSv2, v31.CVSSv31, v40.CVSSv40) {
	var (
		cvss2 v2.CVSSv2
		cvss3 v31.CVSSv31
		cvss4 v40.CVSSv40
	)

	for _, s := range ss {
		switch s.Type {
		case severityTypes.SeverityTypeCVSSv2:
			if cvss2.Vector == "" && s.CVSSv2 != nil {
				cvss2 = *s.CVSSv2
			}
		case severityTypes.SeverityTypeCVSSv30:
			if cvss3.Vector == "" && s.CVSSv30 != nil {
				cvss3 = v31.CVSSv31{
					Vector:       s.CVSSv30.Vector,
					BaseScore:    s.CVSSv30.BaseScore,
					BaseSeverity: s.CVSSv30.BaseSeverity,
				}
			}
		case severityTypes.SeverityTypeCVSSv31:
			if !strings.HasPrefix(cvss3.Vector, "CVSS:3.1/") && s.CVSSv31 != nil {
				cvss3 = *s.CVSSv31
			}
		case severityTypes.SeverityTypeCVSSv40:
			if cvss4.Vector == "" && s.CVSSv40 != nil {
				cvss4 = *s.CVSSv40
			}
		default:
		}
	}

	return cvss2, cvss3, cvss4
}
