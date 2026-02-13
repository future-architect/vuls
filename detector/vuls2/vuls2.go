package vuls2

import (
	"cmp"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	severityVendorTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/vendor"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/MaineK00n/vuls2/pkg/version"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// defaultRegistory is GitHub Container Registry for vuls2 db
const defaultRegistory = "ghcr.io/vulsio/vuls-nightly-db"

// Detect detects vulnerabilities and fills ScanResult
func Detect(r *models.ScanResult, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	if vuls2Conf.Repository == "" {
		sv, err := session.SchemaVersion("boltdb")
		if err != nil {
			return xerrors.Errorf("Failed to get schema version. err: %w", err)
		}

		vuls2Conf.Repository = fmt.Sprintf("%s:%d", defaultRegistory, sv)
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	dbConfig, err := newDBConfig(vuls2Conf, noProgress)
	if err != nil {
		return xerrors.Errorf("Failed to get new db connection. err: %w", err)
	}

	sesh, err := dbConfig.New()
	if err != nil {
		return xerrors.Errorf("Failed to new db session. err: %w", err)
	}

	defer sesh.Cache().Close()

	if err := sesh.Storage().Open(); err != nil {
		return xerrors.Errorf("Failed to open db. err: %w", err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return xerrors.Errorf("Failed to get metadata. err: %w", err)
	}
	config.Conf.Vuls2.Digest = metadata.Digest

	vuls2Scanned := preConvert(r)

	vuls2Detected, err := detect(sesh, vuls2Scanned)
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
		base.Version = preConvertBinaryVersion(sr.Family, p.Version)
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

func detect(sesh *session.Session, sr scanTypes.ScanResult) (detectTypes.DetectResult, error) {
	detected := make(map[dataTypes.RootID]detectTypes.VulnerabilityData)

	if len(sr.OSPackages) > 0 {
		m, err := ospkg.Detect(sesh.Storage(), sr, runtime.NumCPU())
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to detect os packages. err: %w", err)
		}
		for rootID, d := range m {
			base := detectTypes.VulnerabilityData{
				ID:         rootID,
				Detections: []detectTypes.VulnerabilityDataDetection{d},
			}

			avs, err := sesh.GetVulnerabilityData(rootID, dbTypes.Filter{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeAdvisories,
					dbTypes.FilterContentTypeVulnerabilities,
				},
				RootIDs:     []dataTypes.RootID{rootID},
				Ecosystems:  []ecosystemTypes.Ecosystem{d.Ecosystem},
				DataSources: slices.Collect(maps.Keys(d.Contents)),
			})
			if err != nil {
				return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get vulnerability data. RootID: %s, err: %w", rootID, err)
			}

			base.Advisories = avs.Advisories
			base.Vulnerabilities = avs.Vulnerabilities
			detected[rootID] = base
		}
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
		s, err := sesh.Storage().GetDataSource(sourceID)
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get datasource. sourceID: %s, err: %w", sourceID, err)
		}
		datasources = append(datasources, s)
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
	Segment  segmentTypes.Segment `json:"segment,omitzero"`
}

type sourceData struct {
	detectableCveIDs []string
	vulninfos        models.VulnInfos
	packStatuses     []packStatus
	cpes             []string
}

type rootTag struct {
	rootID dataTypes.RootID
	tag    segmentTypes.DetectionTag
}

type pack struct {
	ecosystem ecosystemTypes.Ecosystem
	sourceID  sourceTypes.SourceID
	rootTags  []rootTag

	packStatus packStatus
}

type packStatus struct {
	rangeType vcAffectedRangeTypes.RangeType
	status    models.PackageFixStatus
}

func postConvert(scanned scanTypes.ScanResult, detected detectTypes.DetectResult) (models.VulnInfos, error) {
	m := make(map[source]sourceData)

	if err := walkVulnerabilityDetections(m, scanned, detected.Detected); err != nil {
		return nil, xerrors.Errorf("Failed to walk detections. err: %w", err)
	}

	if err := walkVulnerabilityDatas(m, detected.Detected); err != nil {
		return nil, xerrors.Errorf("Failed to walk vulnerability data. err: %w", err)
	}

	type affected struct {
		packm map[string]pack
		cpes  []string
	}

	am := make(map[string]affected)
	for src, vd := range m {
		for _, vi := range vd.vulninfos {
			base := am[vi.CveID]

			if len(vd.packStatuses) > 0 {
				if base.packm == nil {
					base.packm = make(map[string]pack)
				}
				for _, status := range vd.packStatuses {
					p, ok := base.packm[status.status.Name]
					if ok {
						result, err := comparePack(p, pack{
							ecosystem: src.Segment.Ecosystem,
							sourceID:  src.SourceID,
							rootTags: []rootTag{{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							}},
							packStatus: packStatus{
								rangeType: status.rangeType,
								status:    status.status,
							},
						})
						if err != nil {
							return nil, xerrors.Errorf("Failed to compare pack. err: %w", err)
						}
						switch result {
						case 0:
							p.rootTags = append(p.rootTags, rootTag{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							})
						case -1:
							p = pack{
								ecosystem: src.Segment.Ecosystem,
								sourceID:  src.SourceID,
								rootTags: []rootTag{{
									rootID: src.RootID,
									tag:    src.Segment.Tag,
								}},
								packStatus: packStatus{
									rangeType: status.rangeType,
									status:    status.status,
								},
							}
						default:
						}
					} else {
						p = pack{
							ecosystem: src.Segment.Ecosystem,
							sourceID:  src.SourceID,
							rootTags: []rootTag{{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							}},
							packStatus: packStatus{
								rangeType: status.rangeType,
								status:    status.status,
							},
						}
					}
					base.packm[status.status.Name] = p
				}
			}

			if len(vd.cpes) > 0 {
				for _, cpe := range vd.cpes {
					if !slices.Contains(base.cpes, cpe) {
						base.cpes = append(base.cpes, cpe)
					}
				}
				if !slices.Contains(vd.detectableCveIDs, vi.CveID) {
					vd.detectableCveIDs = append(vd.detectableCveIDs, vi.CveID)
				}
			}

			am[vi.CveID] = base
		}

		m[src] = vd
	}
	for cveID, mm := range am {
		for _, p := range mm.packm {
			for _, tag := range p.rootTags {
				src := source{
					RootID:   tag.rootID,
					SourceID: p.sourceID,
					Segment: segmentTypes.Segment{
						Ecosystem: p.ecosystem,
						Tag:       tag.tag,
					},
				}
				base := m[src]
				if !slices.Contains(base.detectableCveIDs, cveID) {
					base.detectableCveIDs = append(base.detectableCveIDs, cveID)
				}
				m[src] = base
			}
		}
	}

	vim := make(models.VulnInfos)
	for _, vd := range m {
		for _, vi := range vd.vulninfos {
			if !slices.Contains(vd.detectableCveIDs, vi.CveID) {
				continue
			}

			base, ok := vim[vi.CveID]
			if ok {
				merged, err := mergeVulnInfo(base, vi)
				if err != nil {
					return nil, xerrors.Errorf("Failed to merge vuln info. err: %w", err)
				}
				base = merged
			} else {
				base = vi
			}
			vim[vi.CveID] = base
		}
	}
	for _, vi := range vim {
		ps := make(models.PackageFixStatuses, 0, len(am[vi.CveID].packm))
		for _, p := range am[vi.CveID].packm {
			ps = append(ps, p.packStatus.status)
		}
		vi.AffectedPackages = ps
		vi.CpeURIs = am[vi.CveID].cpes

		vim[vi.CveID] = vi
	}

	return vim, nil
}

func walkVulnerabilityDetections(m map[source]sourceData, scanned scanTypes.ScanResult, vs []detectTypes.VulnerabilityData) error {
	for _, v := range vs {
		for _, d := range v.Detections {
			for sourceID, fconds := range d.Contents {
				for _, fcond := range fconds {
					ca, err := pruneCriteria(fcond.Criteria)
					if err != nil {
						return xerrors.Errorf("Failed to prune criteria. err: %w", err)
					}

					statuses, cpes, _, err := walkCriteria(d.Ecosystem, sourceID, ca, fcond.Tag, scanned)
					if err != nil {
						return xerrors.Errorf("Failed to walk criteria. err: %w", err)
					}
					if len(statuses) == 0 && len(cpes) == 0 {
						continue
					}

					src := source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}
					base := m[src]
					base.packStatuses = append(base.packStatuses, statuses...)
					base.cpes = append(base.cpes, cpes...)
					m[src] = base
				}
			}
		}
	}
	return nil
}

func pruneCriteria(c criteriaTypes.FilteredCriteria) (criteriaTypes.FilteredCriteria, error) {
	pruned := criteriaTypes.FilteredCriteria{
		Operator: c.Operator,
		Criterias: func() []criteriaTypes.FilteredCriteria {
			if len(c.Criterias) > 0 {
				return make([]criteriaTypes.FilteredCriteria, 0, len(c.Criterias))
			}
			return nil
		}(),
		Criterions: func() []criterionTypes.FilteredCriterion {
			if len(c.Criterions) > 0 {
				return make([]criterionTypes.FilteredCriterion, 0, len(c.Criterions))
			}
			return nil
		}(),
	}

	for _, child := range c.Criterias {
		child, err := pruneCriteria(child)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("prune criteria: %w", err)
		}

		if len(child.Criterias) == 0 && len(child.Criterions) == 0 {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterias = append(pruned.Criterias, child)
	}

	for _, cn := range c.Criterions {
		isAffected, err := cn.Affected()
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("criterion affected: %w", err)
		}

		if !isAffected {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterions = append(pruned.Criterions, cn)
	}

	return pruned, nil
}

func walkCriteria(e ecosystemTypes.Ecosystem, sourceID sourceTypes.SourceID, ca criteriaTypes.FilteredCriteria, tag segmentTypes.DetectionTag, scanned scanTypes.ScanResult) ([]packStatus, []string, bool, error) {
	var (
		statuses []packStatus
		cpes     []string
	)
	for _, child := range ca.Criterias {
		ss, cs, ignore, err := walkCriteria(e, sourceID, child, tag, scanned)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("Failed to walk criteria. err: %w", err)
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

		if ignoreCriterion(e, cn, tag) {
			continue
		}

		fcn, err := filterCriterion(e, scanned, cn)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("Failed to filter criterion. err: %w", err)
		}

		switch fcn.Criterion.Version.Package.Type {
		case vcPackageTypes.PackageTypeBinary, vcPackageTypes.PackageTypeSource:
			rangeType, fixedIn := func() (vcAffectedRangeTypes.RangeType, string) {
				if fcn.Criterion.Version.Affected == nil {
					return vcAffectedRangeTypes.RangeTypeUnknown, ""
				}
				return fcn.Criterion.Version.Affected.Type, selectFixedIn(fcn.Criterion.Version.Affected.Type, fcn.Criterion.Version.Affected.Fixed)
			}()

			for _, index := range fcn.Accepts.Version {
				if len(scanned.OSPackages) <= index {
					return nil, nil, false, xerrors.Errorf("Too large OSPackage index. len(OSPackage): %d, index: %d", len(scanned.OSPackages), index)
				}
				statuses = append(statuses, packStatus{
					rangeType: rangeType,
					status: models.PackageFixStatus{
						Name: affectedPackageName(e, scanned.OSPackages[index]),
						FixState: func() string {
							if fcn.Criterion.Version.FixStatus == nil {
								return ""
							}
							return fixState(e, sourceID, fcn.Criterion.Version.FixStatus.Vendor)
						}(),
						FixedIn:     fixedIn,
						NotFixedYet: fixedIn == "",
					},
				})
			}
		case vcPackageTypes.PackageTypeCPE:
			for _, index := range fcn.Accepts.Version {
				if len(scanned.CPE) <= index {
					return nil, nil, false, xerrors.Errorf("Too large CPE index. len(CPE): %d, index: %d", len(scanned.CPE), index)
				}
			}
			cpes = append(cpes, string(*fcn.Criterion.Version.Package.CPE))
		default:
		}
	}
	return statuses, cpes, false, nil
}

func walkVulnerabilityDatas(m map[source]sourceData, vds []detectTypes.VulnerabilityData) error {
	for _, vd := range vds {
		am := make(map[source]models.DistroAdvisories)
		for _, vda := range vd.Advisories {
			for sid, rm := range vda.Contents {
				if rm == nil {
					return xerrors.Errorf("advisories map is nil, root id: %q -> advisories[source id: %q]", vd.ID, sid)
				}
				for _, a := range rm[vd.ID] {
					for _, segment := range a.Segments {
						src := source{
							RootID:   vd.ID,
							SourceID: sid,
							Segment:  segment,
						}

						if _, ok := m[src]; !ok {
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

		for _, vdv := range vd.Vulnerabilities {
			for sid, rm := range vdv.Contents {
				if rm == nil {
					return xerrors.Errorf("vulnerabilities map is nil, root id: %q -> vulnerabilities[source id: %q]", vd.ID, sid)
				}
				for _, v := range rm[vd.ID] {
					for _, segment := range v.Segments {
						src := source{
							RootID:   vd.ID,
							SourceID: sid,
							Segment:  segment,
						}

						if _, ok := m[src]; !ok {
							continue
						}

						if ignoreVulnerability(src.Segment.Ecosystem, v, am[src]) {
							continue
						}

						vinfo, err := func() (models.VulnInfo, error) {
							bs, err := json.Marshal([]source{src})
							if err != nil {
								return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
							}

							fdas := filterDistroAdvisories(src.Segment.Ecosystem, am[src])
							cctype := toCveContentType(src.Segment.Ecosystem, sid)
							cvss2, cvss3, cvss40 := toCvss(src.Segment.Ecosystem, sid, v.Content.Severity)

							var rs models.References
							for _, r := range v.Content.References {
								rs = append(rs, toReference(r.URL))
							}
							for _, da := range fdas {
								ar, err := advisoryReference(src.Segment.Ecosystem, src.SourceID, da)
								if err != nil {
									return models.VulnInfo{}, xerrors.Errorf("Failed to get advisory reference. err: %w", err)
								}
								if !slices.ContainsFunc(rs, func(r models.Reference) bool {
									return r.Link == ar.Link && r.Source == ar.Source && r.RefID == ar.RefID && slices.Equal(r.Tags, ar.Tags)
								}) {
									rs = append(rs, ar)
								}
							}

							return models.VulnInfo{
								CveID:            string(v.Content.ID),
								Confidences:      models.Confidences{toVuls0Confidence(src.Segment.Ecosystem, src.SourceID)},
								DistroAdvisories: fdas,
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
									References:     rs,
									CweIDs: func() []string {
										var cs []string
										for _, cwe := range v.Content.CWE {
											cs = append(cs, cwe.CWE...)
										}
										return cs
									}(),
									Published: func() time.Time {
										if v.Content.Published != nil {
											return *v.Content.Published
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
							return xerrors.Errorf("Failed to create vuln info. err: %w", err)
						}

						base := m[src]
						if base.vulninfos == nil {
							base.vulninfos = make(models.VulnInfos)
						}
						base.vulninfos[vinfo.CveID] = vinfo
						m[src] = base
					}
				}
			}
		}
	}
	return nil
}

func comparePack(a, b pack) (int, error) {
	if a.ecosystem == b.ecosystem {
		if r := compareSourceID(a.ecosystem, a.sourceID, b.sourceID); r != 0 {
			return r, nil
		}

		maxTagFn := func(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, tags []rootTag) segmentTypes.DetectionTag {
			rt := slices.MaxFunc(tags, func(a, b rootTag) int {
				return compareTag(e, s, a.tag, b.tag)
			})
			return rt.tag
		}

		if r := compareTag(a.ecosystem, a.sourceID, maxTagFn(a.ecosystem, a.sourceID, a.rootTags), maxTagFn(b.ecosystem, b.sourceID, b.rootTags)); r != 0 {
			return r, nil
		}
	}

	r, err := comparePackStatus(a.packStatus, b.packStatus)
	if err != nil {
		return 0, xerrors.Errorf("Failed to compare pack status. err: %w", err)
	}

	return r, nil
}

func mergeVulnInfo(a, b models.VulnInfo) (models.VulnInfo, error) {
	if a.CveID != b.CveID {
		return models.VulnInfo{}, xerrors.Errorf("CVE IDs are different. a: %s, b: %s", a.CveID, b.CveID)
	}

	info := models.VulnInfo{
		CveID:       a.CveID,
		CveContents: models.CveContents{},
	}

	for _, cc := range []models.Confidences{a.Confidences, b.Confidences} {
		for _, c := range cc {
			info.Confidences.AppendIfMissing(c)
		}
	}

	am := make(map[string]models.DistroAdvisory)
	for _, as := range []models.DistroAdvisories{a.DistroAdvisories, b.DistroAdvisories} {
		for _, a := range as {
			base, ok := am[a.AdvisoryID]
			if ok {
				if cmp.Or(
					severityVendorTypes.Compare("", base.Severity, a.Severity),
					base.Issued.Compare(a.Issued),
					base.Updated.Compare(a.Updated),
				) < 0 {
					base = a
				}
			} else {
				base = a
			}
			am[a.AdvisoryID] = base
		}
	}
	info.DistroAdvisories = slices.Collect(maps.Values(am))

	ccm := make(map[models.CveContentType]models.CveContent)
	for _, cciter := range []iter.Seq[[]models.CveContent]{maps.Values(a.CveContents), maps.Values(b.CveContents)} {
		for cc := range cciter {
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

					merged := models.CveContent{
						Type:         base.Type,
						CveID:        base.CveID,
						Title:        base.Title,
						Summary:      base.Summary,
						SSVC:         base.SSVC,
						SourceLink:   base.SourceLink,
						Published:    base.Published,
						LastModified: base.LastModified,
						Optional:     base.Optional,
					}

					if compareSource(slices.MaxFunc(src1, compareSource), slices.MaxFunc(src2, compareSource)) < 0 {
						merged = models.CveContent{
							Type:         c.Type,
							CveID:        c.CveID,
							Title:        c.Title,
							Summary:      c.Summary,
							SSVC:         c.SSVC,
							SourceLink:   c.SourceLink,
							Published:    c.Published,
							LastModified: c.LastModified,
							Optional:     c.Optional,
						}
					}

					switch cmp.Compare(base.Cvss40Score, c.Cvss40Score) {
					case -1:
						merged.Cvss40Score = c.Cvss40Score
						merged.Cvss40Vector = c.Cvss40Vector
						merged.Cvss40Severity = c.Cvss40Severity
					default:
						merged.Cvss40Score = base.Cvss40Score
						merged.Cvss40Vector = base.Cvss40Vector
						merged.Cvss40Severity = base.Cvss40Severity
					}

					switch {
					case strings.HasPrefix(base.Cvss3Vector, "CVSS:3.0") && strings.HasPrefix(c.Cvss3Vector, "CVSS:3.1"):
						merged.Cvss3Score = c.Cvss3Score
						merged.Cvss3Vector = c.Cvss3Vector
						merged.Cvss3Severity = c.Cvss3Severity
					case strings.HasPrefix(base.Cvss3Vector, "CVSS:3.1") && strings.HasPrefix(c.Cvss3Vector, "CVSS:3.0"):
						merged.Cvss3Score = base.Cvss3Score
						merged.Cvss3Vector = base.Cvss3Vector
						merged.Cvss3Severity = base.Cvss3Severity
					default:
						switch cmp.Compare(base.Cvss3Score, c.Cvss3Score) {
						case -1:
							merged.Cvss3Score = c.Cvss3Score
							merged.Cvss3Vector = c.Cvss3Vector
							merged.Cvss3Severity = c.Cvss3Severity
						default:
							merged.Cvss3Score = base.Cvss3Score
							merged.Cvss3Vector = base.Cvss3Vector
							merged.Cvss3Severity = base.Cvss3Severity
						}
					}

					switch cmp.Compare(base.Cvss2Score, c.Cvss2Score) {
					case -1:
						merged.Cvss2Score = c.Cvss2Score
						merged.Cvss2Vector = c.Cvss2Vector
						merged.Cvss2Severity = c.Cvss2Severity
					default:
						merged.Cvss2Score = base.Cvss2Score
						merged.Cvss2Vector = base.Cvss2Vector
						merged.Cvss2Severity = base.Cvss2Severity
					}

					for _, rs := range []models.References{base.References, c.References} {
						for _, r := range rs {
							if !slices.ContainsFunc(merged.References, func(e models.Reference) bool {
								return r.Link == e.Link && r.Source == e.Source && r.RefID == e.RefID && slices.Equal(r.Tags, e.Tags)
							}) {
								merged.References = append(merged.References, r)
							}
						}
					}

					for _, cs := range [][]string{base.CweIDs, c.CweIDs} {
						for _, c := range cs {
							if !slices.Contains(merged.CweIDs, c) {
								merged.CweIDs = append(merged.CweIDs, c)
							}
						}
					}

					srcs := append(src1, src2...)
					slices.SortFunc(srcs, compareSource)
					bs, err := json.Marshal(srcs)
					if err != nil {
						return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
					}
					merged.Optional["vuls2-sources"] = string(bs)

					base = merged
				} else {
					base = c
				}
				ccm[c.Type] = base
			}
		}
	}
	ccs := make(models.CveContents)
	for cctype, cc := range ccm {
		ccs[cctype] = []models.CveContent{cc}
	}
	info.CveContents = ccs

	return info, nil
}

func toReference(ref string) models.Reference {
	switch {
	case strings.HasPrefix(ref, "https://www.cve.org/CVERecord?id="):
		return models.Reference{
			Link:   ref,
			Source: "CVE",
			RefID:  strings.TrimPrefix(ref, "https://www.cve.org/CVERecord?id="),
		}
	case strings.HasPrefix(ref, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="):
		return models.Reference{
			Link:   ref,
			Source: "MITRE",
			RefID:  strings.TrimPrefix(ref, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="),
		}
	case strings.HasPrefix(ref, "https://nvd.nist.gov/vuln/detail/"):
		return models.Reference{
			Link:   ref,
			Source: "NVD",
			RefID:  strings.TrimPrefix(ref, "https://nvd.nist.gov/vuln/detail/"),
		}
	case strings.HasPrefix(ref, "https://access.redhat.com/"), strings.HasPrefix(ref, "https://bugzilla.redhat.com/"):
		switch {
		case strings.HasPrefix(ref, "https://access.redhat.com/security/cve/"):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://access.redhat.com/security/cve/"),
			}
		case strings.HasPrefix(ref, "https://access.redhat.com/errata/"):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://access.redhat.com/errata/"),
			}
		case strings.HasPrefix(ref, "https://bugzilla.redhat.com/show_bug.cgi?id="):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://bugzilla.redhat.com/show_bug.cgi?id="),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
			}
		}
	case strings.HasPrefix(ref, "https://bodhi.fedoraproject.org/"):
		switch {
		case strings.HasPrefix(ref, "https://bodhi.fedoraproject.org/updates/"):
			return models.Reference{
				Link:   ref,
				Source: "FEDORA",
				RefID:  strings.TrimPrefix(ref, "https://bodhi.fedoraproject.org/updates/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "FEDORA",
			}
		}
	case strings.HasPrefix(ref, "https://errata.almalinux.org/"):
		u, err := url.Parse(ref)
		if err != nil {
			return models.Reference{
				Link:   ref,
				Source: "ALMA",
			}
		}

		ss := strings.Split(strings.TrimSuffix(path.Base(u.Path), ".html"), "-")
		if len(ss) != 3 {
			return models.Reference{
				Link:   ref,
				Source: "ALMA",
			}
		}

		return models.Reference{
			Link:   ref,
			Source: "ALMA",
			RefID:  fmt.Sprintf("%s-%s:%s", ss[0], ss[1], ss[2]),
		}
	case strings.HasPrefix(ref, "https://errata.build.resf.org/"):
		return models.Reference{
			Link:   ref,
			Source: "ROCKY",
			RefID:  strings.TrimPrefix(ref, "https://errata.build.resf.org/"),
		}
	case strings.HasPrefix(ref, "https://linux.oracle.com/"):
		switch {
		case strings.HasPrefix(ref, "https://linux.oracle.com/cve/"):
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
				RefID:  strings.TrimPrefix(strings.TrimSuffix(ref, ".html"), "https://linux.oracle.com/cve/"),
			}
		case strings.HasPrefix(ref, "https://linux.oracle.com/errata/"):
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
				RefID:  strings.TrimPrefix(strings.TrimSuffix(ref, ".html"), "https://linux.oracle.com/errata/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
			}
		}
	case strings.HasPrefix(ref, "https://security.alpinelinux.org/vuln/"):
		return models.Reference{
			Link:   ref,
			Source: "ALPINE",
			RefID:  strings.TrimPrefix(ref, "https://security.alpinelinux.org/vuln/"),
		}
	case strings.HasPrefix(ref, "https://ubuntu.com/security/"):
		switch {
		case strings.HasPrefix(ref, "https://ubuntu.com/security/CVE-"):
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
				RefID:  strings.TrimPrefix(ref, "https://ubuntu.com/security/"),
			}
		case strings.HasPrefix(ref, "https://ubuntu.com/security/notices/"):
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
				RefID:  strings.TrimPrefix(ref, "https://ubuntu.com/security/notices/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
			}
		}
	default:
		return models.Reference{
			Link:   ref,
			Source: "MISC",
		}
	}
}
