package vuls2

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	rpm "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	versioncriterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

	"github.com/future-architect/vuls/models"
)

func ignoreVulnerability(e ecosystemTypes.Ecosystem, v vulnerabilityTypes.Vulnerability, as models.DistroAdvisories) bool {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeRedHat:
		if strings.Contains(v.Content.Description, "** REJECT **") || strings.HasPrefix(v.Content.Description, "[REJECTED CVE]") {
			return true
		}

		if len(as) == 0 {
			return false
		}

		if len(filterDistroAdvisories(e, as)) == 0 {
			return true
		}

		return false
	default:
		return false
	}
}

func filterDistroAdvisories(e ecosystemTypes.Ecosystem, as models.DistroAdvisories) models.DistroAdvisories {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeRedHat:
		var fas models.DistroAdvisories
		for _, a := range as {
			if !strings.Contains(a.Description, "** REJECT **") {
				fas = append(fas, a)
			}
		}
		return fas
	default:
		return as
	}

}

func ignoreCriteria(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, cn criterionTypes.FilteredCriterion) bool {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeRedHat:
		switch s {
		case sourceTypes.RedHatOVALv1, sourceTypes.RedHatOVALv2:
			// Ignore whole criteria from root if kpatch-patch-* package is included.
			switch cn.Criterion.Type {
			case criterionTypes.CriterionTypeVersion:
				if cn.Criterion.Version != nil &&
					cn.Criterion.Version.Package.Type == versioncriterionpackageTypes.PackageTypeBinary && cn.Criterion.Version.Package.Binary != nil &&
					strings.HasPrefix(cn.Criterion.Version.Package.Binary.Name, "kpatch-patch-") {
					return true
				}
				return false
			case criterionTypes.CriterionTypeNoneExist:
				if cn.Criterion.NoneExist != nil &&
					cn.Criterion.NoneExist.Type == noneexistcriterionTypes.PackageTypeBinary && cn.Criterion.NoneExist.Binary != nil &&
					strings.HasPrefix(cn.Criterion.NoneExist.Binary.Name, "kpatch-patch-") {
					return true
				}
				return false
			default:
				return false
			}
		default:
			return false
		}
	default:
		return false
	}
}

func ignoreCriterion(e ecosystemTypes.Ecosystem, cn criterionTypes.FilteredCriterion) bool {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeRedHat:
		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			if cn.Criterion.Version != nil && cn.Criterion.Version.FixStatus != nil && cn.Criterion.Version.FixStatus.Class == fixstatusTypes.ClassUnfixed {
				switch strings.ToLower(cn.Criterion.Version.FixStatus.Vendor) {
				case "will not fix", "under investigation":
					return true
				}
			}
			return false
		default:
			return false
		}
	default:
		return false
	}
}

func affectedPackageName(e ecosystemTypes.Ecosystem, pkg scanTypes.OSPackage) string {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	default:
		return pkg.Name
	}
}

func selectFixedIn(rangeType vcAffectedRangeTypes.RangeType, fixed []string) string {
	if len(fixed) == 0 {
		return ""
	}

	switch rangeType {
	case vcAffectedRangeTypes.RangeTypeRPM:
		return slices.MaxFunc(fixed, func(x, y string) int {
			return rpm.NewVersion(x).Compare(rpm.NewVersion(y))
		})
	default:
		return fixed[0]
	}
}

func comparePackStatus(a, b packStatus) (int, error) {
	if a.status.Name != b.status.Name {
		return 0, xerrors.Errorf("Package names are different. a: %s, b: %s", a.status.Name, b.status.Name)
	}

	if a.rangeType != vcAffectedRangeTypes.RangeTypeUnknown && b.rangeType != vcAffectedRangeTypes.RangeTypeUnknown && a.rangeType != b.rangeType {
		return 0, xerrors.Errorf("Range types are different. a: %s, b: %s", a.rangeType, b.rangeType)
	}

	return cmp.Or(
		func() int {
			switch {
			case a.status.NotFixedYet && !b.status.NotFixedYet:
				return +1
			case !a.status.NotFixedYet && b.status.NotFixedYet:
				return -1
			default:
				return 0
			}
		}(),
		func() int {
			if a.rangeType == vcAffectedRangeTypes.RangeTypeUnknown || b.rangeType == vcAffectedRangeTypes.RangeTypeUnknown || a.rangeType != b.rangeType {
				return 0
			}

			switch a.rangeType {
			case vcAffectedRangeTypes.RangeTypeRPM:
				return rpm.NewVersion(a.status.FixedIn).Compare(rpm.NewVersion(b.status.FixedIn))
			default:
				return 0
			}
		}(),
	), nil
}

func advisoryReference(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, da models.DistroAdvisory) (models.Reference, error) {
	et, v, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeCPE:
		switch s {
		case sourceTypes.JVNFeedRSS, sourceTypes.JVNFeedDetail:
			ss := strings.Split(da.AdvisoryID, "-")
			if len(ss) != 3 {
				return models.Reference{}, xerrors.Errorf("unexpected JVNDB ID: %s", da.AdvisoryID)
			}
			return models.Reference{
				Link:   fmt.Sprintf("https://jvndb.jvn.jp/ja/contents/%s/%s.html", ss[1], da.AdvisoryID),
				Source: "JVN",
				RefID:  da.AdvisoryID,
			}, nil
		case sourceTypes.Fortinet:
			return models.Reference{
				Link:   fmt.Sprintf("https://www.fortiguard.com/psirt/%s", da.AdvisoryID),
				Source: "FORTINET",
				RefID:  da.AdvisoryID,
			}, nil
		case sourceTypes.PaloAltoCSAF, sourceTypes.PaloAltoJSON, sourceTypes.PaloAltoList:
			return models.Reference{
				Link: func() string {
					if strings.HasPrefix(da.AdvisoryID, "PAN-CVE-") {
						return fmt.Sprintf("https://security.paloaltonetworks.com/%s", strings.TrimPrefix(da.AdvisoryID, "PAN-"))
					}
					return fmt.Sprintf("https://security.paloaltonetworks.com/%s", da.AdvisoryID)
				}(),
				Source: "PALOALTO",
				RefID:  da.AdvisoryID,
			}, nil
		case sourceTypes.CiscoCSAF, sourceTypes.CiscoCVRF, sourceTypes.CiscoJSON:
			return models.Reference{
				Link:   fmt.Sprintf("https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/%s", da.AdvisoryID),
				Source: "CISCO",
				RefID:  da.AdvisoryID,
			}, nil
		default:
			return models.Reference{}, xerrors.Errorf("unsupported source: %s", s)
		}
	case ecosystemTypes.EcosystemTypeEPEL:
		return models.Reference{
			Link:   fmt.Sprintf("https://bodhi.fedoraproject.org/updates/%s", da.AdvisoryID),
			Source: "FEDORA",
			RefID:  da.AdvisoryID,
		}, nil
	case ecosystemTypes.EcosystemTypeRedHat:
		return models.Reference{
			Link:   fmt.Sprintf("https://access.redhat.com/errata/%s", da.AdvisoryID),
			Source: "REDHAT",
			RefID:  da.AdvisoryID,
		}, nil
	case ecosystemTypes.EcosystemTypeAlma:
		return models.Reference{
			Link:   fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", v, strings.ReplaceAll(da.AdvisoryID, ":", "-")),
			Source: "ALMA",
			RefID:  da.AdvisoryID,
		}, nil
	case ecosystemTypes.EcosystemTypeRocky:
		return models.Reference{
			Link:   fmt.Sprintf("https://errata.build.resf.org/%s", da.AdvisoryID),
			Source: "ROCKY",
			RefID:  da.AdvisoryID,
		}, nil
	default:
		return models.Reference{}, xerrors.Errorf("unsupported family: %s", et)
	}
}

func cveContentSourceLink(ccType models.CveContentType, v vulnerabilityTypes.Vulnerability) string {
	switch ccType {
	case models.RedHat:
		return fmt.Sprintf("https://access.redhat.com/security/cve/%s", v.Content.ID)
	case models.Nvd:
		return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.Content.ID)
	default:
		return ""
	}
}

func compareSource(a, b source) int {
	preferenceFn := func(e ecosystemTypes.Ecosystem) int {
		et, _, _ := strings.Cut(string(e), ":")

		switch et {
		case ecosystemTypes.EcosystemTypeCPE:
			return 0
		case ecosystemTypes.EcosystemTypeEPEL:
			return 1
		default:
			return 2
		}
	}
	return cmp.Or(
		cmp.Compare(preferenceFn(a.Segment.Ecosystem), preferenceFn(b.Segment.Ecosystem)),
		compareSourceID(a.Segment.Ecosystem, a.SourceID, b.SourceID),
		compareTag(a.Segment.Ecosystem, a.SourceID, a.Segment.Tag, b.Segment.Tag),
		cmp.Compare(a.RootID, b.RootID),
		cmp.Compare(a.Segment.Tag, b.Segment.Tag),
	)
}

func compareSourceID(e ecosystemTypes.Ecosystem, a, b sourceTypes.SourceID) int {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeCPE:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.NVDAPICVE, sourceTypes.JVNFeedDetail, sourceTypes.Fortinet, sourceTypes.PaloAltoCSAF, sourceTypes.CiscoCSAF:
				return 4
			case sourceTypes.NVDFeedCVE, sourceTypes.JVNFeedRSS, sourceTypes.PaloAltoJSON, sourceTypes.CiscoCVRF:
				return 3
			case sourceTypes.PaloAltoList, sourceTypes.CiscoJSON:
				return 2
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(a), preferenceFn(b))
	case ecosystemTypes.EcosystemTypeRedHat:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.RedHatCSAF:
				return 5
			case sourceTypes.RedHatVEX:
				return 4
			case sourceTypes.RedHatOVALv2:
				return 3
			case sourceTypes.RedHatOVALv1:
				return 2
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(a), preferenceFn(b))
	case ecosystemTypes.EcosystemTypeAlma:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.AlmaErrata:
				return 4
			case sourceTypes.AlmaOVAL:
				return 3
			case sourceTypes.AlmaOSV:
				return 2
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(a), preferenceFn(b))
	case ecosystemTypes.EcosystemTypeRocky:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.RockyErrata:
				return 3
			case sourceTypes.RockyOSV:
				return 2
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(a), preferenceFn(b))
	default:
		return 0
	}
}

func compareTag(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, a, b segmentTypes.DetectionTag) int {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeRedHat:
		preferenceFn := func(sourceID sourceTypes.SourceID, tag segmentTypes.DetectionTag) int {
			switch sourceID {
			case sourceTypes.RedHatOVALv2:
				switch {
				case strings.HasSuffix(string(tag), "-including-unpatched"):
					return 4
				case strings.HasSuffix(string(tag), "-extras-including-unpatched"):
					return 3
				case strings.HasSuffix(string(tag), "-supplementary"):
					return 2
				default:
					return 1
				}
			case sourceTypes.RedHatCSAF, sourceTypes.RedHatVEX:
				lhs, _, _ := strings.Cut(string(tag), ":")
				switch {
				case strings.HasSuffix(lhs, "-including-unpatched"):
					return 4
				case strings.HasSuffix(lhs, "-extras-including-unpatched"):
					return 3
				case strings.HasSuffix(lhs, "-supplementary"):
					return 2
				default:
					return 1
				}
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(s, a), preferenceFn(s, b))
	default:
		return 0
	}
}

func toCveContentType(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID) models.CveContentType {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeCPE:
		switch s {
		case sourceTypes.NVDAPICVE, sourceTypes.NVDFeedCVE:
			return models.Nvd
		case sourceTypes.JVNFeedRSS, sourceTypes.JVNFeedDetail:
			return models.Jvn
		case sourceTypes.Fortinet:
			return models.Fortinet
		case sourceTypes.PaloAltoCSAF, sourceTypes.PaloAltoJSON, sourceTypes.PaloAltoList:
			return models.Paloalto
		case sourceTypes.CiscoCSAF, sourceTypes.CiscoCVRF, sourceTypes.CiscoJSON:
			return models.Cisco
		default:
			return models.Unknown
		}
	case ecosystemTypes.EcosystemTypeEPEL:
		return models.CveContentType("epel")
	default:
		return models.NewCveContentType(et)
	}
}

func toVuls0Confidence(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID) models.Confidence {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeCPE:
		switch s {
		case sourceTypes.NVDAPICVE, sourceTypes.NVDFeedCVE:
			return models.NvdExactVersionMatch
		case sourceTypes.JVNFeedRSS, sourceTypes.JVNFeedDetail:
			return models.JvnVendorProductMatch
		case sourceTypes.Fortinet:
			return models.FortinetExactVersionMatch
		case sourceTypes.PaloAltoCSAF, sourceTypes.PaloAltoJSON, sourceTypes.PaloAltoList:
			return models.PaloaltoExactVersionMatch
		case sourceTypes.CiscoCSAF, sourceTypes.CiscoCVRF, sourceTypes.CiscoJSON:
			return models.CiscoExactVersionMatch
		default:
			return models.Confidence{
				Score:           0,
				DetectionMethod: models.DetectionMethod("unknown"),
				SortOrder:       100,
			}
		}
	case ecosystemTypes.EcosystemTypeEPEL:
		return models.Confidence{
			Score:           100,
			DetectionMethod: models.DetectionMethod("EPELMatch"),
			SortOrder:       1,
		}
	case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosystemTypeAlma, ecosystemTypes.EcosystemTypeRocky:
		return models.OvalMatch
	default:
		return models.Confidence{
			Score:           0,
			DetectionMethod: models.DetectionMethod("unknown"),
			SortOrder:       100,
		}
	}
}
