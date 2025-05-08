package vuls2

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	versioncriterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	rpm "github.com/knqyf263/go-rpm-version"
)

func ignoresVulnerability(family string, v vulnerabilityTypes.Vulnerability, a *advisoryTypes.Advisory) bool {
	switch family {
	case constant.RedHat, constant.CentOS:
		if strings.Contains(v.Content.Description, "** REJECT **") {
			return true
		}
		if a != nil && strings.Contains(a.Content.Description, "** REJECT **") {
			return true
		}
		return false
	default:
		return false
	}
}

func ignoreCriterion(e ecosystemTypes.Ecosystem, cn criterionTypes.FilteredCriterion) bool {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS:
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

func ignoreCriteria(e ecosystemTypes.Ecosystem, sourceID sourceTypes.SourceID, cn criterionTypes.FilteredCriterion) bool {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS:
		switch sourceID {
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

func selectFixedIn(e ecosystemTypes.Ecosystem, fixed []string) string {
	if len(fixed) == 0 {
		return ""
	}

	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return slices.MaxFunc(fixed, func(x, y string) int {
			return rpm.NewVersion(x).Compare(rpm.NewVersion(y))
		})
	default:
		return fixed[0]
	}
}

func compareFixedIn(e ecosystemTypes.Ecosystem, a, b string) int {
	family, _, _ := strings.Cut(string(e), ":")
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return rpm.NewVersion(a).Compare(rpm.NewVersion(b))
	default:
		return 0
	}
}

func advisoryReference(family string, a *advisoryTypes.Advisory, r referenceTypes.Reference) *models.Reference {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Rocky:
		if a != nil && strings.Contains(r.URL, string(a.Content.ID)) {
			return &models.Reference{
				Link: r.URL,
				Source: func() string {
					switch family {
					case constant.RedHat, constant.CentOS:
						return "RHSA"
					case constant.Rocky:
						return "RLSA"
					default:
						return r.Source
					}
				}(),
				RefID: string(a.Content.ID),
			}
		}
		return nil
	case constant.Alma:
		if a != nil && strings.Contains(r.URL, strings.ReplaceAll(string(a.Content.ID), ":", "-")) {
			return &models.Reference{
				Link:   r.URL,
				Source: "ALSA",
				RefID:  string(a.Content.ID),
			}
		}
		return nil
	default:
		return nil
	}
}

func cveContentSourceLink(ccType models.CveContentType, v vulnerabilityTypes.Vulnerability) string {
	switch ccType {
	case models.RedHat:
		return fmt.Sprintf("https://access.redhat.com/security/cve/%s", v.Content.ID)
	default:
		return ""
	}
}

func compareSourceID(e ecosystemTypes.Ecosystem, a, b sourceTypes.SourceID) int {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.RedHatCSAF:
				return 4
			case sourceTypes.RedHatVEX:
				return 3
			case sourceTypes.RedHatOVALv2:
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
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS:
		switch s {
		case sourceTypes.RedHatOVALv2:
			return cmp.Compare(tagPreference(e, s, a), tagPreference(e, s, b))
		default:
			return 0
		}
	default:
		return 0
	}
}

func tagPreference(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, tag segmentTypes.DetectionTag) int {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS:
		switch s {
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
		default:
			return 1
		}
	default:
		return 1
	}
}

func affectedPackageName(e ecosystemTypes.Ecosystem, pkg scanTypes.OSPackage) string {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return pkg.Name
	default:
		// for families that uses source name in detecting vulnerabilities
		return pkg.SrcName
	}
}

func toVuls0Confidence(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID) models.Confidence {
	family, _, _ := strings.Cut(string(e), ":")

	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return models.OvalMatch
	default:
		return models.Confidence{
			Score:           5,
			DetectionMethod: models.DetectionMethod("unknown"),
			SortOrder:       100,
		}
	}
}
