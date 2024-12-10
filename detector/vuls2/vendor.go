package vuls2

import (
	"fmt"
	"slices"
	"strings"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	rpm "github.com/knqyf263/go-rpm-version"
)

func resolveCveContentList(family string, sviX, sviY sourceVulnInfo, ccListX, ccListY []models.CveContent) (sourceVulnInfo, []models.CveContent) {
	switch family {
	// This logic is from old vuls's oval resolution. Maybe more widely applicable than these four distros.
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		if sviX.rootID < sviY.rootID {
			return sviY, ccListY
		}
		return sviX, ccListX
	default:
		return sviX, ccListX
	}
}

func resolveAffectedPackage(family string, rootIDX, rootIDY dataTypes.RootID, statusX, statusY models.PackageFixStatus) models.PackageFixStatus {
	switch family {
	// This logic is from old vuls's oval resolution. Maybe more widely applicable than these four distros.
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		former, latter := statusX, statusY
		if rootIDY < rootIDX {
			former, latter = statusY, statusX
		}

		fixedIn := statusX.FixedIn
		if rpm.NewVersion(statusX.FixedIn).Compare(rpm.NewVersion(statusY.FixedIn)) < 0 {
			fixedIn = statusY.FixedIn
		}
		if latter.NotFixedYet {
			former.NotFixedYet = true
			former.FixedIn = fixedIn
			return former
		}
		latter.FixedIn = fixedIn
		return latter
	default:
		return statusX
	}
}

func ignoresCriterion(family string, cn criterion.FilteredCriterion) bool {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		if cn.Criterion.Version.FixStatus != nil && cn.Criterion.Version.FixStatus.Class == fixstatus.ClassUnfixed {
			switch cn.Criterion.Version.FixStatus.Vendor {
			case "Will not fix", "Under investigation":
				return true
			}
		}
		return false
	default:
		return false
	}
}

func ignoresWholeCriteria(family string, cn criterion.FilteredCriterion) bool {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		// Ignore whole criteria from root if kpatch-patch-* package is included.
		return cn.Criterion.Type == criterion.CriterionTypeVersion && strings.HasPrefix(cn.Criterion.Version.Package.Name, "kpatch-patch-")
	default:
		return false
	}
}

func selectFixedIn(family string, fixed []string) string {
	if len(fixed) == 0 {
		return ""
	}

	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return slices.MaxFunc(fixed, func(x, y string) int {
			return rpm.NewVersion(x).Compare(rpm.NewVersion(y))
		})
	default:
		return fixed[0]
	}
}

func advisoryReferenceSource(family string, r referenceTypes.Reference) string {
	switch family {
	case constant.RedHat:
		return "RHSA"
	default:
		return r.Source
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

func overwritesByNewVulnInfo(family, baseSourceID, newSourceID string) bool {
	switch family {
	case constant.RedHat, constant.CentOS:
		favorFunc := func(sourceID string) int {
			switch sourceID {
			case "redhat-csaf":
				return 4
			case "redhat-vex":
				return 3
			case "redhat-ovalv2":
				return 2
			default:
				return 1
			}
		}
		return favorFunc(baseSourceID) < favorFunc(newSourceID)
	default:
		return true
	}
}

func cveContentOptional(family string, rootID dataTypes.RootID, sourceID sourceTypes.SourceID) map[string]string {
	switch family {
	case constant.RedHat, constant.CentOS:
		return map[string]string{
			"redhat-rootid":   string(rootID),
			"redhat-sourceid": string(sourceID),
		}
	default:
		return nil
	}
}
