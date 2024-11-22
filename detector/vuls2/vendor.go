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
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	rpm "github.com/knqyf263/go-rpm-version"
)

func resolveCveContentList(family string, rootIDBase, rootID1 dataTypes.RootID, ccListBase, ccList1 []models.CveContent) []models.CveContent {
	switch family {
	// This logic is from old vuls's oval resolution. Maybe more widely applicable than these four distros.
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		if rootIDBase < rootID1 {
			return ccList1
		}
		return ccListBase
	default:
		return ccListBase
	}
}

func resolveAffectedPackage(family string, rootIDBase, rootID1 dataTypes.RootID, statusBase, status1 models.PackageFixStatus) models.PackageFixStatus {
	switch family {
	// This logic is from old vuls's oval resolution. Maybe more widely applicable than these four distros.
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		former, latter := func() (models.PackageFixStatus, models.PackageFixStatus) {
			if rootIDBase < rootID1 {
				return statusBase, status1
			}
			return status1, statusBase
		}()

		if latter.NotFixedYet {
			former.NotFixedYet = true
			return former
		}
		return latter
	default:
		return statusBase
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
		return strings.HasPrefix(cn.Criterion.Version.Package.Name, "kpatch-patch-")
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

func discardsNewVulnInfoBySourceID(family, baseSourceID, newSourceID string) bool {
	switch family {
	case constant.RedHat, constant.CentOS:
		switch newSourceID {
		case "redhat-csaf":
			return false
		case "redhat-ovalv2":
			return baseSourceID == "redhat-ovalv1"
		default:
			return true
		}
	default:
		return true
	}
}
