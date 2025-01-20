package vuls2

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	versioncriterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
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

func resolvePackageByRootID(family string, rootIDX, rootIDY dataTypes.RootID, statusX, statusY models.PackageFixStatus) models.PackageFixStatus {
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

func mostPreferredTag(family string, segments []segmentTypes.Segment) segmentTypes.DetectionTag {
	if len(segments) == 0 {
		return segmentTypes.DetectionTag("")
	}

	s := slices.MaxFunc(segments, func(x, y segmentTypes.Segment) int {
		return cmp.Compare(tagPreference(family, string(x.Tag)), tagPreference(family, string(y.Tag)))
	})
	return s.Tag
}

func resolvePackageByTag(family string, x, y pack) pack {
	if tagPreference(family, string(x.tag)) < tagPreference(family, string(y.tag)) {
		return y
	}
	return x
}

func resolveAdvisoryByTag(family string, x, y taggedAdvisory) taggedAdvisory {
	if tagPreference(family, string(x.tag)) < tagPreference(family, string(y.tag)) {
		return y
	}
	return x
}

func tagPreference(family string, tag string) int {
	switch family {
	case constant.RedHat, constant.CentOS:
		switch {
		case strings.HasSuffix(tag, "-including-unpatched"):
			return 4
		case strings.HasSuffix(tag, "-extras-including-unpatched"):
			return 3
		case strings.HasSuffix(tag, "-supplementary"):
			return 2
		default:
			return 1
		}
	default:
		return 1
	}
}

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

func ignoresCriterion(family string, cn criterionTypes.FilteredCriterion) bool {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		if cn.Criterion.Version.FixStatus != nil && cn.Criterion.Version.FixStatus.Class == fixstatusTypes.ClassUnfixed {
			switch strings.ToLower(cn.Criterion.Version.FixStatus.Vendor) {
			case "will not fix", "under investigation":
				return true
			}
		}
		return false
	default:
		return false
	}
}

func ignoresWholeCriteria(family string, sourceID sourceTypes.SourceID, cn criterionTypes.FilteredCriterion) bool {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		switch sourceID {
		case sourceTypes.RedHatOVALv1, sourceTypes.RedHatOVALv2:
			// Ignore whole criteria from root if kpatch-patch-* package is included.
			if cn.Criterion.Type == criterionTypes.CriterionTypeVersion && cn.Criterion.Version != nil &&
				cn.Criterion.Version.Package.Type == versioncriterionpackageTypes.PackageTypeBinary && cn.Criterion.Version.Package.Binary != nil &&
				strings.HasPrefix(cn.Criterion.Version.Package.Binary.Name, "kpatch-patch-") {
				return true
			}
			if cn.Criterion.Type == criterionTypes.CriterionTypeNoneExist && cn.Criterion.NoneExist != nil &&
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
	case models.RedHat, models.Alma, models.Rocky:
		return fmt.Sprintf("https://access.redhat.com/security/cve/%s", v.Content.ID)
	default:
		return ""
	}
}

func resolveSourceVulnInfo(family string, x, y sourceVulnInfo) sourceVulnInfo {
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
		if cmp.Or(
			cmp.Compare(preferenceFn(x.sourceID), preferenceFn(y.sourceID)),
			cmp.Compare(tagPreference(family, string(x.tag)), tagPreference(family, string(y.tag))),
		) < 0 {
			return y
		}
		return x
	default:
		return x
	}
}

func affectedPackageName(family string, pkg scanTypes.OSPackage) string {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		return pkg.Name
	default:
		// for families that uses source name in detecting vulnerabilities
		return pkg.SrcName
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
