package vuls2

import (
	"cmp"
	"fmt"
	"maps"
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

func extractPkgs(family string, pmmm map[sourceTypes.SourceID]map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack) []pack {
	switch family {
	case constant.RedHat, constant.CentOS:
		var pmm map[dataTypes.RootID]map[segmentTypes.DetectionTag]pack
		var selectedSource sourceTypes.SourceID
		foundSource := false
		for _, s := range []sourceTypes.SourceID{sourceTypes.RedHatCSAF, sourceTypes.RedHatVEX, sourceTypes.RedHatOVALv2, sourceTypes.RedHatOVALv1} {
			if _, found := pmmm[s]; found {
				selectedSource = s
				pmm = pmmm[s]
				foundSource = true
				break
			}
		}
		if !foundSource {
			return nil
		}

		switch selectedSource {
		case sourceTypes.RedHatCSAF:
			// FIXME: not implemented yet
			return nil
		case sourceTypes.RedHatVEX:
			var ps []pack
			// FIXME: Probably, MUST resolve including-unfixed / extras conflict in oval case
			for _, pm := range pmm {
				for _, p := range pm {
					ps = append(ps, p)
				}
			}
			return ps
		default:
			// OVAL v2 and v1
			maxRootID := slices.Max(slices.Collect(maps.Keys(pmm)))
			pm := pmm[maxRootID]
			if len(pm) == 0 {
				return nil
			}
			preferedTag := slices.MaxFunc(slices.Collect(maps.Keys(pm)), func(x, y segmentTypes.DetectionTag) int {
				return tagPreference(family, string(x)) - tagPreference(family, string(y))
			})
			return []pack{pm[preferedTag]}
		}

	default:
		var ps []pack
		for _, pmm := range pmmm {
			for _, pm := range pmm {
				for _, p := range pm {
					ps = append(ps, p)
				}
			}
		}
		return ps
	}
}

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

func mostPreferredTag(family string, tags []segmentTypes.DetectionTag) segmentTypes.DetectionTag {
	if len(tags) == 0 {
		return segmentTypes.DetectionTag("")
	}

	s := slices.MaxFunc(tags, func(x, y segmentTypes.DetectionTag) int {
		return tagPreference(family, string(x)) - tagPreference(family, string(y))
	})
	return s
}

func resolvePackageByTag(family string, x, y pack) pack {
	if tagPreference(family, string(x.tag)) < tagPreference(family, string(y.tag)) {
		return y
	}
	return x
}

func resolveAdvisoryByTag(family string, x, y advisoryTypes.Advisory) advisoryTypes.Advisory {
	if tagPreference(family, string(mostPreferredTag(family, toTags(x.Segments)))) < tagPreference(family, string(mostPreferredTag(family, toTags(y.Segments)))) {
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
		if a == nil && strings.Contains(v.Content.Description, "** REJECT **") {
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

func ignoresWholeCriteria(family string, cn criterionTypes.FilteredCriterion) bool {
	switch family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
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
	case constant.RedHat, constant.CentOS:
		return "RHSA"
	case constant.Alma:
		return "ALSA"
	case constant.Rocky:
		return "RLSA"
	default:
		return r.Source
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
		preferenceFn := func(sourceID string) int {
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
		if cmp.Or(
			preferenceFn(string(x.sourceID))-preferenceFn(string(y.sourceID)),
			tagPreference(family, string(mostPreferredTag(family, x.tags)))-tagPreference(family, string(mostPreferredTag(family, y.tags))),
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
