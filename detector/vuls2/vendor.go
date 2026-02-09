package vuls2

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	versioncriterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func preConvertBinaryVersion(family, version string) string {
	switch family {
	case constant.Debian, constant.Raspbian, constant.Ubuntu:
		// https://github.com/future-architect/vuls/pull/2329
		// If you are using a scanner from before this PR was merged, the binary package version will be lost when updating NeedRestartProcs during a fast-root scan.
		// However, the current data source does not require the binary package version, so it will be filled in with "0".
		if version == "" {
			return "0"
		}
		return version
	default:
		return version
	}
}

func toVuls2Family(vuls0Family, vuls0Release string) string {
	switch vuls0Family {
	case constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		return ecosystemTypes.EcosystemTypeSUSELinuxEnterprise
	case constant.OpenSUSE:
		switch vuls0Release {
		case "tumbleweed":
			return ecosystemTypes.EcosystemTypeOpenSUSETumbleweed
		default:
			return vuls0Family
		}
	default:
		return vuls0Family
	}
}

func toVuls2Release(vuls0Family, vuls0Release string) string {
	switch vuls0Family {
	case constant.OpenSUSE:
		switch vuls0Release {
		case "tumbleweed":
			return ""
		default:
			return vuls0Release
		}
	default:
		return vuls0Release
	}
}

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
	case ecosystemTypes.EcosystemTypeUbuntu:
		if strings.HasPrefix(v.Content.Description, "** REJECT **") || strings.HasPrefix(v.Content.Description, "Rejected reason:") {
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

func ignoreCriterion(e ecosystemTypes.Ecosystem, cn criterionTypes.FilteredCriterion, tag segmentTypes.DetectionTag) bool {
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
	case ecosystemTypes.EcosystemTypeUbuntu:
		if func() bool {
			lhs, _, _ := strings.Cut(string(tag), "_")
			lhs, rhs, ok := strings.Cut(lhs, "/")
			if !ok {
				return false
			}
			services := []string{"esm", "esm-infra", "esm-apps", "esm-infra-legacy", "esm-apps-legacy", "ros-esm"}
			if !slices.Contains(services, lhs) && !slices.Contains(services, rhs) {
				return true
			}
			return false
		}() {
			return true
		}

		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			if cn.Criterion.Version != nil && cn.Criterion.Version.FixStatus != nil && cn.Criterion.Version.FixStatus.Class == fixstatusTypes.ClassUnfixed {
				lhs, _, _ := strings.Cut(cn.Criterion.Version.FixStatus.Vendor, ":")
				switch lhs {
				case "ignored", "in-progress":
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

func filterCriterion(e ecosystemTypes.Ecosystem, scanned scanTypes.ScanResult, cn criterionTypes.FilteredCriterion) (criterionTypes.FilteredCriterion, error) {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			if cn.Criterion.Version != nil {
				switch cn.Criterion.Version.Package.Type {
				case versioncriterionpackageTypes.PackageTypeSource:
					if !models.IsKernelSourcePackage(constant.Ubuntu, cn.Criterion.Version.Package.Source.Name) {
						return cn, nil
					}

					m := make(map[string][]string)
					for _, p := range scanned.OSPackages {
						sn := fmt.Sprintf("%s:%d:%s-%s", models.RenameKernelSourcePackageName(constant.Ubuntu, p.SrcName), func() int {
							if p.SrcEpoch != nil {
								return *p.SrcEpoch
							}
							return 0
						}(), p.SrcVersion, p.SrcRelease)
						m[sn] = append(m[sn], p.Name)
					}

					var accepts []int
					for _, index := range cn.Accepts.Version {
						if len(scanned.OSPackages) <= index {
							return criterionTypes.FilteredCriterion{}, xerrors.Errorf("Too large OSPackage index. len(OSPackage): %d, index: %d", len(scanned.OSPackages), index)
						}

						if slices.ContainsFunc(m[fmt.Sprintf("%s:%d:%s-%s", models.RenameKernelSourcePackageName(constant.Ubuntu, scanned.OSPackages[index].SrcName), func() int {
							if scanned.OSPackages[index].SrcEpoch != nil {
								return *scanned.OSPackages[index].SrcEpoch
							}
							return 0
						}(), scanned.OSPackages[index].SrcVersion, scanned.OSPackages[index].SrcRelease)], func(s string) bool {
							switch s {
							case fmt.Sprintf("linux-image-%s", scanned.Kernel.Release), fmt.Sprintf("linux-image-unsigned-%s", scanned.Kernel.Release), fmt.Sprintf("linux-signed-image-%s", scanned.Kernel.Release), fmt.Sprintf("linux-image-uc-%s", scanned.Kernel.Release),
								fmt.Sprintf("linux-buildinfo-%s", scanned.Kernel.Release), fmt.Sprintf("linux-cloud-tools-%s", scanned.Kernel.Release), fmt.Sprintf("linux-headers-%s", scanned.Kernel.Release), fmt.Sprintf("linux-lib-rust-%s", scanned.Kernel.Release), fmt.Sprintf("linux-modules-%s", scanned.Kernel.Release), fmt.Sprintf("linux-modules-extra-%s", scanned.Kernel.Release), fmt.Sprintf("linux-modules-ipu6-%s", scanned.Kernel.Release), fmt.Sprintf("linux-modules-ivsc-%s", scanned.Kernel.Release), fmt.Sprintf("linux-modules-iwlwifi-%s", scanned.Kernel.Release), fmt.Sprintf("linux-tools-%s", scanned.Kernel.Release):
								return true
							default:
								if (strings.HasPrefix(s, "linux-modules-nvidia-") || strings.HasPrefix(s, "linux-objects-nvidia-") || strings.HasPrefix(s, "linux-signatures-nvidia-")) && strings.HasSuffix(s, scanned.Kernel.Release) {
									return true
								}
								return false
							}
						}) {
							accepts = append(accepts, index)
						}
					}
					cn.Accepts.Version = accepts

					return cn, nil
				default:
					return cn, nil
				}
			}
			return cn, nil
		default:
			return cn, nil
		}
	default:
		return cn, nil
	}
}

func affectedPackageName(e ecosystemTypes.Ecosystem, pkg scanTypes.OSPackage) string {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	default:
		return pkg.Name
	}
}

func fixState(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, fixstate string) string {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch s {
		case sourceTypes.UbuntuCVETracker:
			lhs, _, _ := strings.Cut(fixstate, ":")
			return lhs
		default:
			return fixstate
		}
	default:
		return fixstate
	}
}

func selectFixedIn(rangeType vcAffectedRangeTypes.RangeType, fixed []string) string {
	if len(fixed) == 0 {
		return ""
	}

	switch rangeType {
	case vcAffectedRangeTypes.RangeTypeAPK:
		return slices.MaxFunc(fixed, func(x, y string) int {
			vx, errx := apk.NewVersion(x)
			vy, erry := apk.NewVersion(y)
			switch {
			case errx != nil && erry != nil:
				return 0
			case errx != nil && erry == nil:
				return -1
			case errx == nil && erry != nil:
				return +1
			default:
				return vx.Compare(vy)
			}
		})
	case vcAffectedRangeTypes.RangeTypeRPM:
		return slices.MaxFunc(fixed, func(x, y string) int {
			return rpm.NewVersion(x).Compare(rpm.NewVersion(y))
		})
	case vcAffectedRangeTypes.RangeTypeDPKG:
		return slices.MaxFunc(fixed, func(x, y string) int {
			vx, errx := deb.NewVersion(x)
			vy, erry := deb.NewVersion(y)
			switch {
			case errx != nil && erry != nil:
				return 0
			case errx != nil && erry == nil:
				return -1
			case errx == nil && erry != nil:
				return +1
			default:
				return vx.Compare(vy)
			}
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
			case vcAffectedRangeTypes.RangeTypeAPK:
				va, erra := apk.NewVersion(a.status.FixedIn)
				vb, errb := apk.NewVersion(b.status.FixedIn)
				switch {
				case erra != nil && errb != nil:
					return 0
				case erra != nil && errb == nil:
					return -1
				case erra == nil && errb != nil:
					return +1
				default:
					return va.Compare(vb)
				}
			case vcAffectedRangeTypes.RangeTypeRPM:
				return rpm.NewVersion(a.status.FixedIn).Compare(rpm.NewVersion(b.status.FixedIn))
			case vcAffectedRangeTypes.RangeTypeDPKG:
				va, erra := deb.NewVersion(a.status.FixedIn)
				vb, errb := deb.NewVersion(b.status.FixedIn)
				switch {
				case erra != nil && errb != nil:
					return 0
				case erra != nil && errb == nil:
					return -1
				case erra == nil && errb != nil:
					return +1
				default:
					return va.Compare(vb)
				}
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
	case ecosystemTypes.EcosystemTypeEPEL, ecosystemTypes.EcosystemTypeFedora:
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
	case ecosystemTypes.EcosystemTypeOracle:
		return models.Reference{
			Link:   fmt.Sprintf("https://linux.oracle.com/errata/%s.html", da.AdvisoryID),
			Source: "ORACLE",
			RefID:  da.AdvisoryID,
		}, nil
	case ecosystemTypes.EcosystemTypeUbuntu:
		return models.Reference{
			Link:   fmt.Sprintf("https://ubuntu.com/security/notices/%s", da.AdvisoryID),
			Source: "UBUNTU",
			RefID:  da.AdvisoryID,
		}, nil
	case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
		return models.Reference{
			Link:   fmt.Sprintf("https://www.suse.com/security/cve/%s.html", da.AdvisoryID),
			Source: "SUSE",
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
	case models.Oracle:
		return fmt.Sprintf("https://linux.oracle.com/cve/%s.html", v.Content.ID)
	case models.Alpine:
		return fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", v.Content.ID)
	case models.Ubuntu, models.UbuntuAPI:
		return fmt.Sprintf("https://ubuntu.com/security/%s", v.Content.ID)
	case models.Nvd:
		return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.Content.ID)
	case models.SUSE:
		return fmt.Sprintf("https://www.suse.com/security/cve/%s.html", v.Content.ID)
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
				return 5
			case sourceTypes.NVDFeedCVEv2, sourceTypes.JVNFeedRSS, sourceTypes.PaloAltoJSON, sourceTypes.CiscoCVRF:
				return 4
			case sourceTypes.NVDFeedCVEv1:
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
	case ecosystemTypes.EcosystemTypeAlpine:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.AlpineSecDB:
				return 3
			case sourceTypes.AlpineOSV:
				return 2
			default:
				return 1
			}
		}
		return cmp.Compare(preferenceFn(a), preferenceFn(b))
	case ecosystemTypes.EcosystemTypeUbuntu:
		preferenceFn := func(sourceID sourceTypes.SourceID) int {
			switch sourceID {
			case sourceTypes.UbuntuCVETracker:
				return 4
			case sourceTypes.UbuntuOVAL:
				return 3
			case sourceTypes.UbuntuOSV:
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
	case ecosystemTypes.EcosystemTypeUbuntu:
		preferenceFn := func(sourceID sourceTypes.SourceID, tag segmentTypes.DetectionTag) int {
			switch sourceID {
			case sourceTypes.UbuntuCVETracker:
				switch {
				case !strings.Contains(string(tag), "/"):
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
		case sourceTypes.NVDAPICVE, sourceTypes.NVDFeedCVEv1, sourceTypes.NVDFeedCVEv2:
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
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch s {
		case sourceTypes.UbuntuCVETracker:
			return models.UbuntuAPI
		default:
			return models.Ubuntu
		}
	case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
		return models.SUSE
	default:
		return models.NewCveContentType(et)
	}
}

func toCvss(e ecosystemTypes.Ecosystem, src sourceTypes.SourceID, ss []severityTypes.Severity) (v2.CVSSv2, v31.CVSSv31, v40.CVSSv40) {
	var (
		cvss2 v2.CVSSv2
		cvss3 v31.CVSSv31
		cvss4 v40.CVSSv40
	)

	for _, s := range ss {
		et, _, _ := strings.Cut(string(e), ":")
		switch s.Type {
		case severityTypes.SeverityTypeVendor:
			switch et {
			case ecosystemTypes.EcosystemTypeUbuntu:
				switch src {
				case sourceTypes.UbuntuCVETracker:
					if s.Vendor != nil {
						cvss2 = v2.CVSSv2{NVDBaseSeverity: *s.Vendor}
						cvss3 = v31.CVSSv31{BaseSeverity: *s.Vendor}
					}
				default:
				}
			case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
				if s.Vendor != nil {
					if cvss2.Vector != "" {
						cvss2.NVDBaseSeverity = *s.Vendor
					}
					if cvss3.Vector != "" {
						cvss3.BaseSeverity = *s.Vendor
					}
					if cvss4.Vector != "" {
						cvss4.Severity = *s.Vendor
					}
				}
			default:
			}
		case severityTypes.SeverityTypeCVSSv2:
			switch et {
			case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
				if s.Source != "SUSE" {
					continue
				}
			default:
			}
			if cvss2.Vector == "" && s.CVSSv2 != nil {
				cvss2 = *s.CVSSv2
			}
		case severityTypes.SeverityTypeCVSSv30:
			switch et {
			case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
				if s.Source != "SUSE" {
					continue
				}
			default:
			}
			if cvss3.Vector == "" && s.CVSSv30 != nil {
				cvss3 = v31.CVSSv31{
					Vector:       s.CVSSv30.Vector,
					BaseScore:    s.CVSSv30.BaseScore,
					BaseSeverity: s.CVSSv30.BaseSeverity,
				}
			}
		case severityTypes.SeverityTypeCVSSv31:
			switch et {
			case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
				if s.Source != "SUSE" {
					continue
				}
			default:
			}
			if !strings.HasPrefix(cvss3.Vector, "CVSS:3.1/") && s.CVSSv31 != nil {
				cvss3 = *s.CVSSv31
			}
		case severityTypes.SeverityTypeCVSSv40:
			switch et {
			case ecosystemTypes.EcosystemTypeSUSELinuxEnterprise:
				if s.Source != "SUSE" {
					continue
				}
			default:
			}
			if cvss4.Vector == "" && s.CVSSv40 != nil {
				cvss4 = *s.CVSSv40
			}
		default:
		}
	}

	return cvss2, cvss3, cvss4
}

func toVuls0Confidence(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID) models.Confidence {
	et, _, _ := strings.Cut(string(e), ":")

	switch et {
	case ecosystemTypes.EcosystemTypeCPE:
		switch s {
		case sourceTypes.NVDAPICVE, sourceTypes.NVDFeedCVEv1, sourceTypes.NVDFeedCVEv2:
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
	case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosystemTypeFedora, ecosystemTypes.EcosystemTypeAlma, ecosystemTypes.EcosystemTypeRocky, ecosystemTypes.EcosystemTypeOracle, ecosystemTypes.EcosystemTypeAlpine,
		ecosystemTypes.EcosystemTypeSUSELinuxEnterprise, ecosystemTypes.EcosystemTypeOpenSUSE, ecosystemTypes.EcosystemTypeOpenSUSELeap, ecosystemTypes.EcosystemTypeOpenSUSETumbleweed:
		return models.OvalMatch
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch s {
		case sourceTypes.UbuntuCVETracker:
			return models.UbuntuAPIMatch
		default:
			return models.OvalMatch
		}
	default:
		return models.Confidence{
			Score:           0,
			DetectionMethod: models.DetectionMethod("unknown"),
			SortOrder:       100,
		}
	}
}
