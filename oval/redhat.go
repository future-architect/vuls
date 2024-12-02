//go:build !scanner

package oval

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// RedHatBase is the base struct for RedHat, CentOS, Alma, Rocky and Fedora
type RedHatBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o RedHatBase) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.driver == nil {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.baseURL); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions via HTTP. err: %w", err)
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(r, o.driver); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions from DB. err: %w", err)
		}
	}

	relatedDefs.Sort()
	for _, defPacks := range relatedDefs.entries {
		nCVEs += o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		switch models.NewCveContentType(o.family) {
		case models.RedHat:
			if conts, ok := vuln.CveContents[models.RedHat]; ok {
				for i, cont := range conts {
					cont.SourceLink = "https://access.redhat.com/security/cve/" + cont.CveID
					vuln.CveContents[models.RedHat][i] = cont
				}
			}
		case models.Fedora:
			for _, d := range vuln.DistroAdvisories {
				if conts, ok := vuln.CveContents[models.Fedora]; ok {
					for i, cont := range conts {
						cont.SourceLink = "https://bodhi.fedoraproject.org/updates/" + d.AdvisoryID
						vuln.CveContents[models.Fedora][i] = cont
					}
				}
			}
		case models.Oracle:
			if conts, ok := vuln.CveContents[models.Oracle]; ok {
				for i, cont := range conts {
					cont.SourceLink = fmt.Sprintf("https://linux.oracle.com/cve/%s.html", cont.CveID)
					vuln.CveContents[models.Oracle][i] = cont
				}
			}
		case models.Amazon:
			for _, d := range vuln.DistroAdvisories {
				if conts, ok := vuln.CveContents[models.Amazon]; ok {
					for i, cont := range conts {
						switch {
						case strings.HasPrefix(d.AdvisoryID, "ALAS-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/%s.html", d.AdvisoryID)
						case strings.HasPrefix(d.AdvisoryID, "ALAS2-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2", "ALAS"))
						case strings.HasPrefix(d.AdvisoryID, "ALAS2022-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2022/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2022", "ALAS"))
						case strings.HasPrefix(d.AdvisoryID, "ALAS2023-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2023/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2023", "ALAS"))
						}
						vuln.CveContents[models.Amazon][i] = cont
					}
				}
			}
		}
	}

	return nCVEs, nil
}

var kernelRelatedPackNames = []string{
	"kernel",
	"kernel-64k",
	"kernel-64k-core",
	"kernel-64k-debug",
	"kernel-64k-debug-core",
	"kernel-64k-debug-devel",
	"kernel-64k-debug-devel-matched",
	"kernel-64k-debug-modules",
	"kernel-64k-debug-modules-core",
	"kernel-64k-debug-modules-extra",
	"kernel-64k-debug-modules-internal",
	"kernel-64k-debug-modules-partner",
	"kernel-64k-devel",
	"kernel-64k-devel-matched",
	"kernel-64k-modules",
	"kernel-64k-modules-core",
	"kernel-64k-modules-extra",
	"kernel-64k-modules-internal",
	"kernel-64k-modules-partner",
	"kernel-aarch64",
	"kernel-abi-stablelists",
	"kernel-abi-whitelists",
	"kernel-bootwrapper",
	"kernel-core",
	"kernel-cross-headers",
	"kernel-debug",
	"kernel-debug-core",
	"kernel-debug-devel",
	"kernel-debug-devel-matched",
	"kernel-debuginfo",
	"kernel-debuginfo-common-aarch64",
	"kernel-debuginfo-common-armv7hl",
	"kernel-debuginfo-common-i686",
	"kernel-debuginfo-common-ppc64le",
	"kernel-debuginfo-common-s390x",
	"kernel-debuginfo-common-x86_64",
	"kernel-debug-modules",
	"kernel-debug-modules-core",
	"kernel-debug-modules-extra",
	"kernel-debug-modules-internal",
	"kernel-debug-modules-partner",
	"kernel-debug-uki-virt",
	"kernel-devel",
	"kernel-devel-matched",
	"kernel-doc",
	"kernel-firmware",
	"kernel-headers",
	"kernel-ipaclones-internal",
	"kernel-kdump",
	"kernel-kdump-devel",
	"kernel-libbpf",
	"kernel-libbpf-devel",
	"kernel-libbpf-static",
	"kernel-modules",
	"kernel-modules-core",
	"kernel-modules-extra",
	"kernel-modules-extra-common",
	"kernel-modules-internal",
	"kernel-modules-partner",
	"kernel-rt",
	"kernel-rt-core",
	"kernel-rt-debug",
	"kernel-rt-debug-core",
	"kernel-rt-debug-devel",
	"kernel-rt-debug-devel-matched",
	"kernel-rt-debug-kvm",
	"kernel-rt-debug-modules",
	"kernel-rt-debug-modules-core",
	"kernel-rt-debug-modules-extra",
	"kernel-rt-debug-modules-internal",
	"kernel-rt-debug-modules-partner",
	"kernel-rt-devel",
	"kernel-rt-devel-matched",
	"kernel-rt-doc",
	"kernel-rt-kvm",
	"kernel-rt-modules",
	"kernel-rt-modules-core",
	"kernel-rt-modules-extra",
	"kernel-rt-modules-internal",
	"kernel-rt-modules-partner",
	"kernel-rt-selftests-internal",
	"kernel-rt-trace",
	"kernel-rt-trace-devel",
	"kernel-rt-trace-kvm",
	"kernel-selftests-internal",
	"kernel-tools",
	"kernel-tools-debuginfo",
	"kernel-tools-debugsource",
	"kernel-tools-devel",
	"kernel-tools-libs",
	"kernel-tools-libs-debuginfo",
	"kernel-tools-libs-devel",
	"kernel-uek",
	"kernel-uek-container",
	"kernel-uek-container-debug",
	"kernel-uek-core",
	"kernel-uek-debug",
	"kernel-uek-debug-core",
	"kernel-uek-debug-devel",
	"kernel-uek-debug-modules",
	"kernel-uek-debug-modules-extra",
	"kernel-uek-devel",
	"kernel-uek-doc",
	"kernel-uek-firmware",
	"kernel-uek-headers",
	"kernel-uek-modules",
	"kernel-uek-modules-extra",
	"kernel-uek-tools",
	"kernel-uek-tools-libs",
	"kernel-uek-tools-libs-devel",
	"kernel-uki-virt",
	"kernel-xen",
	"kernel-xen-devel",
	"kernel-zfcpdump",
	"kernel-zfcpdump-core",
	"kernel-zfcpdump-devel",
	"kernel-zfcpdump-devel-matched",
	"kernel-zfcpdump-modules",
	"kernel-zfcpdump-modules-core",
	"kernel-zfcpdump-modules-extra",
	"kernel-zfcpdump-modules-internal",
	"kernel-zfcpdump-modules-partner",
	"libperf",
	"libperf-devel",
	"perf",
	"python3-perf",
	"python-perf",
}

func (o RedHatBase) update(r *models.ScanResult, defpacks defPacks) (nCVEs int) {
	for _, cve := range defpacks.def.Advisory.Cves {
		ovalContent := o.convertToModel(cve.CveID, &defpacks.def)
		if ovalContent == nil {
			continue
		}
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			logging.Log.Debugf("%s is newly detected by OVAL: DefID: %s", cve.CveID, defpacks.def.DefinitionID)
			vinfo = models.VulnInfo{
				CveID:       cve.CveID,
				Confidences: models.Confidences{models.OvalMatch},
				CveContents: models.NewCveContents(*ovalContent),
			}
			nCVEs++
		} else {
			cveContents := vinfo.CveContents
			if v, ok := vinfo.CveContents[ovalContent.Type]; ok {
				for _, vv := range v {
					if vv.LastModified.After(ovalContent.LastModified) {
						logging.Log.Debugf("%s ignored. DefID: %s ", cve.CveID, defpacks.def.DefinitionID)
					} else {
						logging.Log.Debugf("%s OVAL will be overwritten. DefID: %s", cve.CveID, defpacks.def.DefinitionID)
					}
				}
			} else {
				logging.Log.Debugf("%s also detected by OVAL. DefID: %s", cve.CveID, defpacks.def.DefinitionID)
				cveContents = models.CveContents{}
			}

			vinfo.Confidences.AppendIfMissing(models.OvalMatch)
			cveContents[ovalContent.Type] = []models.CveContent{*ovalContent}
			vinfo.CveContents = cveContents
		}

		if da := o.convertToDistroAdvisory(&defpacks.def); da != nil {
			vinfo.DistroAdvisories.AppendIfMissing(da)
		}

		// uniq(vinfo.AffectedPackages[].Name + defPacks.binpkgFixstat(map[string(=package name)]fixStat{}))
		collectBinpkgFixstat := defPacks{
			binpkgFixstat: map[string]fixStat{},
		}
		for packName, fixStatus := range defpacks.binpkgFixstat {
			collectBinpkgFixstat.binpkgFixstat[packName] = fixStatus
		}

		for _, pack := range vinfo.AffectedPackages {
			if stat, ok := collectBinpkgFixstat.binpkgFixstat[pack.Name]; !ok {
				collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: pack.NotFixedYet,
					fixState:    pack.FixState,
					fixedIn:     pack.FixedIn,
				}
			} else if stat.notFixedYet {
				collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: true,
					fixState:    pack.FixState,
					fixedIn:     pack.FixedIn,
				}
			}
		}
		vinfo.AffectedPackages = collectBinpkgFixstat.toPackStatuses()
		vinfo.AffectedPackages.Sort()
		r.ScannedCves[cve.CveID] = vinfo
	}
	return
}

func (o RedHatBase) convertToDistroAdvisory(def *ovalmodels.Definition) *models.DistroAdvisory {
	switch o.family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky:
		if !strings.HasPrefix(def.Title, "RHSA-") && !strings.HasPrefix(def.Title, "RHBA-") {
			return nil
		}
		return &models.DistroAdvisory{
			AdvisoryID:  strings.TrimSuffix(strings.Fields(def.Title)[0], ":"),
			Severity:    def.Advisory.Severity,
			Issued:      def.Advisory.Issued,
			Updated:     def.Advisory.Updated,
			Description: def.Description,
		}
	case constant.Oracle:
		if !strings.HasPrefix(def.Title, "ELSA-") {
			return nil
		}
		return &models.DistroAdvisory{
			AdvisoryID:  strings.TrimSuffix(strings.Fields(def.Title)[0], ":"),
			Severity:    def.Advisory.Severity,
			Issued:      def.Advisory.Issued,
			Updated:     def.Advisory.Updated,
			Description: def.Description,
		}
	case constant.Amazon:
		if !strings.HasPrefix(def.Title, "ALAS") {
			return nil
		}
		return &models.DistroAdvisory{
			AdvisoryID:  def.Title,
			Severity:    def.Advisory.Severity,
			Issued:      def.Advisory.Issued,
			Updated:     def.Advisory.Updated,
			Description: def.Description,
		}
	case constant.Fedora:
		if !strings.HasPrefix(def.Title, "FEDORA") {
			return nil
		}
		return &models.DistroAdvisory{
			AdvisoryID:  def.Title,
			Severity:    def.Advisory.Severity,
			Issued:      def.Advisory.Issued,
			Updated:     def.Advisory.Updated,
			Description: def.Description,
		}
	default:
		return nil
	}
}

func (o RedHatBase) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	refs := make([]models.Reference, 0, len(def.References))
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}

		score2, vec2 := parseCvss2(cve.Cvss2)
		score3, vec3 := parseCvss3(cve.Cvss3)

		sev2, sev3, severity := "", "", def.Advisory.Severity
		if cve.Impact != "" {
			severity = cve.Impact
		}
		if severity != "None" {
			sev3 = severity
			if score2 != 0 {
				sev2 = severity
			}
		}

		// CWE-ID in RedHat OVAL may have multiple cweIDs separated by space
		cwes := strings.Fields(cve.Cwe)

		return &models.CveContent{
			Type:          models.NewCveContentType(o.family),
			CveID:         cve.CveID,
			Title:         def.Title,
			Summary:       def.Description,
			Cvss2Score:    score2,
			Cvss2Vector:   vec2,
			Cvss2Severity: sev2,
			Cvss3Score:    score3,
			Cvss3Vector:   vec3,
			Cvss3Severity: sev3,
			References:    refs,
			CweIDs:        cwes,
			Published:     def.Advisory.Issued,
			LastModified:  def.Advisory.Updated,
		}
	}
	return nil
}

// RedHat is the interface for RedhatBase OVAL
type RedHat struct {
	RedHatBase
}

// NewRedhat creates OVAL client for Redhat
func NewRedhat(driver ovaldb.DB, baseURL string) RedHat {
	return RedHat{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.RedHat,
			},
		},
	}
}

// CentOS is the interface for CentOS OVAL
type CentOS struct {
	RedHatBase
}

// NewCentOS creates OVAL client for CentOS
func NewCentOS(driver ovaldb.DB, baseURL string) CentOS {
	return CentOS{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.CentOS,
			},
		},
	}
}

// Oracle is the interface for Oracle OVAL
type Oracle struct {
	RedHatBase
}

// NewOracle creates OVAL client for Oracle
func NewOracle(driver ovaldb.DB, baseURL string) Oracle {
	return Oracle{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Oracle,
			},
		},
	}
}

// Amazon is the interface for RedhatBase OVAL
type Amazon struct {
	// Base
	RedHatBase
}

// NewAmazon creates OVAL client for Amazon Linux
func NewAmazon(driver ovaldb.DB, baseURL string) Amazon {
	return Amazon{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Amazon,
			},
		},
	}
}

// Alma is the interface for RedhatBase OVAL
type Alma struct {
	// Base
	RedHatBase
}

// NewAlma creates OVAL client for Alma Linux
func NewAlma(driver ovaldb.DB, baseURL string) Alma {
	return Alma{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Alma,
			},
		},
	}
}

// Rocky is the interface for RedhatBase OVAL
type Rocky struct {
	// Base
	RedHatBase
}

// NewRocky creates OVAL client for Rocky Linux
func NewRocky(driver ovaldb.DB, baseURL string) Rocky {
	return Rocky{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Rocky,
			},
		},
	}
}

// Fedora is the interface for RedhatBase OVAL
type Fedora struct {
	// Base
	RedHatBase
}

// NewFedora creates OVAL client for Fedora Linux
func NewFedora(driver ovaldb.DB, baseURL string) Fedora {
	return Fedora{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Fedora,
			},
		},
	}
}
