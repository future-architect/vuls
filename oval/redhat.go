//go:build !scanner
// +build !scanner

package oval

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// RedHatBase is the base struct for RedHat, CentOS, Alma, Rocky and Fedora
type RedHatBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o RedHatBase) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.Cnf.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.Cnf.GetURL()); err != nil {
			return 0, err
		}
	} else {
		driver, err := newOvalDB(o.Cnf)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
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
						if strings.HasPrefix(d.AdvisoryID, "ALAS2022-") {
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2022/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2022", "ALAS"))
						} else if strings.HasPrefix(d.AdvisoryID, "ALAS2-") {
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2", "ALAS"))
						} else if strings.HasPrefix(d.AdvisoryID, "ALAS-") {
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/%s.html", d.AdvisoryID)
						}
						vuln.CveContents[models.Amazon][i] = cont
					}
				}
			}
		}
	}

	return nCVEs, nil
}

var kernelRelatedPackNames = map[string]bool{
	"kernel":                  true,
	"kernel-aarch64":          true,
	"kernel-abi-whitelists":   true,
	"kernel-bootwrapper":      true,
	"kernel-debug":            true,
	"kernel-debug-devel":      true,
	"kernel-devel":            true,
	"kernel-doc":              true,
	"kernel-headers":          true,
	"kernel-kdump":            true,
	"kernel-kdump-devel":      true,
	"kernel-rt":               true,
	"kernel-rt-debug":         true,
	"kernel-rt-debug-devel":   true,
	"kernel-rt-debug-kvm":     true,
	"kernel-rt-devel":         true,
	"kernel-rt-doc":           true,
	"kernel-rt-kvm":           true,
	"kernel-rt-trace":         true,
	"kernel-rt-trace-devel":   true,
	"kernel-rt-trace-kvm":     true,
	"kernel-rt-virt":          true,
	"kernel-rt-virt-devel":    true,
	"kernel-tools":            true,
	"kernel-tools-libs":       true,
	"kernel-tools-libs-devel": true,
	"kernel-uek":              true,
	"perf":                    true,
	"python-perf":             true,
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

		vinfo.DistroAdvisories.AppendIfMissing(
			o.convertToDistroAdvisory(&defpacks.def))

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
					fixedIn:     pack.FixedIn,
				}
			} else if stat.notFixedYet {
				collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: true,
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
	advisoryID := def.Title
	switch o.family {
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Oracle:
		if def.Title != "" {
			ss := strings.Fields(def.Title)
			advisoryID = strings.TrimSuffix(ss[0], ":")
		}
	}
	return &models.DistroAdvisory{
		AdvisoryID:  advisoryID,
		Severity:    def.Advisory.Severity,
		Issued:      def.Advisory.Issued,
		Updated:     def.Advisory.Updated,
		Description: def.Description,
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

		score2, vec2 := o.parseCvss2(cve.Cvss2)
		score3, vec3 := o.parseCvss3(cve.Cvss3)

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

// ParseCvss2 divide CVSSv2 string into score and vector
// 5/AV:N/AC:L/Au:N/C:N/I:N/A:P
func (o RedHatBase) parseCvss2(scoreVector string) (score float64, vector string) {
	var err error
	ss := strings.Split(scoreVector, "/")
	if 1 < len(ss) {
		if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
			return 0, ""
		}
		return score, strings.Join(ss[1:], "/")
	}
	return 0, ""
}

// ParseCvss3 divide CVSSv3 string into score and vector
// 5.6/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L
func (o RedHatBase) parseCvss3(scoreVector string) (score float64, vector string) {
	var err error
	for _, s := range []string{
		"/CVSS:3.0/",
		"/CVSS:3.1/",
	} {
		ss := strings.Split(scoreVector, s)
		if 1 < len(ss) {
			if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
				return 0, ""
			}
			return score, strings.TrimPrefix(s, "/") + ss[1]
		}
	}
	return 0, ""
}

// RedHat is the interface for RedhatBase OVAL
type RedHat struct {
	RedHatBase
}

// NewRedhat creates OVAL client for Redhat
func NewRedhat(cnf config.VulnDictInterface) RedHat {
	return RedHat{
		RedHatBase{
			Base{
				family: constant.RedHat,
				Cnf:    cnf,
			},
		},
	}
}

// CentOS is the interface for CentOS OVAL
type CentOS struct {
	RedHatBase
}

// NewCentOS creates OVAL client for CentOS
func NewCentOS(cnf config.VulnDictInterface) CentOS {
	return CentOS{
		RedHatBase{
			Base{
				family: constant.CentOS,
				Cnf:    cnf,
			},
		},
	}
}

// Oracle is the interface for Oracle OVAL
type Oracle struct {
	RedHatBase
}

// NewOracle creates OVAL client for Oracle
func NewOracle(cnf config.VulnDictInterface) Oracle {
	return Oracle{
		RedHatBase{
			Base{
				family: constant.Oracle,
				Cnf:    cnf,
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
func NewAmazon(cnf config.VulnDictInterface) Amazon {
	return Amazon{
		RedHatBase{
			Base{
				family: constant.Amazon,
				Cnf:    cnf,
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
func NewAlma(cnf config.VulnDictInterface) Alma {
	return Alma{
		RedHatBase{
			Base{
				family: constant.Alma,
				Cnf:    cnf,
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
func NewRocky(cnf config.VulnDictInterface) Rocky {
	return Rocky{
		RedHatBase{
			Base{
				family: constant.Rocky,
				Cnf:    cnf,
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
func NewFedora(cnf config.VulnDictInterface) Fedora {
	return Fedora{
		RedHatBase{
			Base{
				family: constant.Fedora,
				Cnf:    cnf,
			},
		},
	}
}
