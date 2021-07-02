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
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// RedHatBase is the base struct for RedHat, CentOS and Rocky
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
		driver, err := newOvalDB(o.Cnf, r.Family)
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
			if cont, ok := vuln.CveContents[models.RedHat]; ok {
				cont.SourceLink = "https://access.redhat.com/security/cve/" + cont.CveID
				vuln.CveContents[models.RedHat] = cont
			}
		case models.Oracle:
			if cont, ok := vuln.CveContents[models.Oracle]; ok {
				cont.SourceLink = fmt.Sprintf("https://linux.oracle.com/cve/%s.html", cont.CveID)
				vuln.CveContents[models.Oracle] = cont
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

func (o RedHatBase) update(r *models.ScanResult, defPacks defPacks) (nCVEs int) {
	ctype := models.NewCveContentType(o.family)
	for _, cve := range defPacks.def.Advisory.Cves {
		ovalContent := *o.convertToModel(cve.CveID, &defPacks.def)
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			logging.Log.Debugf("%s is newly detected by OVAL: DefID: %s", cve.CveID, defPacks.def.DefinitionID)
			vinfo = models.VulnInfo{
				CveID:       cve.CveID,
				Confidences: models.Confidences{models.OvalMatch},
				CveContents: models.NewCveContents(ovalContent),
			}
			nCVEs++
		} else {
			cveContents := vinfo.CveContents
			if v, ok := vinfo.CveContents[ctype]; ok {
				if v.LastModified.After(ovalContent.LastModified) {
					logging.Log.Debugf("%s ignored. DefID: %s ", cve.CveID, defPacks.def.DefinitionID)
				} else {
					logging.Log.Debugf("%s OVAL will be overwritten. DefID: %s", cve.CveID, defPacks.def.DefinitionID)
				}
			} else {
				logging.Log.Debugf("%s also detected by OVAL. DefID: %s", cve.CveID, defPacks.def.DefinitionID)
				cveContents = models.CveContents{}
			}

			vinfo.Confidences.AppendIfMissing(models.OvalMatch)
			cveContents[ctype] = ovalContent
			vinfo.CveContents = cveContents
		}

		vinfo.DistroAdvisories.AppendIfMissing(
			o.convertToDistroAdvisory(&defPacks.def))

		// uniq(vinfo.PackNames + defPacks.actuallyAffectedPackNames)
		for _, pack := range vinfo.AffectedPackages {
			if stat, ok := defPacks.binpkgFixstat[pack.Name]; !ok {
				defPacks.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: pack.NotFixedYet,
					fixedIn:     pack.FixedIn,
				}
			} else if stat.notFixedYet {
				defPacks.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: true,
					fixedIn:     pack.FixedIn,
				}
			}
		}
		vinfo.AffectedPackages = defPacks.toPackStatuses()
		vinfo.AffectedPackages.Sort()
		r.ScannedCves[cve.CveID] = vinfo
	}
	return
}

func (o RedHatBase) convertToDistroAdvisory(def *ovalmodels.Definition) *models.DistroAdvisory {
	advisoryID := def.Title
	switch o.family {
	case constant.RedHat, constant.CentOS, constant.Rocky, constant.Oracle:
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
	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}
		var refs []models.Reference
		for _, r := range def.References {
			refs = append(refs, models.Reference{
				Link:   r.RefURL,
				Source: r.Source,
				RefID:  r.RefID,
			})
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
