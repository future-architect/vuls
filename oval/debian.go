/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package oval

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

func (o DebianBase) update(r *models.ScanResult, defPacks defPacks) {
	ovalContent := *o.convertToModel(&defPacks.def)
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[defPacks.def.Debian.CveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", defPacks.def.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:       defPacks.def.Debian.CveID,
			Confidence:  models.OvalMatch,
			CveContents: models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s OVAL will be overwritten",
				defPacks.def.Debian.CveID)
		} else {
			util.Log.Debugf("%s is also detected by OVAL",
				defPacks.def.Debian.CveID)
			cveContents = models.CveContents{}
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.PackNames + defPacks.actuallyAffectedPackNames)
	for _, pack := range vinfo.AffectedPackages {
		defPacks.actuallyAffectedPackNames[pack.Name] = true
	}
	vinfo.AffectedPackages = defPacks.toPackStatuses(r.Family, r.Packages)
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[defPacks.def.Debian.CveID] = vinfo
}

func (o DebianBase) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	var refs []models.Reference
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	return &models.CveContent{
		CveID:      def.Debian.CveID,
		Title:      def.Title,
		Summary:    def.Description,
		Severity:   def.Advisory.Severity,
		References: refs,
	}
}

// Debian is the interface for Debian OVAL
type Debian struct {
	DebianBase
}

// NewDebian creates OVAL client for Debian
func NewDebian() Debian {
	return Debian{
		DebianBase{
			Base{
				family: config.Debian,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Debian) FillWithOval(r *models.ScanResult) (err error) {

	//Debian's uname gives both of kernel release(uname -r), version(kernel-image version)
	linuxImage := "linux-image-" + r.RunningKernel.Release
	// Add linux and set the version of running kernel to search OVAL.
	if r.Container.ContainerID == "" {
		r.Packages["linux"] = models.Package{
			Name:    "linux",
			Version: r.RunningKernel.Version,
		}
	}

	var relatedDefs ovalResult
	if o.isFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(o.family, r.Release, r.Packages); err != nil {
			return err
		}
	}

	delete(r.Packages, "linux")

	for _, defPacks := range relatedDefs.entries {
		// Remove linux added above to search for oval
		// linux is not a real package name (key of affected packages in OVAL)
		if _, ok := defPacks.actuallyAffectedPackNames["linux"]; ok {
			defPacks.actuallyAffectedPackNames[linuxImage] = true
			delete(defPacks.actuallyAffectedPackNames, "linux")
			for i, p := range defPacks.def.AffectedPacks {
				if p.Name == "linux" {
					p.Name = linuxImage
					defPacks.def.AffectedPacks[i] = p
				}
			}
		}
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.Debian]; ok {
			cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
			vuln.CveContents[models.Debian] = cont
		}
	}
	return nil
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu() Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				family: config.Ubuntu,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(r *models.ScanResult) (err error) {
	ovalKernelImageNames := []string{
		"linux-aws",
		"linux-azure",
		"linux-flo",
		"linux-gcp",
		"linux-gke",
		"linux-goldfish",
		"linux-hwe",
		"linux-hwe-edge",
		"linux-kvm",
		"linux-mako",
		"linux-raspi2",
		"linux-snapdragon",
	}
	linuxImage := "linux-image-" + r.RunningKernel.Release

	found := false
	if r.Container.ContainerID == "" {
		for _, n := range ovalKernelImageNames {
			if _, ok := r.Packages[n]; ok {
				v, ok := r.Packages[linuxImage]
				if ok {
					// Set running kernel version
					p := r.Packages[n]
					p.Version = v.Version
					p.NewVersion = v.NewVersion
					r.Packages[n] = p
				} else {
					util.Log.Warnf("Running kernel image %s is not found: %s",
						linuxImage, r.RunningKernel.Version)
				}
				found = true
				break
			}
		}

		if !found {
			// linux-generic is described as "linux" in Ubuntu's oval.
			// Add "linux" and set the version of running kernel to search OVAL.
			v, ok := r.Packages[linuxImage]
			if ok {
				r.Packages["linux"] = models.Package{
					Name:       "linux",
					Version:    v.Version,
					NewVersion: v.NewVersion,
				}
			} else {
				util.Log.Warnf("%s is not found. Running: %s",
					linuxImage, r.RunningKernel.Release)
			}
		}
	}

	var relatedDefs ovalResult
	if o.isFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(o.family, r.Release, r.Packages); err != nil {
			return err
		}
	}

	if !found {
		delete(r.Packages, "linux")
	}

	for _, defPacks := range relatedDefs.entries {

		// Remove "linux" added above to search for oval
		// "linux" is not a real package name (key of affected packages in OVAL)
		if _, ok := defPacks.actuallyAffectedPackNames["linux"]; !found && ok {
			defPacks.actuallyAffectedPackNames[linuxImage] = true
			delete(defPacks.actuallyAffectedPackNames, "linux")
			for i, p := range defPacks.def.AffectedPacks {
				if p.Name == "linux" {
					p.Name = linuxImage
					defPacks.def.AffectedPacks[i] = p
				}
			}
		}
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.Ubuntu]; ok {
			cont.SourceLink = "http://people.ubuntu.com/~ubuntu-security/cve/" + cont.CveID
			vuln.CveContents[models.Ubuntu] = cont
		}
	}
	return nil
}
