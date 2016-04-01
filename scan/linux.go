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

package scan

import (
	"sort"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
)

type linux struct {
	ServerInfo config.ServerInfo

	Family  string
	Release string
	osPackages
	log *logrus.Entry
}

func (l *linux) ssh(cmd string, sudo bool) sshResult {
	return sshExec(l.ServerInfo, cmd, sudo, l.log)
}

func (l *linux) setServerInfo(c config.ServerInfo) {
	l.ServerInfo = c
}

func (l *linux) getServerInfo() config.ServerInfo {
	return l.ServerInfo
}

func (l *linux) setDistributionInfo(fam, rel string) {
	l.Family = fam
	l.Release = rel
}

func (l *linux) convertToModel() (models.ScanResult, error) {
	var cves, unknownScoreCves []models.CveInfo
	for _, p := range l.UnsecurePackages {
		if p.CveDetail.CvssScore(config.Conf.Lang) < 0 {
			unknownScoreCves = append(unknownScoreCves, models.CveInfo{
				CveDetail:        p.CveDetail,
				Packages:         p.Packs,
				DistroAdvisories: p.DistroAdvisories, // only Amazon Linux
			})
			continue
		}

		cpenames := []models.CpeName{}
		for _, cpename := range p.CpeNames {
			cpenames = append(cpenames,
				models.CpeName{Name: cpename})
		}

		cve := models.CveInfo{
			CveDetail:        p.CveDetail,
			Packages:         p.Packs,
			DistroAdvisories: p.DistroAdvisories, // only Amazon Linux
			CpeNames:         cpenames,
		}
		cves = append(cves, cve)
	}

	return models.ScanResult{
		ServerName:  l.ServerInfo.ServerName,
		Family:      l.Family,
		Release:     l.Release,
		KnownCves:   cves,
		UnknownCves: unknownScoreCves,
	}, nil
}

// scanVulnByCpeName search vulnerabilities that specified in config file.
func (l *linux) scanVulnByCpeName() error {
	unsecurePacks := CvePacksList{}

	serverInfo := l.getServerInfo()
	cpeNames := serverInfo.CpeNames

	// remove duplicate
	set := map[string]CvePacksInfo{}

	for _, name := range cpeNames {
		details, err := cveapi.CveClient.FetchCveDetailsByCpeName(name)
		if err != nil {
			return err
		}
		for _, detail := range details {
			if val, ok := set[detail.CveID]; ok {
				names := val.CpeNames
				names = append(names, name)
				val.CpeNames = names
				set[detail.CveID] = val
			} else {
				set[detail.CveID] = CvePacksInfo{
					CveID:     detail.CveID,
					CveDetail: detail,
					CpeNames:  []string{name},
				}
			}
		}
	}

	for key := range set {
		unsecurePacks = append(unsecurePacks, set[key])
	}
	unsecurePacks = append(unsecurePacks, l.UnsecurePackages...)
	sort.Sort(CvePacksList(unsecurePacks))
	l.setUnsecurePackages(unsecurePacks)
	return nil
}
