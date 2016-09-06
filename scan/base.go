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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
)

type base struct {
	ServerInfo config.ServerInfo

	Family   string
	Release  string
	Platform models.Platform
	osPackages

	log  *logrus.Entry
	errs []error
}

func (l *base) ssh(cmd string, sudo bool) sshResult {
	return sshExec(l.ServerInfo, cmd, sudo, l.log)
}

func (l *base) setServerInfo(c config.ServerInfo) {
	l.ServerInfo = c
}

func (l base) getServerInfo() config.ServerInfo {
	return l.ServerInfo
}

func (l *base) setDistributionInfo(fam, rel string) {
	l.Family = fam
	l.Release = rel
}

func (l base) getDistributionInfo() string {
	return fmt.Sprintf("%s %s", l.Family, l.Release)
}

func (l *base) setPlatform(p models.Platform) {
	l.Platform = p
}

func (l base) getPlatform() models.Platform {
	return l.Platform
}

func (l base) allContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.Container.Type {
	case "", "docker":
		stdout, err := l.dockerPs("-a --format '{{.ID}} {{.Names}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	default:
		return containers, fmt.Errorf(
			"Not supported yet: %s", l.ServerInfo.Container.Type)
	}
}

func (l *base) runningContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.Container.Type {
	case "", "docker":
		stdout, err := l.dockerPs("--format '{{.ID}} {{.Names}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	default:
		return containers, fmt.Errorf(
			"Not supported yet: %s", l.ServerInfo.Container.Type)
	}
}

func (l *base) exitedContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.Container.Type {
	case "", "docker":
		stdout, err := l.dockerPs("--filter 'status=exited' --format '{{.ID}} {{.Names}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	default:
		return containers, fmt.Errorf(
			"Not supported yet: %s", l.ServerInfo.Container.Type)
	}
}

func (l *base) dockerPs(option string) (string, error) {
	cmd := fmt.Sprintf("docker ps %s", option)
	r := l.ssh(cmd, noSudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseDockerPs(stdout string) (containers []config.Container, err error) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			break
		}
		if len(fields) != 2 {
			return containers, fmt.Errorf("Unknown format: %s", line)
		}
		containers = append(containers, config.Container{
			ContainerID: fields[0],
			Name:        fields[1],
		})
	}
	return
}

func (l *base) detectPlatform() error {
	ok, instanceID, err := l.detectRunningOnAws()
	if err != nil {
		return err
	}
	if ok {
		l.setPlatform(models.Platform{
			Name:       "aws",
			InstanceID: instanceID,
		})
		return nil
	}

	//TODO Azure, GCP...
	l.setPlatform(models.Platform{
		Name: "other",
	})
	return nil
}

func (l base) detectRunningOnAws() (ok bool, instanceID string, err error) {
	if r := l.ssh("type curl", noSudo); r.isSuccess() {
		cmd := "curl --max-time 1 --retry 3 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id"
		r := l.ssh(cmd, noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)

			if id == "not found" {
				// status: 0, stdout: "not found" on degitalocean or Azure
				return false, "", nil
			}
			return true, id, nil
		}

		switch r.ExitStatus {
		case 28, 7:
			// Not running on AWS
			//  7   Failed to connect to host.
			// 28  operation timeout.
			return false, "", nil
		}
	}

	if r := l.ssh("type wget", noSudo); r.isSuccess() {
		cmd := "wget --tries=3 --timeout=1 --no-proxy -q -O - http://169.254.169.254/latest/meta-data/instance-id"
		r := l.ssh(cmd, noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			return true, id, nil
		}

		switch r.ExitStatus {
		case 4, 8:
			// Not running on AWS
			// 4   Network failure
			// 8   Server issued an error response.
			return false, "", nil
		}
	}
	return false, "", fmt.Errorf(
		"Failed to curl or wget to AWS instance metadata on %s. container: %s",
		l.ServerInfo.ServerName, l.ServerInfo.Container.Name)
}

func (l *base) convertToModel() (models.ScanResult, error) {
	var scoredCves, unscoredCves models.CveInfos
	for _, p := range l.UnsecurePackages {
		if p.CveDetail.CvssScore(config.Conf.Lang) <= 0 {
			unscoredCves = append(unscoredCves, models.CveInfo{
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
		scoredCves = append(scoredCves, cve)
	}

	container := models.Container{
		ContainerID: l.ServerInfo.Container.ContainerID,
		Name:        l.ServerInfo.Container.Name,
	}

	sort.Sort(scoredCves)
	sort.Sort(unscoredCves)

	return models.ScanResult{
		ServerName:  l.ServerInfo.ServerName,
		ScannedAt:   time.Now(),
		Family:      l.Family,
		Release:     l.Release,
		Container:   container,
		Platform:    l.Platform,
		KnownCves:   scoredCves,
		UnknownCves: unscoredCves,
		Optional:    l.ServerInfo.Optional,
	}, nil
}

// scanVulnByCpeName search vulnerabilities that specified in config file.
func (l *base) scanVulnByCpeName() error {
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
	l.setUnsecurePackages(unsecurePacks)
	return nil
}

func (l *base) setErrs(errs []error) {
	l.errs = errs
}

func (l base) getErrs() []error {
	return l.errs
}
