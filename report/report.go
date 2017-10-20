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

package report

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/util"
	"github.com/hashicorp/uuid"
)

const (
	vulsOpenTag  = "<vulsreport>"
	vulsCloseTag = "</vulsreport>"
)

// FillCveInfos fills CVE Detailed Information
func FillCveInfos(rs []models.ScanResult, dir string) ([]models.ScanResult, error) {
	var filled []models.ScanResult
	reportedAt := time.Now()
	for _, r := range rs {
		if c.Conf.RefreshCve || needToRefreshCve(r) {
			cpeNames := c.Conf.Servers[r.ServerName].CpeNames
			if err := FillCveInfo(&r, cpeNames); err != nil {
				return nil, err
			}
			r.Lang = c.Conf.Lang
			r.ReportedAt = reportedAt
			r.Config.Report = c.Conf
			r.Config.Report.Servers = map[string]c.ServerInfo{
				r.ServerName: c.Conf.Servers[r.ServerName],
			}
			if err := overwriteJSONFile(dir, r); err != nil {
				return nil, fmt.Errorf("Failed to write JSON: %s", err)
			}
			filled = append(filled, r)
		} else {
			util.Log.Debugf("No need to refresh")
			filled = append(filled, r)
		}
	}

	if c.Conf.Diff {
		previous, err := loadPrevious(filled)
		if err != nil {
			return nil, err
		}

		diff, err := diff(filled, previous)
		if err != nil {
			return nil, err
		}
		filled = []models.ScanResult{}
		for _, r := range diff {
			if err := fillCveDetail(&r); err != nil {
				return nil, err
			}
			filled = append(filled, r)
		}
	}

	filtered := []models.ScanResult{}
	for _, r := range filled {
		r = r.FilterByCvssOver(c.Conf.CvssScoreOver)
		r = r.FilterIgnoreCves(c.Conf.Servers[r.ServerName].IgnoreCves)
		r = r.FilterUnfixed()
		if c.Conf.IgnoreUnscoredCves {
			r.ScannedCves = r.ScannedCves.FindScoredVulns()
		}
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// FillCveInfo fill scanResult with cve info.
func FillCveInfo(r *models.ScanResult, cpeNames []string) error {
	util.Log.Debugf("need to refresh")

	util.Log.Infof("Fill CVE detailed information with OVAL")
	if err := FillWithOval(r); err != nil {
		return fmt.Errorf("Failed to fill OVAL information: %s", err)
	}

	util.Log.Infof("Fill CVE detailed information with CVE-DB")
	if err := fillWithCveDB(r, cpeNames); err != nil {
		return fmt.Errorf("Failed to fill CVE information: %s", err)
	}

	for cveID := range r.ScannedCves {
		vinfo := r.ScannedCves[cveID]
		r.ScannedCves[cveID] = *vinfo.NilToEmpty()
	}
	return nil
}

// fillCveDetail fetches NVD, JVN from CVE Database, and then set to fields.
func fillCveDetail(r *models.ScanResult) error {
	var cveIDs []string
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	ds, err := CveClient.FetchCveDetails(cveIDs)
	if err != nil {
		return err
	}
	for _, d := range ds {
		nvd := models.ConvertNvdToModel(d.CveID, d.Nvd)
		jvn := models.ConvertJvnToModel(d.CveID, d.Jvn)
		for cveID, vinfo := range r.ScannedCves {
			if vinfo.CveID == d.CveID {
				if vinfo.CveContents == nil {
					vinfo.CveContents = models.CveContents{}
				}
				for _, con := range []models.CveContent{*nvd, *jvn} {
					if !con.Empty() {
						vinfo.CveContents[con.Type] = con
					}
				}
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

func fillWithCveDB(r *models.ScanResult, cpeNames []string) error {
	if err := fillVulnByCpeNames(cpeNames, r.ScannedCves); err != nil {
		return err
	}
	if err := fillCveDetail(r); err != nil {
		return err
	}
	return nil
}

// FillWithOval fetches OVAL database, and then set to fields.
func FillWithOval(r *models.ScanResult) (err error) {
	var ovalClient oval.Client
	var ovalFamily string

	// TODO
	switch r.Family {
	case c.Debian:
		ovalClient = oval.NewDebian()
		ovalFamily = c.Debian
	case c.Ubuntu:
		ovalClient = oval.NewUbuntu()
		ovalFamily = c.Ubuntu
	case c.RedHat:
		ovalClient = oval.NewRedhat()
		ovalFamily = c.RedHat
	case c.CentOS:
		ovalClient = oval.NewCentOS()
		//use RedHat's OVAL
		ovalFamily = c.RedHat
	case c.Oracle:
		ovalClient = oval.NewOracle()
		ovalFamily = c.Oracle
	case c.SUSEEnterpriseServer:
		// TODO other suse family
		ovalClient = oval.NewSUSE()
		ovalFamily = c.SUSEEnterpriseServer
	case c.Amazon, c.Raspbian, c.FreeBSD, c.Windows:
		return nil
	default:
		return fmt.Errorf("OVAL for %s is not implemented yet", r.Family)
	}

	ok, err := ovalClient.CheckIfOvalFetched(ovalFamily, r.Release)
	if err != nil {
		return err
	}
	if !ok {
		major := strings.Split(r.Release, ".")[0]
		util.Log.Warnf("OVAL entries of %s %s are not found. It's recommended to use OVAL to improve scanning accuracy. For details, see https://github.com/kotakanbe/goval-dictionary#usage , Then report with --ovaldb-path or --ovaldb-url flag", ovalFamily, major)
		return nil
	}

	_, err = ovalClient.CheckIfOvalFresh(ovalFamily, r.Release)
	if err != nil {
		return err
	}

	if err := ovalClient.FillWithOval(r); err != nil {
		return err
	}
	return nil
}

func fillVulnByCpeNames(cpeNames []string, scannedVulns models.VulnInfos) error {
	for _, name := range cpeNames {
		details, err := CveClient.FetchCveDetailsByCpeName(name)
		if err != nil {
			return err
		}
		for _, detail := range details {
			if val, ok := scannedVulns[detail.CveID]; ok {
				names := val.CpeNames
				names = util.AppendIfMissing(names, name)
				val.CpeNames = names
				val.Confidence = models.CpeNameMatch
				scannedVulns[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:      detail.CveID,
					CpeNames:   []string{name},
					Confidence: models.CpeNameMatch,
				}
				scannedVulns[detail.CveID] = v
			}
		}
	}
	return nil
}

const reUUID = "[\\da-f]{8}-[\\da-f]{4}-[\\da-f]{4}-[\\da-f]{4}-[\\da-f]{12}"

// EnsureUUIDs generate a new UUID of the scan target server if UUID is not assigned yet.
// And then set the generated UUID to config.toml and scan results.
func EnsureUUIDs(configPath string, results models.ScanResults) error {

	// Sort Host->Container
	sort.Slice(results, func(i, j int) bool {
		if results[i].ServerName == results[j].ServerName {
			return results[i].Container.ContainerID < results[j].Container.ContainerID
		}
		return results[i].ServerName < results[j].ServerName
	})

	for i, r := range results {
		server := c.Conf.Servers[r.ServerName]
		if server.UUIDs == nil {
			server.UUIDs = map[string]string{}
		}

		name := ""
		if r.IsContainer() {
			name = fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)

			// Scanning with the -containers-only flag at scan time, the UUID of Container Host may not be generated,
			// so check it. Otherwise create a UUID of the Container Host and set it.
			serverUUID := ""
			if id, ok := server.UUIDs[r.ServerName]; !ok {
				serverUUID = uuid.GenerateUUID()
			} else {
				matched, err := regexp.MatchString(reUUID, id)
				if !matched || err != nil {
					serverUUID = uuid.GenerateUUID()
				}
			}
			if serverUUID != "" {
				server.UUIDs[r.ServerName] = serverUUID
			}
		} else {
			name = r.ServerName
		}

		if id, ok := server.UUIDs[name]; ok {
			matched, err := regexp.MatchString(reUUID, id)
			if !matched || err != nil {
				util.Log.Warnf("UUID is invalid. Re-generate UUID %s: %s", id, err)
			} else {
				if r.IsContainer() {
					results[i].Container.UUID = id
					results[i].ServerUUID = server.UUIDs[r.ServerName]
				} else {
					results[i].ServerUUID = id
				}
				// continue if the UUID has already assigned and valid
				continue
			}
		}

		// Generate a new UUID and set to config and scan result
		id := uuid.GenerateUUID()
		server.UUIDs[name] = id
		server = cleanForTOMLEncoding(server, c.Conf.Default)
		c.Conf.Servers[r.ServerName] = server

		if r.IsContainer() {
			results[i].Container.UUID = id
			results[i].ServerUUID = server.UUIDs[r.ServerName]
		} else {
			results[i].ServerUUID = id
		}
	}

	for name, server := range c.Conf.Servers {
		server = cleanForTOMLEncoding(server, c.Conf.Default)
		c.Conf.Servers[name] = server
	}

	email := &c.Conf.EMail
	if email.SMTPAddr == "" {
		email = nil
	}

	slack := &c.Conf.Slack
	if slack.HookURL == "" {
		slack = nil
	}

	c := struct {
		Email   *c.SMTPConf             `toml:"email"`
		Slack   *c.SlackConf            `toml:"slack"`
		Default c.ServerInfo            `toml:"default"`
		Servers map[string]c.ServerInfo `toml:"servers"`
	}{
		Email:   email,
		Slack:   slack,
		Default: c.Conf.Default,
		Servers: c.Conf.Servers,
	}

	// rename the current config.toml to config.toml.bak
	info, err := os.Lstat(configPath)
	if err != nil {
		return fmt.Errorf("Failed to lstat %s: %s", configPath, err)
	}
	realPath := configPath
	if info.Mode()&os.ModeSymlink == os.ModeSymlink {
		if realPath, err = os.Readlink(configPath); err != nil {
			return fmt.Errorf("Failed to Read link %s: %s", configPath, err)
		}
	}
	if err := os.Rename(realPath, realPath+".bak"); err != nil {
		return fmt.Errorf("Failed to rename %s: %s", configPath, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return fmt.Errorf("Failed to encode to toml: %s", err)
	}
	str := strings.Replace(buf.String(), "\n  [", "\n\n  [", -1)
	str = fmt.Sprintf("%s\n\n%s",
		"# See REAME for details: https://github.com/future-architect/vuls#example",
		str)

	if err := ioutil.WriteFile(realPath, []byte(str), 0600); err != nil {
		return err
	}

	return nil
}

func cleanForTOMLEncoding(server c.ServerInfo, def c.ServerInfo) c.ServerInfo {
	if reflect.DeepEqual(server.Optional, def.Optional) {
		server.Optional = nil
	}

	if def.User == server.User {
		server.User = ""
	}

	if def.Host == server.Host {
		server.Host = ""
	}

	if def.Port == server.Port {
		server.Port = ""
	}

	if def.KeyPath == server.KeyPath {
		server.KeyPath = ""
	}

	if reflect.DeepEqual(server.CpeNames, def.CpeNames) {
		server.CpeNames = nil
	}

	if def.DependencyCheckXMLPath == server.DependencyCheckXMLPath {
		server.DependencyCheckXMLPath = ""
	}

	if reflect.DeepEqual(server.IgnoreCves, def.IgnoreCves) {
		server.IgnoreCves = nil
	}

	if reflect.DeepEqual(server.Enablerepo, def.Enablerepo) {
		server.Enablerepo = nil
	}

	for k, v := range def.Optional {
		if vv, ok := server.Optional[k]; ok && v == vv {
			delete(server.Optional, k)
		}
	}

	return server
}
