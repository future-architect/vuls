/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/exploit"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/util"
	"github.com/hashicorp/uuid"
	gostdb "github.com/knqyf263/gost/db"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
	exploitdb "github.com/mozqnet/go-exploitdb/db"
)

const (
	vulsOpenTag  = "<vulsreport>"
	vulsCloseTag = "</vulsreport>"
)

// FillCveInfos fills CVE Detailed Information
func FillCveInfos(dbclient DBClient, rs []models.ScanResult, dir string) ([]models.ScanResult, error) {
	var filledResults []models.ScanResult
	reportedAt := time.Now()
	hostname, _ := os.Hostname()
	for _, r := range rs {
		if c.Conf.RefreshCve || needToRefreshCve(r) {
			r.ScannedCves = models.VulnInfos{}
			cpeURIs := []string{}
			if len(r.Container.ContainerID) == 0 {
				cpeURIs = c.Conf.Servers[r.ServerName].CpeNames
				owaspDCXMLPath := c.Conf.Servers[r.ServerName].OwaspDCXMLPath
				if owaspDCXMLPath != "" {
					cpes, err := parser.Parse(owaspDCXMLPath)
					if err != nil {
						return nil, fmt.Errorf("Failed to read OWASP Dependency Check XML: %s, %s, %s",
							r.ServerName, owaspDCXMLPath, err)
					}
					cpeURIs = append(cpeURIs, cpes...)
				}
			} else {
				if s, ok := c.Conf.Servers[r.ServerName]; ok {
					if con, ok := s.Containers[r.Container.Name]; ok {
						cpeURIs = con.Cpes
						owaspDCXMLPath := con.OwaspDCXMLPath
						if owaspDCXMLPath != "" {
							cpes, err := parser.Parse(owaspDCXMLPath)
							if err != nil {
								return nil, fmt.Errorf("Failed to read OWASP Dependency Check XML: %s, %s, %s",
									r.ServerInfo(), owaspDCXMLPath, err)
							}
							cpeURIs = append(cpeURIs, cpes...)
						}
					}
				}
			}

			if err := FillCveInfo(dbclient, &r, cpeURIs); err != nil {
				return nil, err
			}
			r.Lang = c.Conf.Lang
			r.ReportedAt = reportedAt
			r.ReportedVersion = c.Version
			r.ReportedRevision = c.Revision
			r.ReportedBy = hostname
			r.Config.Report = c.Conf
			r.Config.Report.Servers = map[string]c.ServerInfo{
				r.ServerName: c.Conf.Servers[r.ServerName],
			}
			if err := overwriteJSONFile(dir, r); err != nil {
				return nil, fmt.Errorf("Failed to write JSON: %s", err)
			}
			filledResults = append(filledResults, r)
		} else {
			util.Log.Debugf("No need to refresh")
			filledResults = append(filledResults, r)
		}
	}

	if c.Conf.Diff {
		prevs, err := loadPrevious(filledResults)
		if err != nil {
			return nil, err
		}

		diff, err := diff(filledResults, prevs)
		if err != nil {
			return nil, err
		}
		filledResults = []models.ScanResult{}
		for _, r := range diff {
			if err := fillCveDetail(dbclient.CveDB, &r); err != nil {
				return nil, err
			}
			filledResults = append(filledResults, r)
		}
	}

	filtered := []models.ScanResult{}
	for _, r := range filledResults {
		r = r.FilterByCvssOver(c.Conf.CvssScoreOver)
		r = r.FilterIgnoreCves()
		r = r.FilterUnfixed()
		r = r.FilterIgnorePkgs()
		if c.Conf.IgnoreUnscoredCves {
			r.ScannedCves = r.ScannedCves.FindScoredVulns()
		}
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// FillCveInfo fill scanResult with cve info.
func FillCveInfo(dbclient DBClient, r *models.ScanResult, cpeURIs []string) error {
	util.Log.Debugf("need to refresh")

	nCVEs, err := FillWithOval(dbclient.OvalDB, r)
	if err != nil {
		return fmt.Errorf("Failed to fill with OVAL: %s", err)
	}
	util.Log.Infof("%s: %d CVEs are detected with OVAL",
		r.FormatServerName(), nCVEs)

	for i, v := range r.ScannedCves {
		for j, p := range v.AffectedPackages {
			if p.NotFixedYet && p.FixState == "" {
				p.FixState = "Not fixed yet"
				r.ScannedCves[i].AffectedPackages[j] = p
			}
		}
	}

	nCVEs, err = fillVulnByCpeURIs(dbclient.CveDB, r, cpeURIs)
	if err != nil {
		return fmt.Errorf("Failed to detect vulns of %s: %s", cpeURIs, err)
	}
	util.Log.Infof("%s: %d CVEs are detected with CPE", r.FormatServerName(), nCVEs)

	nCVEs, err = FillWithGost(dbclient.GostDB, r)
	if err != nil {
		return fmt.Errorf("Failed to fill with gost: %s", err)
	}
	util.Log.Infof("%s: %d unfixed CVEs are detected with gost",
		r.FormatServerName(), nCVEs)

	util.Log.Infof("Fill CVE detailed information with CVE-DB")
	if err := fillCveDetail(dbclient.CveDB, r); err != nil {
		return fmt.Errorf("Failed to fill with CVE: %s", err)
	}

	util.Log.Infof("Fill Exploit information with Exploit-DB")
	nExploitCve, err := FillWithExploit(dbclient.ExploitDB, r)
	if err != nil {
		return fmt.Errorf("Failed to fill with exploit: %s", err)
	}
	util.Log.Infof("%s: %d Exploits are detected with exploit",
		r.FormatServerName(), nExploitCve)

	fillCweDict(r)
	return nil
}

// fillCveDetail fetches NVD, JVN from CVE Database
func fillCveDetail(driver cvedb.DB, r *models.ScanResult) error {
	var cveIDs []string
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	ds, err := CveClient.FetchCveDetails(driver, cveIDs)
	if err != nil {
		return err
	}
	for _, d := range ds {
		nvd := models.ConvertNvdJSONToModel(d.CveID, d.NvdJSON)
		if nvd == nil {
			nvd = models.ConvertNvdXMLToModel(d.CveID, d.NvdXML)
		}
		jvn := models.ConvertJvnToModel(d.CveID, d.Jvn)

		for cveID, vinfo := range r.ScannedCves {
			if vinfo.CveID == d.CveID {
				if vinfo.CveContents == nil {
					vinfo.CveContents = models.CveContents{}
				}
				for _, con := range []*models.CveContent{nvd, jvn} {
					if con != nil && !con.Empty() {
						vinfo.CveContents[con.Type] = *con
					}
				}
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

// FillWithOval fetches OVAL database
func FillWithOval(driver ovaldb.DB, r *models.ScanResult) (nCVEs int, err error) {
	var ovalClient oval.Client
	var ovalFamily string

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
	case c.Alpine:
		ovalClient = oval.NewAlpine()
		ovalFamily = c.Alpine
	case c.Amazon, c.Raspbian, c.FreeBSD, c.Windows:
		return 0, nil
	case c.ServerTypePseudo:
		return 0, nil
	default:
		if r.Family == "" {
			return 0, fmt.Errorf("Probably an error occurred during scanning. Check the error message")
		}
		return 0, fmt.Errorf("OVAL for %s is not implemented yet", r.Family)
	}

	if !c.Conf.OvalDict.IsFetchViaHTTP() {
		if driver == nil {
			return 0, nil
		}
		if err = driver.NewOvalDB(ovalFamily); err != nil {
			return 0, fmt.Errorf("Failed to New Oval DB. err: %s", err)
		}
	}

	util.Log.Debugf("Check whether oval fetched: %s %s", ovalFamily, r.Release)
	ok, err := ovalClient.CheckIfOvalFetched(driver, ovalFamily, r.Release)
	if err != nil {
		return 0, err
	}
	if !ok {
		util.Log.Warnf("OVAL entries of %s %s are not found. It's recommended to use OVAL to improve scanning accuracy. For details, see https://github.com/kotakanbe/goval-dictionary#usage , Then report with --ovaldb-path or --ovaldb-url flag", ovalFamily, r.Release)
		return 0, nil
	}

	_, err = ovalClient.CheckIfOvalFresh(driver, ovalFamily, r.Release)
	if err != nil {
		return 0, err
	}

	return ovalClient.FillWithOval(driver, r)
}

// FillWithGost fills CVEs with gost dataabase
// https://github.com/knqyf263/gost
func FillWithGost(driver gostdb.DB, r *models.ScanResult) (nCVEs int, err error) {
	gostClient := gost.NewClient(r.Family)
	// TODO chekc if fetched
	// TODO chekc if fresh enough
	return gostClient.FillWithGost(driver, r)
}

// FillWithExploit fills Exploits with exploit dataabase
// https://github.com/mozqnet/go-exploitdb
func FillWithExploit(driver exploitdb.DB, r *models.ScanResult) (nExploitCve int, err error) {
	// TODO chekc if fetched
	// TODO chekc if fresh enough
	return exploit.FillWithExploit(driver, r)
}

func fillVulnByCpeURIs(driver cvedb.DB, r *models.ScanResult, cpeURIs []string) (nCVEs int, err error) {
	for _, name := range cpeURIs {
		details, err := CveClient.FetchCveDetailsByCpeName(driver, name)
		if err != nil {
			return 0, err
		}
		for _, detail := range details {
			if val, ok := r.ScannedCves[detail.CveID]; ok {
				names := val.CpeURIs
				names = util.AppendIfMissing(names, name)
				val.CpeURIs = names
				val.Confidences.AppendIfMissing(models.CpeNameMatch)
				r.ScannedCves[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:       detail.CveID,
					CpeURIs:     []string{name},
					Confidences: models.Confidences{models.CpeNameMatch},
				}
				r.ScannedCves[detail.CveID] = v
				nCVEs++
			}
		}
	}
	return nCVEs, nil
}

func fillCweDict(r *models.ScanResult) {
	uniqCweIDMap := map[string]bool{}
	for _, vinfo := range r.ScannedCves {
		for _, cont := range vinfo.CveContents {
			for _, id := range cont.CweIDs {
				if strings.HasPrefix(id, "CWE-") {
					id = strings.TrimPrefix(id, "CWE-")
					uniqCweIDMap[id] = true
				}
			}
		}
	}

	// TODO check the format of CWEID, clean CWEID
	// JVN, NVD XML, JSON, OVALs

	dict := map[string]models.CweDictEntry{}
	for id := range uniqCweIDMap {
		entry := models.CweDictEntry{}
		if e, ok := cwe.CweDictEn[id]; ok {
			if rank, ok := cwe.OwaspTopTen2017[id]; ok {
				entry.OwaspTopTen2017 = rank
			}
			entry.En = &e
		} else {
			util.Log.Debugf("CWE-ID %s is not found in English CWE Dict", id)
			entry.En = &cwe.Cwe{CweID: id}
		}

		if c.Conf.Lang == "ja" {
			if e, ok := cwe.CweDictJa[id]; ok {
				if rank, ok := cwe.OwaspTopTen2017[id]; ok {
					entry.OwaspTopTen2017 = rank
				}
				entry.Ja = &e
			} else {
				util.Log.Debugf("CWE-ID %s is not found in Japanese CWE Dict", id)
				entry.Ja = &cwe.Cwe{CweID: id}
			}
		}
		dict[id] = entry
	}
	r.CweDict = dict
	return
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

	cveDict := &c.Conf.CveDict
	ovalDict := &c.Conf.OvalDict
	gost := &c.Conf.Gost
	exploit := &c.Conf.Exploit
	http := &c.Conf.HTTP
	if http.URL == "" {
		http = nil
	}

	syslog := &c.Conf.Syslog
	if syslog.Host == "" {
		syslog = nil
	}

	aws := &c.Conf.AWS
	if aws.S3Bucket == "" {
		aws = nil
	}

	azure := &c.Conf.Azure
	if azure.AccountName == "" {
		azure = nil
	}

	stride := &c.Conf.Stride
	if stride.HookURL == "" {
		stride = nil
	}

	hipChat := &c.Conf.HipChat
	if hipChat.AuthToken == "" {
		hipChat = nil
	}

	chatWork := &c.Conf.ChatWork
	if chatWork.APIToken == "" {
		chatWork = nil
	}

	saas := &c.Conf.Saas
	if saas.GroupID == 0 {
		saas = nil
	}

	c := struct {
		CveDict  *c.GoCveDictConf `toml:"cveDict"`
		OvalDict *c.GovalDictConf `toml:"ovalDict"`
		Gost     *c.GostConf      `toml:"gost"`
		Exploit  *c.ExploitConf   `toml:"exploit"`
		Slack    *c.SlackConf     `toml:"slack"`
		Email    *c.SMTPConf      `toml:"email"`
		HTTP     *c.HTTPConf      `toml:"http"`
		Syslog   *c.SyslogConf    `toml:"syslog"`
		AWS      *c.AWS           `toml:"aws"`
		Azure    *c.Azure         `toml:"azure"`
		Stride   *c.StrideConf    `toml:"stride"`
		HipChat  *c.HipChatConf   `toml:"hipChat"`
		ChatWork *c.ChatWorkConf  `toml:"chatWork"`
		Saas     *c.SaasConf      `toml:"saas"`

		Default c.ServerInfo            `toml:"default"`
		Servers map[string]c.ServerInfo `toml:"servers"`
	}{
		CveDict:  cveDict,
		OvalDict: ovalDict,
		Gost:     gost,
		Exploit:  exploit,
		Slack:    slack,
		Email:    email,
		HTTP:     http,
		Syslog:   syslog,
		AWS:      aws,
		Azure:    azure,
		Stride:   stride,
		HipChat:  hipChat,
		ChatWork: chatWork,
		Saas:     saas,

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
		"# See REAME for details: https://vuls.io/docs/en/usage-settings.html",
		str)

	return ioutil.WriteFile(realPath, []byte(str), 0600)
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

	if reflect.DeepEqual(server.ScanMode, def.ScanMode) {
		server.ScanMode = nil
	}

	if def.Type == server.Type {
		server.Type = ""
	}

	if reflect.DeepEqual(server.CpeNames, def.CpeNames) {
		server.CpeNames = nil
	}

	if def.OwaspDCXMLPath == server.OwaspDCXMLPath {
		server.OwaspDCXMLPath = ""
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
