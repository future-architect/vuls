// +build !scanner

package report

import (
	"os"
	"strings"
	"time"

	"github.com/future-architect/vuls/libmanager"

	"github.com/future-architect/vuls/config"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/exploit"
	"github.com/future-architect/vuls/github"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/msf"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/util"
	"github.com/future-architect/vuls/wordpress"
	gostdb "github.com/knqyf263/gost/db"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	cvemodels "github.com/kotakanbe/go-cve-dictionary/models"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
	exploitdb "github.com/mozqnet/go-exploitdb/db"
	metasploitdb "github.com/takuzoo3868/go-msfdb/db"
	"golang.org/x/xerrors"
)

// FillCveInfos fills CVE Detailed Information
func FillCveInfos(dbclient DBClient, rs []models.ScanResult, dir string) ([]models.ScanResult, error) {

	// Use the same reportedAt for all rs
	reportedAt := time.Now()
	for i, r := range rs {
		if !c.Conf.RefreshCve && !needToRefreshCve(r) {
			util.Log.Info("No need to refresh")
			continue
		}

		if !useScannedCves(&r) {
			r.ScannedCves = models.VulnInfos{}
		}

		cpeURIs := []string{}
		if len(r.Container.ContainerID) == 0 {
			cpeURIs = c.Conf.Servers[r.ServerName].CpeNames
			owaspDCXMLPath := c.Conf.Servers[r.ServerName].OwaspDCXMLPath
			if owaspDCXMLPath != "" {
				cpes, err := parser.Parse(owaspDCXMLPath)
				if err != nil {
					return nil, xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
						r.ServerName, owaspDCXMLPath, err)
				}
				cpeURIs = append(cpeURIs, cpes...)
			}
		} else {
			// runningContainer
			if s, ok := c.Conf.Servers[r.ServerName]; ok {
				if con, ok := s.Containers[r.Container.Name]; ok {
					cpeURIs = con.Cpes
					owaspDCXMLPath := con.OwaspDCXMLPath
					if owaspDCXMLPath != "" {
						cpes, err := parser.Parse(owaspDCXMLPath)
						if err != nil {
							return nil, xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
								r.ServerInfo(), owaspDCXMLPath, err)
						}
						cpeURIs = append(cpeURIs, cpes...)
					}
				}
			}
		}

		nCVEs, err := libmanager.DetectLibsCves(&r)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fill with Library dependency: %w", err)
		}
		util.Log.Infof("%s: %d CVEs are detected with Library",
			r.FormatServerName(), nCVEs)

		// Integrations
		githubInts := GithubSecurityAlerts(c.Conf.Servers[r.ServerName].GitHubRepos)

		wpVulnCaches := map[string]string{}
		wpOpt := WordPressOption{c.Conf.Servers[r.ServerName].WordPress.WPVulnDBToken, &wpVulnCaches}

		if err := FillCveInfo(dbclient,
			&r,
			cpeURIs,
			true,
			githubInts,
			wpOpt); err != nil {
			return nil, err
		}

		r.ReportedBy, _ = os.Hostname()
		r.Lang = c.Conf.Lang
		r.ReportedAt = reportedAt
		r.ReportedVersion = c.Version
		r.ReportedRevision = c.Revision
		r.Config.Report = c.Conf
		r.Config.Report.Servers = map[string]c.ServerInfo{
			r.ServerName: c.Conf.Servers[r.ServerName],
		}
		rs[i] = r
	}

	// Overwrite the json file every time to clear the fields specified in config.IgnoredJSONKeys
	for _, r := range rs {
		if s, ok := c.Conf.Servers[r.ServerName]; ok {
			r = r.ClearFields(s.IgnoredJSONKeys)
		}
		if err := overwriteJSONFile(dir, r); err != nil {
			return nil, xerrors.Errorf("Failed to write JSON: %w", err)
		}
	}

	if c.Conf.Diff {
		prevs, err := loadPrevious(rs)
		if err != nil {
			return nil, err
		}

		diff, err := diff(rs, prevs)
		if err != nil {
			return nil, err
		}
		for i, r := range diff {
			if err := fillCvesWithNvdJvn(dbclient.CveDB, &r); err != nil {
				return nil, err
			}
			rs[i] = r
		}
	}

	for i, r := range rs {
		r = r.FilterByCvssOver(c.Conf.CvssScoreOver)
		r = r.FilterIgnoreCves()
		r = r.FilterUnfixed()
		r = r.FilterIgnorePkgs()
		r = r.FilterInactiveWordPressLibs()
		if c.Conf.IgnoreUnscoredCves {
			r.ScannedCves = r.ScannedCves.FindScoredVulns()
		}
		rs[i] = r
	}
	return rs, nil
}

// FillCveInfo fill scanResult with cve info.
func FillCveInfo(dbclient DBClient, r *models.ScanResult, cpeURIs []string, ignoreWillNotFix bool, integrations ...Integration) error {
	util.Log.Debugf("need to refresh")
	nCVEs, err := DetectPkgsCvesWithOval(dbclient.OvalDB, r)
	if err != nil {
		return xerrors.Errorf("Failed to fill with OVAL: %w", err)
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

	// To keep backward compatibility
	for i, pkg := range r.Packages {
		for j, proc := range pkg.AffectedProcs {
			for _, ipPort := range proc.ListenPorts {
				ps, err := models.NewPortStat(ipPort)
				if err != nil {
					util.Log.Warnf("Failed to parse ip:port: %s, err:%+v", ipPort, err)
					continue
				}
				r.Packages[i].AffectedProcs[j].ListenPortStats = append(
					r.Packages[i].AffectedProcs[j].ListenPortStats, *ps)
			}
		}
	}

	nCVEs, err = DetectCpeURIsCves(dbclient.CveDB, r, cpeURIs)
	if err != nil {
		return xerrors.Errorf("Failed to detect vulns of `%s`: %w", cpeURIs, err)
	}
	util.Log.Infof("%s: %d CVEs are detected with CPE", r.FormatServerName(), nCVEs)

	ints := &integrationResults{}
	for _, o := range integrations {
		if err = o.apply(r, ints); err != nil {
			return xerrors.Errorf("Failed to fill with integration: %w", err)
		}
	}
	util.Log.Infof("%s: %d CVEs are detected with GitHub Security Alerts", r.FormatServerName(), ints.GithubAlertsCveCounts)

	nCVEs, err = DetectPkgsCvesWithGost(dbclient.GostDB, r, ignoreWillNotFix)
	if err != nil {
		return xerrors.Errorf("Failed to fill with gost: %w", err)
	}
	util.Log.Infof("%s: %d unfixed CVEs are detected with gost",
		r.FormatServerName(), nCVEs)

	util.Log.Infof("Fill CVE detailed information with CVE-DB")
	if err := fillCvesWithNvdJvn(dbclient.CveDB, r); err != nil {
		return xerrors.Errorf("Failed to fill with CVE: %w", err)
	}

	util.Log.Infof("Fill exploit information with Exploit-DB")
	nExploitCve, err := FillWithExploitDB(dbclient.ExploitDB, r)
	if err != nil {
		return xerrors.Errorf("Failed to fill with exploit: %w", err)
	}
	util.Log.Infof("%s: %d exploits are detected",
		r.FormatServerName(), nExploitCve)

	util.Log.Infof("Fill metasploit module information with Metasploit-DB")
	nMetasploitCve, err := FillWithMetasploit(dbclient.MetasploitDB, r)
	if err != nil {
		return xerrors.Errorf("Failed to fill with metasploit: %w", err)
	}
	util.Log.Infof("%s: %d modules are detected",
		r.FormatServerName(), nMetasploitCve)

	fillCweDict(r)
	return nil
}

// fillCvesWithNvdJvn fetches NVD, JVN from CVE Database
func fillCvesWithNvdJvn(driver cvedb.DB, r *models.ScanResult) error {
	cveIDs := []string{}
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	ds, err := CveClient.FetchCveDetails(driver, cveIDs)
	if err != nil {
		return err
	}
	for _, d := range ds {
		nvd := models.ConvertNvdJSONToModel(d.CveID, d.NvdJSON)
		jvn := models.ConvertJvnToModel(d.CveID, d.Jvn)

		alerts := fillCertAlerts(&d)
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
				vinfo.AlertDict = alerts
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

func fillCertAlerts(cvedetail *cvemodels.CveDetail) (dict models.AlertDict) {
	if cvedetail.NvdJSON != nil {
		for _, cert := range cvedetail.NvdJSON.Certs {
			dict.En = append(dict.En, models.Alert{
				URL:   cert.Link,
				Title: cert.Title,
				Team:  "us",
			})
		}
	}
	if cvedetail.Jvn != nil {
		for _, cert := range cvedetail.Jvn.Certs {
			dict.Ja = append(dict.Ja, models.Alert{
				URL:   cert.Link,
				Title: cert.Title,
				Team:  "jp",
			})
		}
	}
	return dict
}

// DetectPkgsCvesWithOval fetches OVAL database
func DetectPkgsCvesWithOval(driver ovaldb.DB, r *models.ScanResult) (nCVEs int, err error) {
	var ovalClient oval.Client
	var ovalFamily string

	switch r.Family {
	case c.Debian, c.Raspbian:
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
	case c.Amazon:
		ovalClient = oval.NewAmazon()
		ovalFamily = c.Amazon
	case c.FreeBSD, c.Windows:
		return 0, nil
	case c.ServerTypePseudo:
		return 0, nil
	default:
		if r.Family == "" {
			return 0, xerrors.New("Probably an error occurred during scanning. Check the error message")
		}
		return 0, xerrors.Errorf("OVAL for %s is not implemented yet", r.Family)
	}

	if !c.Conf.OvalDict.IsFetchViaHTTP() {
		if driver == nil {
			return 0, xerrors.Errorf("You have to fetch OVAL data for %s before reporting. For details, see `https://github.com/kotakanbe/goval-dictionary#usage`", r.Family)
		}
		if err = driver.NewOvalDB(ovalFamily); err != nil {
			return 0, xerrors.Errorf("Failed to New Oval DB. err: %w", err)
		}
	}

	util.Log.Debugf("Check whether oval fetched: %s %s", ovalFamily, r.Release)
	ok, err := ovalClient.CheckIfOvalFetched(driver, ovalFamily, r.Release)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, xerrors.Errorf("OVAL entries of %s %s are not found. Fetch OVAL before reporting. For details, see `https://github.com/kotakanbe/goval-dictionary#usage`", ovalFamily, r.Release)
	}

	_, err = ovalClient.CheckIfOvalFresh(driver, ovalFamily, r.Release)
	if err != nil {
		return 0, err
	}

	return ovalClient.FillWithOval(driver, r)
}

// DetectPkgsCvesWithGost fills CVEs with gost dataabase
// https://github.com/knqyf263/gost
func DetectPkgsCvesWithGost(driver gostdb.DB, r *models.ScanResult, ignoreWillNotFix bool) (nCVEs int, err error) {
	gostClient := gost.NewClient(r.Family)
	// TODO check if fetched
	// TODO check if fresh enough
	if nCVEs, err = gostClient.DetectUnfixed(driver, r, ignoreWillNotFix); err != nil {
		return
	}
	return nCVEs, gostClient.FillCVEsWithRedHat(driver, r)
}

// FillWithExploitDB fills Exploits with exploit dataabase
// https://github.com/mozqnet/go-exploitdb
func FillWithExploitDB(driver exploitdb.DB, r *models.ScanResult) (nExploitCve int, err error) {
	// TODO check if fetched
	// TODO check if fresh enough
	return exploit.FillWithExploit(driver, r)
}

// FillWithMetasploit fills metasploit modules with metasploit database
// https://github.com/takuzoo3868/go-msfdb
func FillWithMetasploit(driver metasploitdb.DB, r *models.ScanResult) (nMetasploitCve int, err error) {
	return msf.FillWithMetasploit(driver, r)
}

// DetectCpeURIsCves detects CVEs of given CPE-URIs
func DetectCpeURIsCves(driver cvedb.DB, r *models.ScanResult, cpeURIs []string) (nCVEs int, err error) {
	if len(cpeURIs) != 0 && driver == nil && !config.Conf.CveDict.IsFetchViaHTTP() {
		return 0, xerrors.Errorf("cpeURIs %s specified, but cve-dictionary DB not found. Fetch cve-dictionary before reporting. For details, see `https://github.com/kotakanbe/go-cve-dictionary#deploy-go-cve-dictionary`",
			cpeURIs)
	}

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

type integrationResults struct {
	GithubAlertsCveCounts int
	WordPressCveCounts    int
}

// Integration is integration of vuls report
type Integration interface {
	apply(*models.ScanResult, *integrationResults) error
}

// GithubSecurityAlerts :
func GithubSecurityAlerts(githubConfs map[string]config.GitHubConf) Integration {
	return GithubSecurityAlertOption{
		GithubConfs: githubConfs,
	}
}

// GithubSecurityAlertOption :
type GithubSecurityAlertOption struct {
	GithubConfs map[string]config.GitHubConf
}

// https://help.github.com/articles/about-security-alerts-for-vulnerable-dependencies/
func (g GithubSecurityAlertOption) apply(r *models.ScanResult, ints *integrationResults) (err error) {
	var nCVEs int
	for ownerRepo, setting := range g.GithubConfs {
		ss := strings.Split(ownerRepo, "/")
		owner, repo := ss[0], ss[1]
		n, err := github.FillGitHubSecurityAlerts(r, owner, repo, setting.Token)
		if err != nil {
			return xerrors.Errorf("Failed to access GitHub Security Alerts: %w", err)
		}
		nCVEs += n
	}
	ints.GithubAlertsCveCounts = nCVEs
	return nil
}

// WordPressOption :
type WordPressOption struct {
	token        string
	wpVulnCaches *map[string]string
}

func (g WordPressOption) apply(r *models.ScanResult, ints *integrationResults) (err error) {
	if g.token == "" {
		return nil
	}
	n, err := wordpress.FillWordPress(r, g.token, g.wpVulnCaches)
	if err != nil {
		return xerrors.Errorf("Failed to fetch from WPVulnDB. Check the WPVulnDBToken in config.toml. err: %w", err)
	}
	ints.WordPressCveCounts = n
	return nil
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

	dict := map[string]models.CweDictEntry{}
	for id := range uniqCweIDMap {
		entry := models.CweDictEntry{}
		if e, ok := cwe.CweDictEn[id]; ok {
			if rank, ok := cwe.OwaspTopTen2017[id]; ok {
				entry.OwaspTopTen2017 = rank
			}
			if rank, ok := cwe.CweTopTwentyfive2019[id]; ok {
				entry.CweTopTwentyfive2019 = rank
			}
			if rank, ok := cwe.SansTopTwentyfive[id]; ok {
				entry.SansTopTwentyfive = rank
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
				if rank, ok := cwe.CweTopTwentyfive2019[id]; ok {
					entry.CweTopTwentyfive2019 = rank
				}
				if rank, ok := cwe.SansTopTwentyfive[id]; ok {
					entry.SansTopTwentyfive = rank
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
