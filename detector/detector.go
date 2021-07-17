// +build !scanner

package detector

import (
	"os"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/util"
	cvemodels "github.com/kotakanbe/go-cve-dictionary/models"
	"golang.org/x/xerrors"
)

// Detect vulns and fill CVE detailed information
func Detect(rs []models.ScanResult, dir string) ([]models.ScanResult, error) {

	// Use the same reportedAt for all rs
	reportedAt := time.Now()
	for i, r := range rs {
		if !config.Conf.RefreshCve && !needToRefreshCve(r) {
			logging.Log.Info("No need to refresh")
			continue
		}

		if !reuseScannedCves(&r) {
			r.ScannedCves = models.VulnInfos{}
		}

		cpeURIs, owaspDCXMLPath := []string{}, ""
		if len(r.Container.ContainerID) == 0 {
			cpeURIs = config.Conf.Servers[r.ServerName].CpeNames
			owaspDCXMLPath = config.Conf.Servers[r.ServerName].OwaspDCXMLPath
		} else {
			if s, ok := config.Conf.Servers[r.ServerName]; ok {
				if con, ok := s.Containers[r.Container.Name]; ok {
					cpeURIs = con.Cpes
					owaspDCXMLPath = con.OwaspDCXMLPath
				}
			}
		}
		if owaspDCXMLPath != "" {
			cpes, err := parser.Parse(owaspDCXMLPath)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
					r.ServerInfo(), owaspDCXMLPath, err)
			}
			cpeURIs = append(cpeURIs, cpes...)
		}

		if err := DetectLibsCves(&r, config.Conf.TrivyCacheDBDir, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to fill with Library dependency: %w", err)
		}

		if err := DetectPkgCves(&r, config.Conf.OvalDict, config.Conf.Gost); err != nil {
			return nil, xerrors.Errorf("Failed to detect Pkg CVE: %w", err)
		}

		if err := DetectCpeURIsCves(&r, cpeURIs, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to detect CVE of `%s`: %w", cpeURIs, err)
		}

		repos := config.Conf.Servers[r.ServerName].GitHubRepos
		if err := DetectGitHubCves(&r, repos); err != nil {
			return nil, xerrors.Errorf("Failed to detect GitHub Cves: %w", err)
		}

		if err := DetectWordPressCves(&r, config.Conf.WpScan); err != nil {
			return nil, xerrors.Errorf("Failed to detect WordPress Cves: %w", err)
		}

		if err := gost.FillCVEsWithRedHat(&r, config.Conf.Gost); err != nil {
			return nil, xerrors.Errorf("Failed to fill with gost: %w", err)
		}

		if err := FillCvesWithNvdJvn(&r, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with CVE: %w", err)
		}

		nExploitCve, err := FillWithExploit(&r, config.Conf.Exploit)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fill with exploit: %w", err)
		}
		logging.Log.Infof("%s: %d PoC are detected", r.FormatServerName(), nExploitCve)

		nMetasploitCve, err := FillWithMetasploit(&r, config.Conf.Metasploit)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fill with metasploit: %w", err)
		}
		logging.Log.Infof("%s: %d exploits are detected", r.FormatServerName(), nMetasploitCve)

		FillCweDict(&r)

		r.ReportedBy, _ = os.Hostname()
		r.Lang = config.Conf.Lang
		r.ReportedAt = reportedAt
		r.ReportedVersion = config.Version
		r.ReportedRevision = config.Revision
		r.Config.Report = config.Conf
		r.Config.Report.Servers = map[string]config.ServerInfo{
			r.ServerName: config.Conf.Servers[r.ServerName],
		}
		rs[i] = r
	}

	// Overwrite the json file every time to clear the fields specified in config.IgnoredJSONKeys
	for _, r := range rs {
		if s, ok := config.Conf.Servers[r.ServerName]; ok {
			r = r.ClearFields(s.IgnoredJSONKeys)
		}
		//TODO don't call here
		if err := reporter.OverwriteJSONFile(dir, r); err != nil {
			return nil, xerrors.Errorf("Failed to write JSON: %w", err)
		}
	}

	if config.Conf.DiffPlus || config.Conf.DiffMinus {
		prevs, err := loadPrevious(rs, config.Conf.ResultsDir)
		if err != nil {
			return nil, err
		}
		rs = diff(rs, prevs, config.Conf.DiffPlus, config.Conf.DiffMinus)
	}

	for i, r := range rs {
		r.ScannedCves = r.ScannedCves.FilterByCvssOver(config.Conf.CvssScoreOver)
		r.ScannedCves = r.ScannedCves.FilterUnfixed(config.Conf.IgnoreUnfixed)

		// IgnoreCves
		ignoreCves := []string{}
		if r.Container.Name == "" {
			ignoreCves = config.Conf.Servers[r.ServerName].IgnoreCves
		} else if con, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignoreCves = con.IgnoreCves
		}
		r.ScannedCves = r.ScannedCves.FilterIgnoreCves(ignoreCves)

		// ignorePkgs
		ignorePkgsRegexps := []string{}
		if r.Container.Name == "" {
			ignorePkgsRegexps = config.Conf.Servers[r.ServerName].IgnorePkgsRegexp
		} else if s, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignorePkgsRegexps = s.IgnorePkgsRegexp
		}
		r.ScannedCves = r.ScannedCves.FilterIgnorePkgs(ignorePkgsRegexps)

		// IgnoreUnscored
		if config.Conf.IgnoreUnscoredCves {
			r.ScannedCves = r.ScannedCves.FindScoredVulns()
		}

		r.FilterInactiveWordPressLibs(config.Conf.WpScan.DetectInactive)
		rs[i] = r
	}
	return rs, nil
}

// DetectPkgCves detects OS pkg cves
// pass 2 configs
func DetectPkgCves(r *models.ScanResult, ovalCnf config.GovalDictConf, gostCnf config.GostConf) error {
	// Pkg Scan
	if r.Release != "" {
		// OVAL, gost(Debian Security Tracker) does not support Package for Raspbian, so skip it.
		if r.Family == constant.Raspbian {
			r = r.RemoveRaspbianPackFromResult()
		}

		// OVAL
		if err := detectPkgsCvesWithOval(ovalCnf, r); err != nil {
			return xerrors.Errorf("Failed to detect CVE with OVAL: %w", err)
		}

		// gost
		if err := detectPkgsCvesWithGost(gostCnf, r); err != nil {
			return xerrors.Errorf("Failed to detect CVE with gost: %w", err)
		}
	} else if reuseScannedCves(r) {
		logging.Log.Infof("r.Release is empty. Use CVEs as it as.")
	} else if r.Family == constant.ServerTypePseudo {
		logging.Log.Infof("pseudo type. Skip OVAL and gost detection")
	} else {
		return xerrors.Errorf("Failed to fill CVEs. r.Release is empty")
	}

	for i, v := range r.ScannedCves {
		for j, p := range v.AffectedPackages {
			if p.NotFixedYet && p.FixState == "" {
				p.FixState = "Not fixed yet"
				r.ScannedCves[i].AffectedPackages[j] = p
			}
		}
	}

	// To keep backward compatibility
	// Newer versions use ListenPortStats,
	// but older versions of Vuls are set to ListenPorts.
	// Set ListenPorts to ListenPortStats to allow newer Vuls to report old results.
	for i, pkg := range r.Packages {
		for j, proc := range pkg.AffectedProcs {
			for _, ipPort := range proc.ListenPorts {
				ps, err := models.NewPortStat(ipPort)
				if err != nil {
					logging.Log.Warnf("Failed to parse ip:port: %s, err:%+v", ipPort, err)
					continue
				}
				r.Packages[i].AffectedProcs[j].ListenPortStats = append(
					r.Packages[i].AffectedProcs[j].ListenPortStats, *ps)
			}
		}
	}

	return nil
}

// DetectGitHubCves fetches CVEs from GitHub Security Alerts
func DetectGitHubCves(r *models.ScanResult, githubConfs map[string]config.GitHubConf) error {
	if len(githubConfs) == 0 {
		return nil
	}
	for ownerRepo, setting := range githubConfs {
		ss := strings.Split(ownerRepo, "/")
		if len(ss) != 2 {
			return xerrors.Errorf("Failed to parse GitHub owner/repo: %s", ownerRepo)
		}
		owner, repo := ss[0], ss[1]
		n, err := DetectGitHubSecurityAlerts(r, owner, repo, setting.Token, setting.IgnoreGitHubDismissed)
		if err != nil {
			return xerrors.Errorf("Failed to access GitHub Security Alerts: %w", err)
		}
		logging.Log.Infof("%s: %d CVEs detected with GHSA %s/%s",
			r.FormatServerName(), n, owner, repo)
	}
	return nil
}

// DetectWordPressCves detects CVEs of WordPress
func DetectWordPressCves(r *models.ScanResult, wpCnf config.WpScanConf) error {
	if len(r.WordPressPackages) == 0 {
		return nil
	}
	logging.Log.Infof("%s: Detect WordPress CVE. Number of pkgs: %d ", r.ServerInfo(), len(r.WordPressPackages))
	n, err := detectWordPressCves(r, wpCnf)
	if err != nil {
		return xerrors.Errorf("Failed to detect WordPress CVE: %w", err)
	}
	logging.Log.Infof("%s: found %d WordPress CVEs", r.FormatServerName(), n)
	return nil
}

// FillCvesWithNvdJvn fills CVE detail with NVD, JVN
func FillCvesWithNvdJvn(r *models.ScanResult, cnf config.GoCveDictConf, logOpts logging.LogOpts) (err error) {
	cveIDs := []string{}
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	var ds []cvemodels.CveDetail
	if cnf.IsFetchViaHTTP() {
		ds, err = client.fetchCveDetailsViaHTTP(cveIDs)
	} else {
		ds, err = client.fetchCveDetails(cveIDs)
	}
	if err != nil {
		return err
	}

	for _, d := range ds {
		nvd, exploits, mitigations := models.ConvertNvdJSONToModel(d.CveID, d.NvdJSON)
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
				vinfo.Exploits = append(vinfo.Exploits, exploits...)
				vinfo.Mitigations = append(vinfo.Mitigations, mitigations...)
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

// detectPkgsCvesWithOval fetches OVAL database
func detectPkgsCvesWithOval(cnf config.GovalDictConf, r *models.ScanResult) error {
	ovalClient, err := oval.NewOVALClient(r.Family, cnf)
	if err != nil {
		return err
	}
	if ovalClient == nil {
		return nil
	}

	logging.Log.Debugf("Check if oval fetched: %s %s", r.Family, r.Release)
	ok, err := ovalClient.CheckIfOvalFetched(r.Family, r.Release)
	if err != nil {
		return err
	}
	if !ok {
		if r.Family == constant.Debian {
			logging.Log.Debug("Skip OVAL and Scan with gost alone.")
			logging.Log.Infof("%s: %d CVEs are detected with OVAL", r.FormatServerName(), 0)
			return nil
		}
		return xerrors.Errorf("OVAL entries of %s %s are not found. Fetch OVAL before reporting. For details, see `https://github.com/kotakanbe/goval-dictionary#usage`", r.Family, r.Release)
	}

	logging.Log.Debugf("Check if oval fresh: %s %s", r.Family, r.Release)
	_, err = ovalClient.CheckIfOvalFresh(r.Family, r.Release)
	if err != nil {
		return err
	}

	logging.Log.Debugf("Fill with oval: %s %s", r.Family, r.Release)
	nCVEs, err := ovalClient.FillWithOval(r)
	if err != nil {
		return err
	}

	logging.Log.Infof("%s: %d CVEs are detected with OVAL", r.FormatServerName(), nCVEs)
	return nil
}

func detectPkgsCvesWithGost(cnf config.GostConf, r *models.ScanResult) error {
	client, err := gost.NewClient(cnf, r.Family)
	if err != nil {
		return xerrors.Errorf("Failed to new a gost client: %w", err)
	}

	defer func() {
		if err := client.CloseDB(); err != nil {
			logging.Log.Errorf("Failed to close the gost DB. err: %+v", err)
		}
	}()

	nCVEs, err := client.DetectCVEs(r, true)
	if err != nil {
		if r.Family == constant.Debian {
			return xerrors.Errorf("Failed to detect CVEs with gost: %w", err)
		}
		return xerrors.Errorf("Failed to detect unfixed CVEs with gost: %w", err)
	}

	if r.Family == constant.Debian {
		logging.Log.Infof("%s: %d CVEs are detected with gost",
			r.FormatServerName(), nCVEs)
	} else {
		logging.Log.Infof("%s: %d unfixed CVEs are detected with gost",
			r.FormatServerName(), nCVEs)
	}
	return nil
}

// DetectCpeURIsCves detects CVEs of given CPE-URIs
func DetectCpeURIsCves(r *models.ScanResult, cpeURIs []string, cnf config.GoCveDictConf, logOpts logging.LogOpts) error {
	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	nCVEs := 0
	for _, name := range cpeURIs {
		details, err := client.fetchCveDetailsByCpeName(name)
		if err != nil {
			return err
		}

		for _, detail := range details {
			confidence := models.CpeVersionMatch
			if detail.HasJvn() && !detail.HasNvd() {
				// In the case of CpeVendorProduct-match, only the JVN is set(Nvd is not set).
				confidence = models.CpeVendorProductMatch
			}

			if val, ok := r.ScannedCves[detail.CveID]; ok {
				val.CpeURIs = util.AppendIfMissing(val.CpeURIs, name)
				val.Confidences.AppendIfMissing(confidence)
				r.ScannedCves[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:       detail.CveID,
					CpeURIs:     []string{name},
					Confidences: models.Confidences{confidence},
				}
				r.ScannedCves[detail.CveID] = v
				nCVEs++
			}
		}
	}
	logging.Log.Infof("%s: %d CVEs are detected with CPE", r.FormatServerName(), nCVEs)
	return nil
}

// FillCweDict fills CWE
func FillCweDict(r *models.ScanResult) {
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
			logging.Log.Debugf("CWE-ID %s is not found in English CWE Dict", id)
			entry.En = &cwe.Cwe{CweID: id}
		}

		if r.Lang == "ja" {
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
				logging.Log.Debugf("CWE-ID %s is not found in Japanese CWE Dict", id)
				entry.Ja = &cwe.Cwe{CweID: id}
			}
		}
		dict[id] = entry
	}
	r.CweDict = dict
	return
}
