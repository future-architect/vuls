//go:build !scanner

package detector

import (
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
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

		if err := DetectLibsCves(&r, config.Conf.TrivyOpts, config.Conf.LogOpts, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to fill with Library dependency: %w", err)
		}

		// One vuls2 db session for this server's package/CPE detection and the
		// enrichment that follows: detection warms the read cache and
		// enrichment, querying the same CVEs, reuses it instead of opening and
		// rebuilding a fresh cache. The session opens lazily on the first path
		// that queries the db (as the unshared code did), and is closed at the
		// end of this server's turn so each server holds the db only while it
		// needs it.
		if err := func() error {
			sesh := vuls2.NewSession(config.Conf.Vuls2, config.Conf.NoProgress)
			defer sesh.Close()

			if err := DetectPkgCves(&r, sesh); err != nil {
				return xerrors.Errorf("Failed to detect Pkg CVE: %w", err)
			}

			// Collect the user-supplied CPE URIs to check. Sources, in order:
			//   1. r.Config.Scan.Servers[...].CpeNames — the per-server CPE list
			//      that was captured at scan time and shipped in the result JSON.
			//      Using the scan-time snapshot keeps detection coupled to the
			//      server that was actually scanned, and lets detection run
			//      without re-loading config.toml.
			//   2. OWASP DC XML, if configured.
			//
			// Synthesised Apple CPEs for macOS scans are detected separately in
			// DetectPkgCves (macOS has no package security database).
			// Prefer the scan-time snapshot; results produced by an older Vuls
			// (or an external producer) may not embed config.scan.servers, so
			// fall back to the report-time config.Conf.Servers in that case to
			// keep CPE detection working for such inputs.
			serverInfo, serverFound := r.Config.Scan.Servers[r.ServerName]
			if !serverFound {
				serverInfo, serverFound = config.Conf.Servers[r.ServerName]
			}
			cpeURIs, owaspDCXMLPath := []string{}, ""
			cpes := []vuls2.CPE{}
			if serverFound {
				if len(r.Container.ContainerID) == 0 {
					cpeURIs = serverInfo.CpeNames
					owaspDCXMLPath = serverInfo.OwaspDCXMLPath
				} else {
					if con, ok := serverInfo.Containers[r.Container.Name]; ok {
						cpeURIs = con.Cpes
						owaspDCXMLPath = con.OwaspDCXMLPath
					}
				}
			}
			if owaspDCXMLPath != "" {
				owaspCPEs, err := parser.Parse(owaspDCXMLPath)
				if err != nil {
					return xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
						r.ServerInfo(), owaspDCXMLPath, err)
				}
				cpeURIs = append(cpeURIs, owaspCPEs...)
			}
			for _, uri := range cpeURIs {
				cpes = append(cpes, vuls2.CPE{
					URI:    uri,
					UseJVN: true,
				})
			}

			if err := DetectCpeURIsCves(&r, cpes, sesh); err != nil {
				return xerrors.Errorf("Failed to detect CVE of `%s`: %w", cpeURIs, err)
			}

			if err := DetectWordPressCves(&r, config.Conf.WpScan); err != nil {
				return xerrors.Errorf("Failed to detect WordPress Cves: %w", err)
			}

			if err := vuls2.EnrichVulnInfos(&r, sesh); err != nil {
				return xerrors.Errorf("Failed to enrich vulnerability data with vuls2: %w", err)
			}

			return nil
		}(); err != nil {
			return nil, xerrors.Errorf("Failed to detect CVEs of %s. err: %w", r.FormatServerName(), err)
		}

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
			return nil, xerrors.Errorf("Failed to load previous results. err: %w", err)
		}
		rs = diff(rs, prevs, config.Conf.DiffPlus, config.Conf.DiffMinus)
	}

	for i, r := range rs {
		nFiltered := 0
		logging.Log.Infof("%s: total %d CVEs detected", r.FormatServerName(), len(r.ScannedCves))

		if 0 < config.Conf.CvssScoreOver {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterByCvssOver(config.Conf.CvssScoreOver)
			logging.Log.Infof("%s: %d CVEs filtered by --cvss-over=%g", r.FormatServerName(), nFiltered, config.Conf.CvssScoreOver)
		}

		if config.Conf.IgnoreUnfixed {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterUnfixed(config.Conf.IgnoreUnfixed)
			logging.Log.Infof("%s: %d CVEs filtered by --ignore-unfixed", r.FormatServerName(), nFiltered)
		}

		if 0 < config.Conf.ConfidenceScoreOver {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterByConfidenceOver(config.Conf.ConfidenceScoreOver)
			logging.Log.Infof("%s: %d CVEs filtered by --confidence-over=%d", r.FormatServerName(), nFiltered, config.Conf.ConfidenceScoreOver)
		}

		// IgnoreCves
		ignoreCves := []string{}
		if r.Container.Name == "" {
			ignoreCves = config.Conf.Servers[r.ServerName].IgnoreCves
		} else if con, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignoreCves = con.IgnoreCves
		}
		if 0 < len(ignoreCves) {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterIgnoreCves(ignoreCves)
			logging.Log.Infof("%s: %d CVEs filtered by ignoreCves=%s", r.FormatServerName(), nFiltered, ignoreCves)
		}

		// ignorePkgs
		ignorePkgsRegexps := []string{}
		if r.Container.Name == "" {
			ignorePkgsRegexps = config.Conf.Servers[r.ServerName].IgnorePkgsRegexp
		} else if s, ok := config.Conf.Servers[r.ServerName].Containers[r.Container.Name]; ok {
			ignorePkgsRegexps = s.IgnorePkgsRegexp
		}
		if 0 < len(ignorePkgsRegexps) {
			r.ScannedCves, nFiltered = r.ScannedCves.FilterIgnorePkgs(ignorePkgsRegexps)
			logging.Log.Infof("%s: %d CVEs filtered by ignorePkgsRegexp=%s", r.FormatServerName(), nFiltered, ignorePkgsRegexps)
		}

		// IgnoreUnscored
		if config.Conf.IgnoreUnscoredCves {
			r.ScannedCves, nFiltered = r.ScannedCves.FindScoredVulns()
			logging.Log.Infof("%s: %d CVEs filtered by --ignore-unscored-cves", r.FormatServerName(), nFiltered)
		}

		r.FilterInactiveWordPressLibs(config.Conf.WpScan.DetectInactive)
		rs[i] = r
	}
	return rs, nil
}

// DetectPkgCves detects OS-package / Microsoft-KB CVEs via the vuls2
// library (family-gated), and applies the FixState / ListenPortStats
// post-processing. macOS has no package security database, so its installed
// applications and OS are translated to Apple CPEs (vuls2.MacOSCPEs) and
// detected through the CPE path here. Its name and its place in the call
// order are kept from the master era: it runs first and DetectCpeURIsCves
// second, so OS-package / KB detection happens here while user-supplied
// CPE-URI detection is DetectCpeURIsCves' job.
//
// sesh is the vuls2 db session to query (see vuls2.Session), created with
// vuls2.NewSession and owned (Closed) by the caller; it is shared with this
// server's CPE detection and enrichment so all three reuse one warm db
// connection.
func DetectPkgCves(r *models.ScanResult, sesh *vuls2.Session) error {
	switch r.Family {
	case constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer:
		// macOS has no package security database; the OS itself (when its release
		// is known) and installed applications are detected through synthesised
		// Apple CPEs. Applications bind to the OS target, not its version, so they
		// stay detectable without the release; only an empty result — no release
		// AND no detectable applications — is an incomplete scan, recorded rather
		// than silently reporting zero CVEs (as for the recognized families below).
		switch cpes := vuls2.MacOSCPEs(r); len(cpes) {
		case 0:
			r.Errors = append(r.Errors, xerrors.Errorf("Failed to detect CVE for %s: no OS release and no detectable applications", r.Family).Error())
		default:
			if err := vuls2.DetectCPEs(r, cpes, sesh); err != nil {
				return xerrors.Errorf("Failed to detect CVE with Vuls2: %w", err)
			}
		}
	case constant.FreeBSD, constant.ServerTypePseudo:
		logging.Log.Infof("%s type. Skip vuls2 detection", r.Family)
	case constant.Windows:
		if err := vuls2.DetectPkgs(r, sesh); err != nil {
			return xerrors.Errorf("Failed to detect CVE with Vuls2: %w", err)
		}
	case constant.RedHat, constant.CentOS, constant.Fedora, constant.Alma, constant.Rocky, constant.Oracle, constant.Amazon,
		constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop,
		constant.Debian, constant.Raspbian, constant.Ubuntu, constant.Alpine:
		switch {
		case r.ScannedVia == "trivy":
			// trivy runs its own detection; vuls2 OS-package detection is skipped.
			logging.Log.Infof("r.ScannedVia is trivy. Skip vuls2 detection")
		case r.Release == "":
			// A recognized OS family with no release or no packages is an
			// incomplete scan result: record the failure (rather than silently
			// reporting zero package CVEs) but keep going, so this server's other
			// detection (CPE, WordPress, ...) and the other servers still run.
			r.Errors = append(r.Errors, xerrors.Errorf("Failed to detect CVE for %s: r.Release is empty", r.Family).Error())
		case len(r.Packages)+len(r.SrcPackages) == 0:
			r.Errors = append(r.Errors, xerrors.Errorf("Failed to detect CVE for %s: no binary or source packages", r.Family).Error())
		default:
			if err := vuls2.DetectPkgs(r, sesh); err != nil {
				return xerrors.Errorf("Failed to detect CVE with Vuls2: %w", err)
			}
		}
	default:
		// An unknown family is an error only when it actually carries scan
		// data we could not detect; data-less or trivy results are skipped.
		switch {
		case r.ScannedVia == "trivy":
			logging.Log.Infof("r.ScannedVia is trivy. Skip vuls2 detection")
		case r.Release == "":
			logging.Log.Infof("r.Release is empty. Skip vuls2 detection")
		case len(r.Packages)+len(r.SrcPackages) == 0:
			logging.Log.Infof("Number of packages is 0. Skip vuls2 detection")
		default:
			return xerrors.Errorf("Unsupported detection methods for %s", r.Family)
		}
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

// DetectCpeURIsCves detects CVEs of given CPE-URIs — the complete CPE
// detection pipeline. Its name and its place in the call order are kept from
// the master era: it runs after DetectPkgCves (which handles OS-package / KB
// detection).
//
// All CPE detection sources (NVD with cpematch-expanded criteria, VulnCheck
// NVD++, JVN, Fortinet, Cisco and PaloAlto) are detected by vuls2.
//
// sesh is the vuls2 db session to query (see vuls2.Session), created with
// vuls2.NewSession and owned (Closed) by the caller.
func DetectCpeURIsCves(r *models.ScanResult, cpes []vuls2.CPE, sesh *vuls2.Session) error {
	// A caller-provided result may carry a nil ScannedCves map (e.g. a
	// zero-value ScanResult from a library consumer); initialize before the
	// detection paths write into it.
	if r.ScannedCves == nil {
		r.ScannedCves = models.VulnInfos{}
	}

	if err := vuls2.DetectCPEs(r, cpes, sesh); err != nil {
		return xerrors.Errorf("Failed to detect CVEs with vuls2. err: %w", err)
	}

	return nil
}
