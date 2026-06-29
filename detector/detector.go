//go:build !scanner

package detector

import (
	"fmt"
	"os"
	"slices"
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

// Cpe :
type Cpe struct {
	CpeURI string
	UseJVN bool
}

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

		if err := DetectPkgCves(&r, config.Conf.Vuls2, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to detect Pkg CVE: %w", err)
		}

		// Collect the CPE URIs to check. Sources, in order:
		//   1. r.Config.Scan.Servers[...].CpeNames — the per-server CPE list
		//      that was captured at scan time and shipped in the result JSON.
		//      Using the scan-time snapshot keeps detection coupled to the
		//      server that was actually scanned, and lets detection run
		//      without re-loading config.toml.
		//   2. OWASP DC XML, if configured.
		//   3. Synthesised Apple CPEs for macOS scans.
		//
		// User-supplied / OWASP CPEs consult JVN, synthesised Apple CPEs
		// do not.
		// Prefer the scan-time snapshot; results produced by an older Vuls
		// (or an external producer) may not embed config.scan.servers, so
		// fall back to the report-time config.Conf.Servers in that case to
		// keep CPE detection working for such inputs.
		serverInfo, serverFound := r.Config.Scan.Servers[r.ServerName]
		if !serverFound {
			serverInfo, serverFound = config.Conf.Servers[r.ServerName]
		}
		cpeURIs, owaspDCXMLPath := []string{}, ""
		cpes := []Cpe{}
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
			cpes, err := parser.Parse(owaspDCXMLPath)
			if err != nil {
				return nil, xerrors.Errorf("Failed to read OWASP Dependency Check XML on %s, `%s`, err: %w",
					r.ServerInfo(), owaspDCXMLPath, err)
			}
			cpeURIs = append(cpeURIs, cpes...)
		}
		for _, uri := range cpeURIs {
			cpes = append(cpes, Cpe{
				CpeURI: uri,
				UseJVN: true,
			})
		}

		if slices.Contains([]string{constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer}, r.Family) {
			var targets []string
			if r.Release != "" {
				switch r.Family {
				case constant.MacOSX:
					targets = append(targets, "mac_os_x")
				case constant.MacOSXServer:
					targets = append(targets, "mac_os_x_server")
				case constant.MacOS:
					targets = append(targets, "macos", "mac_os")
				case constant.MacOSServer:
					targets = append(targets, "macos_server", "mac_os_server")
				}
				for _, t := range targets {
					cpes = append(cpes, Cpe{
						CpeURI: fmt.Sprintf("cpe:/o:apple:%s:%s", t, r.Release),
						UseJVN: false,
					})
				}
			}
			for _, p := range r.Packages {
				if p.Version == "" {
					continue
				}
				switch p.Repository {
				case "com.apple.Safari":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:safari:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.Music":
					for _, t := range targets {
						cpes = append(cpes,
							Cpe{
								CpeURI: fmt.Sprintf("cpe:/a:apple:music:%s::~~~%s~~", p.Version, t),
								UseJVN: false,
							},
							Cpe{
								CpeURI: fmt.Sprintf("cpe:/a:apple:apple_music:%s::~~~%s~~", p.Version, t),
								UseJVN: false,
							},
						)
					}
				case "com.apple.mail":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:mail:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.Terminal":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:terminal:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.shortcuts":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:shortcuts:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iCal":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:ical:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Keynote":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:keynote:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Numbers":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:numbers:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.iWork.Pages":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:pages:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				case "com.apple.dt.Xcode":
					for _, t := range targets {
						cpes = append(cpes, Cpe{
							CpeURI: fmt.Sprintf("cpe:/a:apple:xcode:%s::~~~%s~~", p.Version, t),
							UseJVN: false,
						})
					}
				}
			}
		}

		if err := DetectCpeURIsCves(&r, cpes, config.Conf.Vuls2, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to detect CVE of `%s`: %w", cpeURIs, err)
		}

		if err := DetectWordPressCves(&r, config.Conf.WpScan); err != nil {
			return nil, xerrors.Errorf("Failed to detect WordPress Cves: %w", err)
		}

		if err := vuls2.EnrichVulnInfos(&r, config.Conf.Vuls2, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to enrich vulnerability data with vuls2: %w", err)
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
// library (family-gated) and applies the FixState / ListenPortStats
// post-processing. It keeps the master-era name, signature and calling
// convention so library consumers that drive detection as
// DetectPkgCves -> DetectCpeURIsCves keep working; CPE-URI detection
// lives in DetectCpeURIsCves.
func DetectPkgCves(r *models.ScanResult, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	if isPkgCvesDetactable(r) {
		switch r.Family {
		case constant.RedHat, constant.CentOS, constant.Fedora, constant.Alma, constant.Rocky, constant.Oracle, constant.Amazon,
			constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop,
			constant.Debian, constant.Raspbian, constant.Ubuntu, constant.Alpine,
			constant.Windows:
			if err := vuls2.DetectPkgs(r, vuls2Conf, noProgress); err != nil {
				return xerrors.Errorf("Failed to detect CVE with Vuls2: %w", err)
			}
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

// isPkgCvesDetactable checks whether CVEs is detactable with vuls2 from the result
func isPkgCvesDetactable(r *models.ScanResult) bool {
	switch r.Family {
	case constant.FreeBSD, constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer, constant.ServerTypePseudo:
		logging.Log.Infof("%s type. Skip vuls2 detection", r.Family)
		return false
	case constant.Windows:
		return true
	default:
		if r.ScannedVia == "trivy" {
			logging.Log.Infof("r.ScannedVia is trivy. Skip vuls2 detection")
			return false
		}

		if r.Release == "" {
			logging.Log.Infof("r.Release is empty. Skip vuls2 detection")
			return false
		}

		if len(r.Packages)+len(r.SrcPackages) == 0 {
			logging.Log.Infof("Number of packages is 0. Skip vuls2 detection")
			return false
		}
		return true
	}
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
// detection pipeline, keeping the master-era name and calling convention so
// library consumers that drive detection as DetectPkgCves ->
// DetectCpeURIsCves keep working.
//
// All CPE detection sources (NVD with cpematch-expanded criteria, VulnCheck
// NVD++, JVN, Fortinet, Cisco and PaloAlto) are detected by vuls2.
func DetectCpeURIsCves(r *models.ScanResult, cpes []Cpe, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	// A caller-provided result may carry a nil ScannedCves map (e.g. a
	// zero-value ScanResult from a library consumer); initialize before the
	// detection paths write into it.
	if r.ScannedCves == nil {
		r.ScannedCves = models.VulnInfos{}
	}

	if len(cpes) == 0 {
		return nil
	}

	cpeURIs := make([]string, 0, len(cpes))
	for _, c := range cpes {
		cpeURIs = append(cpeURIs, c.CpeURI)
	}
	if err := vuls2.DetectCPEs(r, cpeURIs, vuls2Conf, noProgress); err != nil {
		return xerrors.Errorf("Failed to detect CVEs with vuls2. err: %w", err)
	}

	return nil
}
