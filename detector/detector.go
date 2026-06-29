//go:build !scanner

package detector

import (
	"cmp"
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
	"github.com/future-architect/vuls/util"
	cvemodels "github.com/vulsio/go-cve-dictionary/models"
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

		if err := DetectCpeURIsCves(&r, cpes, config.Conf.CveDict, config.Conf.LogOpts, config.Conf.Vuls2, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to detect CVE of `%s`: %w", cpeURIs, err)
		}

		if err := DetectWordPressCves(&r, config.Conf.WpScan); err != nil {
			return nil, xerrors.Errorf("Failed to detect WordPress Cves: %w", err)
		}

		if err := vuls2.EnrichVulnInfos(&r, config.Conf.Vuls2, config.Conf.NoProgress); err != nil {
			return nil, xerrors.Errorf("Failed to enrich vulnerability data with vuls2: %w", err)
		}

		if err := FillCvesWithGoCVEDictionary(&r, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
			return nil, xerrors.Errorf("Failed to fill with CVE: %w", err)
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

// FillCvesWithGoCVEDictionary fills CVE detail with VulnCheck, JVN, Fortinet
// (NVD CveContent, EUVD, and MITRE are filled by the vuls2 enrich path instead, as are the US-CERT
// alerts; Cisco and Palo Alto are detected by vuls2, which emits their DistroAdvisory and CveContent;
// only the JP-CERT alerts, derived from JVN, still come from here)
func FillCvesWithGoCVEDictionary(r *models.ScanResult, cnf config.GoCveDictConf, logOpts logging.LogOpts) (err error) {
	cveIDs := make([]string, 0, len(r.ScannedCves))
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to newGoCveDictClient. err: %w", err)
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	ds, err := client.fetchCveDetails(cveIDs)
	if err != nil {
		return xerrors.Errorf("Failed to fetchCveDetails. err: %w", err)
	}

	for _, d := range ds {
		vulnchecks := models.ConvertVulncheckToModel(d.CveID, d.Vulnchecks)
		jvns := models.ConvertJvnToModel(d.CveID, d.Jvns)
		fortinets := models.ConvertFortinetToModel(d.CveID, d.Fortinets)

		alerts := fillCertAlerts(&d)
		for cveID, vinfo := range r.ScannedCves {
			if vinfo.CveID == d.CveID {
				if vinfo.CveContents == nil {
					vinfo.CveContents = models.CveContents{}
				}
				// NVD CveContent (and its exploits/mitigations and US-CERT
				// alerts) is now provided by the vuls2 detection/enrich path
				// (see vuls2.enrichNVD), so go-cve-dictionary no longer fills it
				// here. JP-CERT alerts stay here — they come from JVN, which is
				// not migrated.
				for _, con := range vulnchecks {
					vinfo.CveContents[con.Type] = append(vinfo.CveContents[con.Type], con)
				}
				for _, cons := range [][]models.CveContent{jvns, fortinets} {
					for _, con := range cons {
						if !con.Empty() {
							if !slices.ContainsFunc(vinfo.CveContents[con.Type], func(e models.CveContent) bool {
								return con.SourceLink == e.SourceLink
							}) {
								vinfo.CveContents[con.Type] = append(vinfo.CveContents[con.Type], con)
							}
						}
					}
				}
				// Set only JP-CERT; US-CERT is filled by the vuls2 enrich path
				// (vuls2.EnrichVulnInfos runs before this) and must be preserved.
				vinfo.AlertDict.JPCERT = alerts.JPCERT
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

// fillCertAlerts derives JP-CERT alerts from go-cve-dictionary's JVN data.
// US-CERT alerts are derived from NVD references by the vuls2 enrich path
// (see vuls2.enrichNVD); JVN is not migrated, so JP-CERT stays here.
func fillCertAlerts(cvedetail *cvemodels.CveDetail) (dict models.AlertDict) {
	for _, jvn := range cvedetail.Jvns {
		for _, cert := range jvn.Certs {
			dict.JPCERT = append(dict.JPCERT, models.Alert{
				URL:   cert.Link,
				Title: cert.Title,
				Team:  "jpcert",
			})
		}
	}

	return dict
}

// DetectCpeURIsCves detects CVEs of given CPE-URIs — the complete CPE
// detection pipeline, keeping the master-era name and calling convention so
// library consumers that drive detection as DetectPkgCves ->
// DetectCpeURIsCves keep working.
//
// Sources already migrated to the vuls2 DB (currently NVD, with
// cpematch-expanded criteria) are detected by vuls2. The remaining sources
// come from go-cve-dictionary, where the migrated sources' contribution is
// excluded — dropped just before confidence selection, with detections
// carried by migrated sources alone skipped entirely — to avoid
// double-reporting the same source with diverging match semantics.
func DetectCpeURIsCves(r *models.ScanResult, cpes []Cpe, cnf config.GoCveDictConf, logOpts logging.LogOpts, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	// A caller-provided result may carry a nil ScannedCves map (e.g. a
	// zero-value ScanResult from a library consumer); initialize before the
	// detection paths write into it.
	if r.ScannedCves == nil {
		r.ScannedCves = models.VulnInfos{}
	}

	if len(cpes) == 0 {
		return nil
	}

	if err := detectCpeURIsCvesWithGoCVEDictionary(r, cpes, cnf, logOpts); err != nil {
		return xerrors.Errorf("Failed to detect CVEs with go-cve-dictionary. err: %w", err)
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

func detectCpeURIsCvesWithGoCVEDictionary(r *models.ScanResult, cpes []Cpe, cnf config.GoCveDictConf, logOpts logging.LogOpts) error {
	client, err := newGoCveDictClient(&cnf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to newGoCveDictClient. err: %w", err)
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	nCVEs := 0
	for _, cpe := range cpes {
		details, err := client.detectCveByCpeURI(cpe.CpeURI, cpe.UseJVN)
		if err != nil {
			return xerrors.Errorf("Failed to detectCveByCpeURI. err: %w", err)
		}

		for _, detail := range details {
			// Skip detections carried by no dictionary-remaining DETECTION
			// source. The list mirrors go-cve-dictionary's GetByCpeURI
			// admission gate minus the vuls2-migrated sources (NVD, Cisco, and
			// Palo Alto), so NVD-only / Cisco-only / Palo Alto-only detections
			// disappear here — vuls2 re-detects them from its own data. EUVD /
			// MITRE contents can ride along on a detail but are never a
			// detection basis (gocve neither matches nor admits on them, and
			// getMaxConfidence has no tier for them), so they do not keep
			// a detail alive.
			if !detail.HasJvn() && !detail.HasFortinet() && !detail.HasVulncheck() {
				continue
			}

			advisories := []models.DistroAdvisory{}
			if detail.HasFortinet() {
				for _, fortinet := range detail.Fortinets {
					advisories = append(advisories, models.DistroAdvisory{
						AdvisoryID:  fortinet.AdvisoryID,
						Issued:      fortinet.PublishedDate,
						Updated:     fortinet.LastModifiedDate,
						Description: fortinet.Summary,
					})
				}
			}

			// JVN advisories are redundant for CVEs that NVD also covers.
			if !detail.HasNvd() && detail.HasJvn() {
				for _, jvn := range detail.Jvns {
					advisories = append(advisories, models.DistroAdvisory{
						AdvisoryID:  jvn.JvnID,
						Issued:      jvn.PublishedDate,
						Updated:     jvn.LastModifiedDate,
						Description: jvn.Summary,
					})
				}
			}

			// Drop the vuls2-migrated sources only now, just before
			// confidence selection: getMaxConfidence must not return their
			// confidences (vuls2 reports those itself), but everything above
			// (the skip gate, advisory synthesis) wants the original
			// detection. Deferring the strip keeps the earlier logic free of
			// per-source "had*" flags as more sources migrate to vuls2.
			detail.Nvds = nil
			detail.Ciscos = nil
			detail.Paloaltos = nil
			maxConfidence := getMaxConfidence(detail)

			if val, ok := r.ScannedCves[detail.CveID]; ok {
				val.CpeURIs = util.AppendIfMissing(val.CpeURIs, cpe.CpeURI)
				val.Confidences.AppendIfMissing(maxConfidence)
				for _, adv := range advisories {
					val.DistroAdvisories.AppendIfMissing(&adv)
				}
				r.ScannedCves[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:            detail.CveID,
					CpeURIs:          []string{cpe.CpeURI},
					Confidences:      models.Confidences{maxConfidence},
					DistroAdvisories: advisories,
					CveContents:      models.CveContents{},
				}
				r.ScannedCves[detail.CveID] = v
				nCVEs++
			}
		}
	}
	logging.Log.Infof("%s: %d CVEs are detected with CPE", r.FormatServerName(), nCVEs)
	return nil
}

func getMaxConfidence(detail cvemodels.CveDetail) (maxConfidence models.Confidence) {
	if detail.HasCisco() {
		fn := func(s string) models.Confidence {
			switch s {
			case cvemodels.CiscoExactVersionMatch:
				return models.CiscoExactVersionMatch
			case cvemodels.CiscoRoughVersionMatch:
				return models.CiscoRoughVersionMatch
			case cvemodels.CiscoVendorProductMatch:
				return models.CiscoVendorProductMatch
			default:
				return models.Confidence{}
			}
		}

		return fn(slices.MaxFunc(detail.Ciscos, func(a, b cvemodels.Cisco) int {
			return cmp.Compare(fn(a.DetectionMethod).Score, fn(b.DetectionMethod).Score)
		}).DetectionMethod)
	}

	if detail.HasPaloalto() {
		fn := func(s string) models.Confidence {
			switch s {
			case cvemodels.PaloaltoExactVersionMatch:
				return models.PaloaltoExactVersionMatch
			case cvemodels.PaloaltoRoughVersionMatch:
				return models.PaloaltoRoughVersionMatch
			case cvemodels.PaloaltoVendorProductMatch:
				return models.PaloaltoVendorProductMatch
			default:
				return models.Confidence{}
			}
		}

		return fn(slices.MaxFunc(detail.Paloaltos, func(a, b cvemodels.Paloalto) int {
			return cmp.Compare(fn(a.DetectionMethod).Score, fn(b.DetectionMethod).Score)
		}).DetectionMethod)
	}

	if detail.HasFortinet() {
		fn := func(s string) models.Confidence {
			switch s {
			case cvemodels.FortinetExactVersionMatch:
				return models.FortinetExactVersionMatch
			case cvemodels.FortinetRoughVersionMatch:
				return models.FortinetRoughVersionMatch
			case cvemodels.FortinetVendorProductMatch:
				return models.FortinetVendorProductMatch
			default:
				return models.Confidence{}
			}
		}

		return fn(slices.MaxFunc(detail.Fortinets, func(a, b cvemodels.Fortinet) int {
			return cmp.Compare(fn(a.DetectionMethod).Score, fn(b.DetectionMethod).Score)
		}).DetectionMethod)
	}

	if detail.HasNvd() {
		fn := func(s string) models.Confidence {
			switch s {
			case cvemodels.NvdExactVersionMatch:
				return models.NvdExactVersionMatch
			case cvemodels.NvdRoughVersionMatch:
				return models.NvdRoughVersionMatch
			case cvemodels.NvdVendorProductMatch:
				return models.NvdVendorProductMatch
			default:
				return models.Confidence{}
			}
		}

		return fn(slices.MaxFunc(detail.Nvds, func(a, b cvemodels.Nvd) int {
			return cmp.Compare(fn(a.DetectionMethod).Score, fn(b.DetectionMethod).Score)
		}).DetectionMethod)
	}

	if detail.HasVulncheck() {
		fn := func(s string) models.Confidence {
			switch s {
			case cvemodels.VulncheckExactVersionMatch:
				return models.VulncheckExactVersionMatch
			case cvemodels.VulncheckRoughVersionMatch:
				return models.VulncheckRoughVersionMatch
			case cvemodels.VulncheckVendorProductMatch:
				return models.VulncheckVendorProductMatch
			default:
				return models.Confidence{}
			}
		}

		return fn(slices.MaxFunc(detail.Vulnchecks, func(a, b cvemodels.Vulncheck) int {
			return cmp.Compare(fn(a.DetectionMethod).Score, fn(b.DetectionMethod).Score)
		}).DetectionMethod)
	}

	if detail.HasJvn() {
		return models.JvnVendorProductMatch
	}

	return maxConfidence
}
