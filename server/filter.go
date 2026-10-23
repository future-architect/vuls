package server

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// filterScanResult applies the server-mode threshold/ignore config to
// r.ScannedCves. Extracted from ServeHTTP so it can be unit-tested without a
// live vuls2 DB session.
func (h VulsHandler) filterScanResult(r *models.ScanResult) {
	nFiltered := 0
	logging.Log.Infof("%s: total %d CVEs detected", r.FormatServerName(), len(r.ScannedCves))

	if 0 < config.Conf.CvssScoreOver {
		r.ScannedCves, nFiltered = r.ScannedCves.FilterByCvssOver(config.Conf.CvssScoreOver)
		logging.Log.Infof("%s: %d CVEs filtered by --cvss-over=%g", r.FormatServerName(), nFiltered, config.Conf.CvssScoreOver)
	}

	if 0 < config.Conf.ConfidenceScoreOver {
		r.ScannedCves, nFiltered = r.ScannedCves.FilterByConfidenceOver(config.Conf.ConfidenceScoreOver)
		logging.Log.Infof("%s: %d CVEs filtered by --confidence-over=%d", r.FormatServerName(), nFiltered, config.Conf.ConfidenceScoreOver)
	}

	// IgnoreCves / IgnorePkgsRegexp: same policy as detector.DetectVulnInfos
	// (detector/detector.go) for scan/report mode. Previously missing here,
	// so server mode silently ignored these settings (issue #1267).
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

	if config.Conf.IgnoreUnscoredCves {
		r.ScannedCves, nFiltered = r.ScannedCves.FindScoredVulns()
		logging.Log.Infof("%s: %d CVEs filtered by --ignore-unscored-cves", r.FormatServerName(), nFiltered)
	}

	if config.Conf.IgnoreUnfixed {
		r.ScannedCves, nFiltered = r.ScannedCves.FilterUnfixed(config.Conf.IgnoreUnfixed)
		logging.Log.Infof("%s: %d CVEs filtered by --ignore-unfixed", r.FormatServerName(), nFiltered)
	}
}
