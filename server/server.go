//go:build !scanner

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/scanner"
)

// VulsHandler is used for vuls server mode
type VulsHandler struct {
	ToLocalFile bool
}

// ServeHTTP is http handler
func (h VulsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	r := models.ScanResult{ScannedCves: models.VulnInfos{}}

	contentType := req.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		logging.Log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch mediatype {
	case "application/json":
		if err = json.NewDecoder(req.Body).Decode(&r); err != nil {
			logging.Log.Error(err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	case "text/plain":
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, req.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r, err = scanner.ViaHTTP(req.Header, buf.String(), h.ToLocalFile); err != nil {
			logging.Log.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		logging.Log.Error(mediatype)
		http.Error(w, fmt.Sprintf("Invalid Content-Type: %s", contentType), http.StatusUnsupportedMediaType)
		return
	}

	if err := detector.DetectPkgCves(&r, config.Conf.OvalDict, config.Conf.Gost, config.Conf.Vuls2, config.Conf.LogOpts, config.Conf.NoProgress); err != nil {
		logging.Log.Errorf("Failed to detect Pkg CVE: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	logging.Log.Infof("Fill CVE detailed with gost")
	if err := gost.FillCVEsWithRedHat(&r, config.Conf.Gost, config.Conf.LogOpts); err != nil {
		logging.Log.Errorf("Failed to fill with gost: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	logging.Log.Infof("Fill CVE detailed with CVE-DB")
	if err := detector.FillCvesWithGoCVEDictionary(&r, config.Conf.CveDict, config.Conf.LogOpts); err != nil {
		logging.Log.Errorf("Failed to fill with CVE: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	nExploitCve, err := detector.FillWithExploit(&r, config.Conf.Exploit, config.Conf.LogOpts)
	if err != nil {
		logging.Log.Errorf("Failed to fill with exploit: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	logging.Log.Infof("%s: %d PoC detected", r.FormatServerName(), nExploitCve)

	nMetasploitCve, err := detector.FillWithMetasploit(&r, config.Conf.Metasploit, config.Conf.LogOpts)
	if err != nil {
		logging.Log.Errorf("Failed to fill with metasploit: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	logging.Log.Infof("%s: %d exploits are detected", r.FormatServerName(), nMetasploitCve)

	if err := detector.FillWithKEVuln(&r, config.Conf.KEVuln, config.Conf.LogOpts); err != nil {
		logging.Log.Errorf("Failed to fill with Known Exploited Vulnerabilities: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	if err := detector.FillWithCTI(&r, config.Conf.Cti, config.Conf.LogOpts); err != nil {
		logging.Log.Errorf("Failed to fill with Cyber Threat Intelligences: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	detector.FillCweDict(&r)

	// set ReportedAt to current time when it's set to the epoch, ensures that ReportedAt will be set
	// properly for scans sent to vuls when running in server mode
	if r.ReportedAt.IsZero() {
		r.ReportedAt = time.Now()
	}

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

	if config.Conf.IgnoreUnscoredCves {
		r.ScannedCves, nFiltered = r.ScannedCves.FindScoredVulns()
		logging.Log.Infof("%s: %d CVEs filtered by --ignore-unscored-cves", r.FormatServerName(), nFiltered)
	}

	if config.Conf.IgnoreUnfixed {
		r.ScannedCves, nFiltered = r.ScannedCves.FilterUnfixed(config.Conf.IgnoreUnfixed)
		logging.Log.Infof("%s: %d CVEs filtered by --ignore-unfixed", r.FormatServerName(), nFiltered)
	}

	// report
	reports := []reporter.ResultWriter{
		reporter.HTTPResponseWriter{Writer: w},
	}
	if h.ToLocalFile {
		scannedAt := r.ScannedAt
		if scannedAt.IsZero() {
			scannedAt = time.Now().Truncate(1 * time.Hour)
			r.ScannedAt = scannedAt
		}
		dir, err := scanner.EnsureResultDir(config.Conf.ResultsDir, scannedAt)
		if err != nil {
			logging.Log.Errorf("Failed to ensure the result directory: %+v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// server subcmd doesn't have diff option
		reports = append(reports, reporter.LocalFileWriter{
			CurrentDir: dir,
			FormatJSON: true,
		})
	}

	for _, w := range reports {
		if err := w.Write(r); err != nil {
			logging.Log.Errorf("Failed to report. err: %+v", err)
			return
		}
	}
}
