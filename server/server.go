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
	"github.com/future-architect/vuls/detector/vuls2"
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

	// Share one lazily-opened vuls2 db session across this request's package
	// detection and the enrichment that follows, so the read cache detection
	// warms is reused by enrichment rather than opened and rebuilt twice.
	sesh := vuls2.NewSession(config.Conf.Vuls2, config.Conf.NoProgress)
	defer sesh.Close()

	if err := detector.DetectPkgCves(&r, sesh); err != nil {
		logging.Log.Errorf("Failed to detect Pkg CVE: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if err := vuls2.EnrichVulnInfos(&r, sesh); err != nil {
		logging.Log.Errorf("Failed to enrich vulnerability data with vuls2: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// set ReportedAt to current time when it's set to the epoch, ensures that ReportedAt will be set
	// properly for scans sent to vuls when running in server mode
	if r.ReportedAt.IsZero() {
		r.ReportedAt = time.Now()
	}

	h.filterScanResult(&r)

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
