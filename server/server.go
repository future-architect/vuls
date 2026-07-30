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

	// DB is the vuls2 db shared by every request for the lifetime of the
	// process. Each request borrows it for the length of its detection and
	// enrichment; nothing here opens or downloads a db.
	DB *vuls2.SharedDB

	// sem bounds how many requests may detect at once, nil for no bound. One
	// detection alone spawns GOMAXPROCS workers and holds every CVE it finds,
	// so letting an unbounded number of them run oversubscribes CPU and memory
	// badly enough that each takes minutes instead of seconds. Requests queue
	// on it rather than being rejected.
	sem chan struct{}
}

// NewVulsHandler returns the /vuls handler. maxConcurrency caps concurrent
// detections; 0 or less leaves them unbounded.
func NewVulsHandler(toLocalFile bool, db *vuls2.SharedDB, maxConcurrency int) *VulsHandler {
	h := &VulsHandler{ToLocalFile: toLocalFile, DB: db}
	if maxConcurrency > 0 {
		h.sem = make(chan struct{}, maxConcurrency)
	}
	return h
}

// ServeHTTP is http handler
func (h *VulsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

	// Bound concurrent detections before touching the db, so queued requests do
	// not pin a db generation while they wait.
	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		case <-req.Context().Done():
			// Client gave up while queued; nothing to report to.
			return
		}
	}

	// Borrow the process-wide vuls2 db for this request's package detection and
	// the enrichment that follows, so both query one open db and the refresher
	// cannot close it under them. Nothing here fetches: while the first fetch is
	// still running this fails and the request is refused, rather than the
	// request becoming another thing that downloads a db.
	sesh, release, err := h.DB.Acquire()
	if err != nil {
		logging.Log.Errorf("Failed to acquire vuls2 db: %+v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer release()

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
