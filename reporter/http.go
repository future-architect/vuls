package reporter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/models"
)

// HTTPRequestWriter writes results to HTTP request
type HTTPRequestWriter struct {
	URL string
}

// Write sends results as HTTP response
func (w HTTPRequestWriter) Write(rs ...models.ScanResult) (err error) {
	for _, r := range rs {
		b := new(bytes.Buffer)
		if err := json.NewEncoder(b).Encode(r); err != nil {
			return xerrors.Errorf("Failed to encode scan result. err: %w", err)
		}

		resp, err := http.Post(w.URL, "application/json; charset=utf-8", b)
		if err != nil {
			return xerrors.Errorf("Failed to post request. err: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return xerrors.Errorf("Failed to post request. err: error request response with status code %d", resp.StatusCode)
		}
		defer resp.Body.Close()

		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return xerrors.Errorf("Failed to discard response body. err: %w", err)
		}
	}
	return nil
}

// HTTPResponseWriter writes results to HTTP response
type HTTPResponseWriter struct {
	Writer http.ResponseWriter
}

// Write sends results as HTTP response
func (w HTTPResponseWriter) Write(rs ...models.ScanResult) (err error) {
	res, err := json.Marshal(rs)
	if err != nil {
		return xerrors.Errorf("Failed to marshal scan results: %w", err)
	}
	w.Writer.Header().Set("Content-Type", "application/json")

	if _, err = w.Writer.Write(res); err != nil {
		return xerrors.Errorf("Failed to write response. err: %w", err)
	}

	return nil
}
