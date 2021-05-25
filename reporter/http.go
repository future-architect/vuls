package reporter

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
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
			return err
		}
		_, err = http.Post(w.URL, "application/json; charset=utf-8", b)
		if err != nil {
			return err
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
	_, err = w.Writer.Write(res)

	return err
}
