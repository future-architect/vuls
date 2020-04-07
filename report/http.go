package report

import (
	"bytes"
	"encoding/json"
	"net/http"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

// HTTPRequestWriter writes results to HTTP request
type HTTPRequestWriter struct{}

// Write sends results as HTTP response
func (w HTTPRequestWriter) Write(rs ...models.ScanResult) (err error) {
	for _, r := range rs {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(r)
		_, err = http.Post(c.Conf.HTTP.URL, "application/json; charset=utf-8", b)
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
		return xerrors.Errorf("Failed to marshal scah results: %w", err)
	}
	w.Writer.Header().Set("Content-Type", "application/json")
	_, err = w.Writer.Write(res)

	return err
}
