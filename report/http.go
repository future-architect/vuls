/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
