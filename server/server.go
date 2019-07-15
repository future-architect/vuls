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

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
)

// VulsHandler is used for vuls server mode
type VulsHandler struct {
	DBclient report.DBClient
}

func (h VulsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	result := models.ScanResult{ScannedCves: models.VulnInfos{}}

	contentType := r.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		util.Log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if mediatype == "application/json" {
		if err = json.NewDecoder(r.Body).Decode(&result); err != nil {
			util.Log.Error(err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else if mediatype == "text/plain" {
		buf := new(bytes.Buffer)
		io.Copy(buf, r.Body)
		if result, err = scan.ViaHTTP(r.Header, buf.String()); err != nil {
			util.Log.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		util.Log.Error(mediatype)
		http.Error(w, fmt.Sprintf("Invalid Content-Type: %s", contentType), http.StatusUnsupportedMediaType)
		return
	}

	if err := report.FillCveInfo(h.DBclient, &result, []string{}, true); err != nil {
		util.Log.Error(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// report
	reports := []report.ResultWriter{
		report.HTTPResponseWriter{Writer: w},
	}
	if c.Conf.ToLocalFile {
		scannedAt := result.ScannedAt
		if scannedAt.IsZero() {
			scannedAt = time.Now().Truncate(1 * time.Hour)
			result.ScannedAt = scannedAt
		}
		dir, err := scan.EnsureResultDir(scannedAt)
		if err != nil {
			util.Log.Errorf("Failed to ensure the result directory: %+v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		reports = append(reports, report.LocalFileWriter{
			CurrentDir: dir,
		})
	}

	for _, w := range reports {
		if err := w.Write(result); err != nil {
			util.Log.Errorf("Failed to report. err: %+v", err)
			return
		}
	}
}
