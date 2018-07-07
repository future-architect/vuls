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
	"encoding/json"
	"net/http"

	"github.com/future-architect/vuls/models"
	"github.com/pkg/errors"
)

// HTTPWriter writes results to S3
type HTTPWriter struct {
	Writer http.ResponseWriter
}

// Write sends results as HTTP response
func (w HTTPWriter) Write(rs ...models.ScanResult) (err error) {
	res, err := json.Marshal(rs)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal scah results")
	}
	w.Writer.Header().Set("Content-Type", "application/json")
	_, err = w.Writer.Write(res)

	return err
}
