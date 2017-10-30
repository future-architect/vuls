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
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// LocalFileWriter writes results to a local file.
type LocalFileWriter struct {
	CurrentDir string
}

func (w LocalFileWriter) Write(rs ...models.ScanResult) (err error) {
	if c.Conf.FormatOneLineText {
		path := filepath.Join(w.CurrentDir, "summary.txt")
		text := formatOneLineSummary(rs...)
		if err := writeFile(path, []byte(text), 0600); err != nil {
			return fmt.Errorf(
				"Failed to write to file. path: %s, err: %s",
				path, err)
		}
	}

	for _, r := range rs {
		path := filepath.Join(w.CurrentDir, r.ReportFileName())

		if c.Conf.FormatJSON {
			var p string
			if c.Conf.Diff {
				p = path + "_diff.json"
			} else {
				p = path + ".json"
			}

			var b []byte
			if c.Conf.Debug {
				if b, err = json.MarshalIndent(r, "", "    "); err != nil {
					return fmt.Errorf("Failed to Marshal to JSON: %s", err)
				}
			} else {
				if b, err = json.Marshal(r); err != nil {
					return fmt.Errorf("Failed to Marshal to JSON: %s", err)
				}
			}
			if err := writeFile(p, b, 0600); err != nil {
				return fmt.Errorf("Failed to write JSON. path: %s, err: %s", p, err)
			}
		}

		if c.Conf.FormatShortText {
			var p string
			if c.Conf.Diff {
				p = path + "_short_diff.txt"
			} else {
				p = path + "_short.txt"
			}

			if err := writeFile(
				p, []byte(formatShortPlainText(r)), 0600); err != nil {
				return fmt.Errorf(
					"Failed to write text files. path: %s, err: %s", p, err)
			}
		}

		if c.Conf.FormatFullText {
			var p string
			if c.Conf.Diff {
				p = path + "_full_diff.txt"
			} else {
				p = path + "_full.txt"
			}

			if err := writeFile(
				p, []byte(formatFullPlainText(r)), 0600); err != nil {
				return fmt.Errorf(
					"Failed to write text files. path: %s, err: %s", p, err)
			}
		}

		if c.Conf.FormatXML {
			var p string
			if c.Conf.Diff {
				p = path + "_diff.xml"
			} else {
				p = path + ".xml"
			}

			var b []byte
			if b, err = xml.Marshal(r); err != nil {
				return fmt.Errorf("Failed to Marshal to XML: %s", err)
			}
			allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})
			if err := writeFile(p, allBytes, 0600); err != nil {
				return fmt.Errorf("Failed to write XML. path: %s, err: %s", p, err)
			}
		}
	}
	return nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	var err error
	if c.Conf.GZIP {
		if data, err = gz(data); err != nil {
			return err
		}
		path = path + ".gz"
	}

	if err := ioutil.WriteFile(
		path, []byte(data), perm); err != nil {
		return err
	}

	return nil
}
