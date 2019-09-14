package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
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
			return xerrors.Errorf(
				"Failed to write to file. path: %s, err: %w",
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
					return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
				}
			} else {
				if b, err = json.Marshal(r); err != nil {
					return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
				}
			}
			if err := writeFile(p, b, 0600); err != nil {
				return xerrors.Errorf("Failed to write JSON. path: %s, err: %w", p, err)
			}
		}

		if c.Conf.FormatList {
			var p string
			if c.Conf.Diff {
				p = path + "_short_diff.txt"
			} else {
				p = path + "_short.txt"
			}

			if err := writeFile(
				p, []byte(formatList(r)), 0600); err != nil {
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
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
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
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
				return xerrors.Errorf("Failed to Marshal to XML: %w", err)
			}
			allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})
			if err := writeFile(p, allBytes, 0600); err != nil {
				return xerrors.Errorf("Failed to write XML. path: %s, err: %w", p, err)
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
		path += ".gz"
	}
	return ioutil.WriteFile(path, []byte(data), perm)
}
