package report

import (
	"encoding/json"
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
			p := path + ".json"
			if c.Conf.DiffPlus || c.Conf.DiffMinus {
				p = path + "_diff.json"
			}
			var b []byte
			if b, err = json.MarshalIndent(r, "", "    "); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := writeFile(p, b, 0600); err != nil {
				return xerrors.Errorf("Failed to write JSON. path: %s, err: %w", p, err)
			}
		}

		if c.Conf.FormatList {
			p := path + "_short.txt"
			if c.Conf.DiffPlus || c.Conf.DiffMinus {
				p = path + "_short_diff.txt"
			}
			if err := writeFile(
				p, []byte(formatList(r)), 0600); err != nil {
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
			}
		}

		if c.Conf.FormatFullText {
			p := path + "_full.txt"
			if c.Conf.DiffPlus || c.Conf.DiffMinus {
				p = path + "_full_diff.txt"
			}

			if err := writeFile(
				p, []byte(formatFullPlainText(r)), 0600); err != nil {
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
			}
		}

		if c.Conf.FormatCsvList {
			p := path + ".csv"
			if c.Conf.DiffPlus || c.Conf.DiffMinus {
				p = path + "_diff.csv"
			}
			if err := formatCsvList(r, p); err != nil {
				return xerrors.Errorf("Failed to write CSV: %s, %w", p, err)
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
