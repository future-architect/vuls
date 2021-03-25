package reporter

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

// LocalFileWriter writes results to a local file.
type LocalFileWriter struct {
	CurrentDir        string
	DiffPlus          bool
	DiffMinus         bool
	FormatJSON        bool
	FormatCsv         bool
	FormatFullText    bool
	FormatOneLineText bool
	FormatList        bool
	Gzip              bool
}

func (w LocalFileWriter) Write(rs ...models.ScanResult) (err error) {
	if w.FormatOneLineText {
		path := filepath.Join(w.CurrentDir, "summary.txt")
		text := formatOneLineSummary(rs...)
		if err := w.writeFile(path, []byte(text), 0600); err != nil {
			return xerrors.Errorf(
				"Failed to write to file. path: %s, err: %w",
				path, err)
		}
	}

	for _, r := range rs {
		r.SortForJSONOutput()

		path := filepath.Join(w.CurrentDir, r.ReportFileName())
		if w.FormatJSON {
			p := path + ".json"
			if w.DiffPlus || w.DiffMinus {
				p = path + "_diff.json"
			}
			var b []byte
			if b, err = json.MarshalIndent(r, "", "    "); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := w.writeFile(p, b, 0600); err != nil {
				return xerrors.Errorf("Failed to write JSON. path: %s, err: %w", p, err)
			}
		}

		if w.FormatList {
			p := path + "_short.txt"
			if w.DiffPlus || w.DiffMinus {
				p = path + "_short_diff.txt"
			}
			if err := w.writeFile(
				p, []byte(formatList(r)), 0600); err != nil {
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
			}
		}

		if w.FormatFullText {
			p := path + "_full.txt"
			if w.DiffPlus || w.DiffMinus {
				p = path + "_full_diff.txt"
			}

			if err := w.writeFile(
				p, []byte(formatFullPlainText(r)), 0600); err != nil {
				return xerrors.Errorf(
					"Failed to write text files. path: %s, err: %w", p, err)
			}
		}

		if w.FormatCsv {
			p := path + ".csv"
			if w.DiffPlus || w.DiffMinus {
				p = path + "_diff.csv"
			}
			if err := formatCsvList(r, p); err != nil {
				return xerrors.Errorf("Failed to write CSV: %s, %w", p, err)
			}
		}

	}
	return nil
}

func (w LocalFileWriter) writeFile(path string, data []byte, perm os.FileMode) (err error) {
	if w.Gzip {
		data, err = gz(data)
		if err != nil {
			return err
		}
		path += ".gz"
	}
	return ioutil.WriteFile(path, []byte(data), perm)
}
