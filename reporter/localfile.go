package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter/sbom"
)

// LocalFileWriter writes results to a local file.
type LocalFileWriter struct {
	CurrentDir          string
	DiffPlus            bool
	DiffMinus           bool
	FormatJSON          bool
	FormatCsv           bool
	FormatFullText      bool
	FormatOneLineText   bool
	FormatList          bool
	FormatCycloneDXJSON bool
	FormatCycloneDXXML  bool
	FormatSPDXJSON      bool
	Gzip                bool
}

// Write results to Local File
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
			text, err := formatList(r)
			if err != nil {
				return xerrors.Errorf("Failed to format list: %w", err)
			}
			if err := w.writeFile(p, []byte(text), 0600); err != nil {
				return xerrors.Errorf("Failed to write text files. path: %s, err: %w", p, err)
			}
		}

		if w.FormatFullText {
			p := path + "_full.txt"
			if w.DiffPlus || w.DiffMinus {
				p = path + "_full_diff.txt"
			}
			text, err := formatFullPlainText(r)
			if err != nil {
				return xerrors.Errorf("Failed to format full text: %w", err)
			}
			if err := w.writeFile(p, []byte(text), 0600); err != nil {
				return xerrors.Errorf("Failed to write text files. path: %s, err: %w", p, err)
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

		if w.FormatCycloneDXJSON {
			bs, err := sbom.SerializeCycloneDX(sbom.ToCycloneDX(r), cyclonedx.BOMFileFormatJSON)
			if err != nil {
				return xerrors.Errorf("Failed to generate CycloneDX JSON. err: %w", err)
			}
			p := fmt.Sprintf("%s_cyclonedx.json", path)
			if err := w.writeFile(p, bs, 0600); err != nil {
				return xerrors.Errorf("Failed to write CycloneDX JSON. path: %s, err: %w", p, err)
			}
		}

		if w.FormatCycloneDXXML {
			bs, err := sbom.SerializeCycloneDX(sbom.ToCycloneDX(r), cyclonedx.BOMFileFormatXML)
			if err != nil {
				return xerrors.Errorf("Failed to generate CycloneDX XML. err: %w", err)
			}
			p := fmt.Sprintf("%s_cyclonedx.xml", path)
			if err := w.writeFile(p, bs, 0600); err != nil {
				return xerrors.Errorf("Failed to write CycloneDX XML. path: %s, err: %w", p, err)
			}
		}

		if w.FormatSPDXJSON {
			bs, err := sbom.SerializeSPDX(sbom.ToSPDX(r, ""))
			if err != nil {
				return xerrors.Errorf("Failed to generate SPDX JSON. err: %w", err)
			}
			p := fmt.Sprintf("%s_spdx.json", path)
			if err := w.writeFile(p, bs, 0600); err != nil {
				return xerrors.Errorf("Failed to write SPDX JSON. path: %s, err: %w", p, err)
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
	return os.WriteFile(path, []byte(data), perm)
}
