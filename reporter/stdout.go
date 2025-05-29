package reporter

import (
	"fmt"

	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

// StdoutWriter write to stdout
type StdoutWriter struct {
	FormatFullText    bool
	FormatOneLineText bool
	FormatList        bool
}

//TODO support -format-jSON

// WriteScanSummary prints Scan summary at the end of scan
func (w StdoutWriter) WriteScanSummary(rs ...models.ScanResult) {
	fmt.Printf("\n\n")
	fmt.Println("Scan Summary")
	fmt.Println("================")
	fmt.Printf("%s\n", formatScanSummary(rs...))
}

// Write results to stdout
func (w StdoutWriter) Write(rs ...models.ScanResult) error {
	if w.FormatOneLineText {
		fmt.Print("\n\n")
		fmt.Println("One Line Summary")
		fmt.Println("================")
		fmt.Println(formatOneLineSummary(rs...))
		fmt.Print("\n")
	}

	if w.FormatList {
		for _, r := range rs {
			text, err := formatList(r)
			if err != nil {
				return xerrors.Errorf("Failed to format list: %w", err)
			}
			fmt.Println(text)
		}
	}

	if w.FormatFullText {
		for _, r := range rs {
			text, err := formatFullPlainText(r)
			if err != nil {
				return xerrors.Errorf("Failed to format full text: %w", err)
			}
			fmt.Println(text)
		}
	}
	return nil
}
