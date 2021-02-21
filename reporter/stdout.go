package reporter

import (
	"fmt"

	"github.com/future-architect/vuls/models"
)

// StdoutWriter write to stdout
type StdoutWriter struct {
	FormatCsv         bool
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

func (w StdoutWriter) Write(rs ...models.ScanResult) error {
	if w.FormatOneLineText {
		fmt.Print("\n\n")
		fmt.Println("One Line Summary")
		fmt.Println("================")
		fmt.Println(formatOneLineSummary(rs...))
		fmt.Print("\n")
	}

	if w.FormatList || w.FormatCsv {
		for _, r := range rs {
			fmt.Println(formatList(r))
		}
	}

	if w.FormatFullText {
		for _, r := range rs {
			fmt.Println(formatFullPlainText(r))
		}
	}
	return nil
}
