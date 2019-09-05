package report

import (
	"fmt"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// StdoutWriter write to stdout
type StdoutWriter struct{}

// WriteScanSummary prints Scan summary at the end of scan
func (w StdoutWriter) WriteScanSummary(rs ...models.ScanResult) {
	fmt.Printf("\n\n")
	fmt.Println("One Line Summary")
	fmt.Println("================")
	fmt.Printf("%s\n", formatScanSummary(rs...))
}

func (w StdoutWriter) Write(rs ...models.ScanResult) error {
	if c.Conf.FormatOneLineText {
		fmt.Print("\n\n")
		fmt.Println("One Line Summary")
		fmt.Println("================")
		fmt.Println(formatOneLineSummary(rs...))
		fmt.Print("\n")
	}

	if c.Conf.FormatList {
		for _, r := range rs {
			fmt.Println(formatList(r))
		}
	}

	if c.Conf.FormatFullText {
		for _, r := range rs {
			fmt.Println(formatFullPlainText(r))
		}
	}
	return nil
}
