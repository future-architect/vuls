package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/future-architect/vuls/pkg/log"
	"github.com/future-architect/vuls/pkg/types"
)

type ReportOptions struct {
	Format string
}

func NewCmdReport() *cobra.Command {
	opts := &ReportOptions{
		Format: "oneline",
	}

	cmd := &cobra.Command{
		Use:   "report (<result path>)",
		Short: "Vuls report vulnerabilities",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exec(context.Background(), opts.Format, args); err != nil {
				return errors.Wrap(err, "failed to report")
			}
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls report
			$ vuls report results
			$ vuls report resutls/2022-11-05T01:08:44+09:00/local/localhost.json
		`),
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "oneline", "stdout format")

	return cmd
}

type affectedPackage struct {
	name   string
	status string
	source string
}
type result struct {
	cveid      string
	cvssVector string
	cvssScore  *float64
	epss       *float64
	kev        bool
	packages   []affectedPackage
}

func exec(ctx context.Context, format string, args []string) error {
	logger, err := zap.NewProduction()
	if err != nil {
		return errors.Wrap(err, "create logger")
	}

	ctx = log.ContextWithLogger(ctx, logger)

	if len(args) == 0 {
		pwd, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err, "get working direcotry")
		}

		fs, err := os.ReadDir(filepath.Join(pwd, "results"))
		if err != nil {
			return errors.Wrapf(err, "read %s", filepath.Join(pwd, "results"))
		}

		var ds []time.Time
		for _, f := range fs {
			if !f.IsDir() {
				continue
			}

			t, err := time.Parse("2006-01-02T150405-0700", f.Name())
			if err != nil {
				continue
			}
			ds = append(ds, t)
		}
		if len(ds) == 0 {
			return errors.Wrapf(err, "result dir not found")
		}

		slices.SortFunc(ds, func(e1, e2 time.Time) bool {
			return e1.After(e2)
		})

		args = append(args, filepath.Join(pwd, "results", ds[0].Format("2006-01-02T150405-0700")))
	}

	rs := map[string][]result{}
	for _, arg := range args {
		if err := filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer f.Close()

			var host types.Host
			if err := json.NewDecoder(f).Decode(&host); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}

			name := host.Name
			if host.Family != "" && host.Release != "" {
				name = fmt.Sprintf("%s (%s %s)", host.Name, host.Family, host.Release)
			}

			for id, vinfo := range host.ScannedCves {
				r := result{
					cveid: id,
				}

				if officialCont, ok := vinfo.Content["official"]; ok {
					for _, c := range officialCont.CVSS {
						if c.Source != "nvd" || strings.HasPrefix(c.Version, "3") {
							continue
						}
						r.cvssVector = c.Vector
						r.cvssScore = c.Score
					}
					if officialCont.EPSS != nil {
						r.epss = officialCont.EPSS.EPSS
					}
					r.kev = officialCont.KEV
				}

				for _, p := range vinfo.AffectedPackages {
					r.packages = append(r.packages, affectedPackage{
						name:   p.Name,
						status: p.Status,
						source: p.Source,
					})
				}

				rs[name] = append(rs[name], r)
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", arg)
		}
	}

	switch format {
	case "oneline":
		formatOneline(rs)
	case "list":
		formatList(rs)
	default:
		return errors.Errorf("%s is not implemented format", format)
	}

	return nil
}

func formatOneline(rs map[string][]result) {
	for name, lines := range rs {
		fmt.Println(name)
		fmt.Println(strings.Repeat("=", len(name)))

		status := map[string]int{}
		for _, l := range lines {
			for _, p := range l.packages {
				s := p.status
				if p.status == "" {
					s = "(none)"
				}
				status[s]++
			}
		}

		var ss []string
		for s, num := range status {
			ss = append(ss, fmt.Sprintf("%s: %d", s, num))
		}
		fmt.Printf("%d CVEs detected. package status: %s\n\n", len(lines), strings.Join(ss, ", "))
	}
}

func formatList(rs map[string][]result) {
	for name, lines := range rs {
		slices.SortFunc(lines, func(l1, l2 result) bool {
			s1, s2 := 0.0, 0.0
			if l1.cvssScore != nil {
				s1 = *l1.cvssScore
			}
			if l2.cvssScore != nil {
				s2 = *l2.cvssScore
			}
			return s1 > s2
		})

		fmt.Println(name)
		fmt.Println(strings.Repeat("=", len(name)))
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"CVEID", "Vector", "CVSS", "EPSS", "KEV", "Package", "Status", "Source"})
		table.SetAutoMergeCells(true)
		table.SetRowLine(true)
		for _, l := range lines {
			for _, p := range l.packages {
				var score string
				if l.cvssScore != nil {
					score = fmt.Sprintf("%.1f", *l.cvssScore)
				}
				var epss string
				if l.epss != nil {
					epss = fmt.Sprintf("%f", *l.epss)
				}
				source, _, _ := strings.Cut(p.source, ":")
				table.Append([]string{l.cveid, l.cvssVector, score, epss, fmt.Sprintf("%v", l.kev), p.name, p.status, source})
			}
		}
		table.Render()
		fmt.Println()
	}
}
