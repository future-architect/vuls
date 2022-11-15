package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/future-architect/vuls/pkg/config"
	"github.com/future-architect/vuls/pkg/detect"
	"github.com/future-architect/vuls/pkg/log"
	"github.com/future-architect/vuls/pkg/types"
)

type DetectOptions struct {
	Config string
}

func NewCmdDetect() *cobra.Command {
	opts := &DetectOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "detect ([\"host\"])",
		Short: "Vuls detect vulnerabilities",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exec(context.Background(), opts.Config, args); err != nil {
				return errors.Wrap(err, "failed to detect")
			}

			return nil
		},
		Example: heredoc.Doc(`
			$ vuls detect
			$ vuls detect results/**/host.json
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}

func exec(ctx context.Context, path string, args []string) error {
	logger, err := zap.NewProduction()
	if err != nil {
		return errors.Wrap(err, "create logger")
	}

	ctx = log.ContextWithLogger(ctx, logger)

	c, err := config.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s as config", path)
	}

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

	type result struct {
		error string
		nCVEs int
	}
	detectCVEs := map[string]result{}
	for _, arg := range args {
		if err := filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			f, err := os.OpenFile(p, os.O_RDWR, 0644)
			if err != nil {
				return errors.Wrapf(err, "open %s", p)
			}
			defer f.Close()

			var host types.Host
			if err := json.NewDecoder(f).Decode(&host); err != nil {
				return errors.Wrapf(err, "decode %s", p)
			}

			hc, ok := c.Hosts[host.Name]
			if !ok {
				return errors.Wrapf(err, "not found %s in %s", host.Name, path)
			}
			host.Config.Detect = &hc.Detect

			host.ScannedCves = nil
			host.DetectError = ""

			if err := detect.Detect(ctx, &host); err != nil {
				host.DetectError = err.Error()
			}

			name := host.Name
			if host.Family != "" && host.Release != "" {
				name = fmt.Sprintf("%s (%s %s)", host.Name, host.Family, host.Release)
			}
			errstr := host.DetectError
			if host.ScanError != "" {
				errstr = fmt.Sprintf("scan error: %s", host.ScanError)
			}

			detectCVEs[name] = result{
				error: errstr,
				nCVEs: len(host.ScannedCves),
			}

			if err := f.Truncate(0); err != nil {
				return errors.Wrap(err, "truncate file")
			}
			if _, err := f.Seek(0, 0); err != nil {
				return errors.Wrap(err, "set offset")
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(host); err != nil {
				return errors.Wrap(err, "encode json")
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", arg)
		}
	}

	fmt.Println("Detect Summary")
	fmt.Println("==============")
	for name, r := range detectCVEs {
		if r.error != "" {
			fmt.Printf("%s : error msg: %s\n", name, r.error)
			continue
		}
		fmt.Printf("%s : success %d CVEs detected\n", name, r.nCVEs)
	}

	return nil
}
