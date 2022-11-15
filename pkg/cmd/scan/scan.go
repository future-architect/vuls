package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"

	"github.com/future-architect/vuls/pkg/config"
	"github.com/future-architect/vuls/pkg/log"
	"github.com/future-architect/vuls/pkg/scan"
	"github.com/future-architect/vuls/pkg/types"
)

type ScanOptions struct {
	Config string
}

func NewCmdScan() *cobra.Command {
	opts := &ScanOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "scan ([\"host\"])",
		Short: "Vuls scan your machine information",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exec(context.Background(), opts.Config, args); err != nil {
				return errors.Wrap(err, "failed to scan")
			}
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls scan
			$ vuls scan host
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

	hosts := []types.Host{}
	targets := args
	if len(args) == 0 {
		targets = maps.Keys(c.Hosts)
	}
	for _, t := range targets {
		h, ok := c.Hosts[t]
		if !ok {
			return errors.Errorf("host %s is not defined in config %s", t, path)
		}

		hosts = append(hosts, types.Host{
			Name: t,
			Config: types.Config{
				Type:      h.Type,
				Host:      h.Host,
				Port:      h.Port,
				User:      h.User,
				SSHConfig: h.SSHConfig,
				SSHKey:    h.SSHKey,
				Scan:      &h.Scan,
			},
		})
	}

	for i := range hosts {
		if err := scan.Scan(ctx, &hosts[i]); err != nil {
			hosts[i].ScanError = err.Error()
		}
	}

	now := time.Now()
	for _, h := range hosts {
		if err := func() error {
			resultDir := filepath.Join(h.Config.Scan.ResultDir, now.Format("2006-01-02T150405-0700"))
			if err := os.MkdirAll(resultDir, os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", resultDir)
			}
			f, err := os.Create(filepath.Join(resultDir, fmt.Sprintf("%s.json", h.Name)))
			if err != nil {
				return errors.Wrapf(err, "create %s", filepath.Join(resultDir, fmt.Sprintf("%s.json", h.Name)))
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(h); err != nil {
				return errors.Wrapf(err, "encode %s result", h.Name)
			}

			return nil
		}(); err != nil {
			return errors.Wrapf(err, "write %s result", h.Name)
		}
	}

	fmt.Println("Scan Summary")
	fmt.Println("============")
	for _, h := range hosts {
		name := h.Name
		if h.Family != "" && h.Release != "" {
			name = fmt.Sprintf("%s (%s %s)", h.Name, h.Family, h.Release)
		}
		if h.ScanError != "" {
			fmt.Printf("%s : error msg: %s\n", name, h.ScanError)
			continue
		}
		fmt.Printf("%s: success ospkg: %d, cpe: %d, KB %d installed\n", name, len(h.Packages.OSPkg), len(h.Packages.CPE), len(h.Packages.KB))
	}

	return nil
}
