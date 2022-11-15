package cpe

import (
	"context"
	"fmt"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	scanTypes "github.com/future-architect/vuls/pkg/scan/types"
	"github.com/future-architect/vuls/pkg/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "cpe analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *scanTypes.AnalyzerHost) error {
	ah.Host.Packages.CPE = map[string]types.CPE{}
	for _, c := range ah.Host.Config.Scan.CPE {
		if _, err := naming.UnbindFS(c.CPE); err != nil {
			return errors.Wrapf(err, "unbind %s", c.CPE)
		}
		key := c.CPE

		if c.RunningOn != "" {
			if _, err := naming.UnbindFS(c.RunningOn); err != nil {
				return errors.Wrapf(err, "unbind %s", c.RunningOn)
			}
			key = fmt.Sprintf("%s_on_%s", c.CPE, c.RunningOn)
		}

		ah.Host.Packages.CPE[key] = types.CPE{
			CPE:       c.CPE,
			RunningOn: c.RunningOn,
		}

	}

	return nil
}
