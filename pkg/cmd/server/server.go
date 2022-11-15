package server

import (
	"context"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/future-architect/vuls/pkg/config"
	"github.com/future-architect/vuls/pkg/log"
	"github.com/future-architect/vuls/pkg/server"
)

type Serveroptions struct {
	Config string
}

func NewCmdServer() *cobra.Command {
	opts := &Serveroptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Vuls start server mode",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := exec(context.Background(), opts.Config); err != nil {
				return errors.Wrap(err, "failed to server")
			}
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls server
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}

func exec(ctx context.Context, path string) error {
	logger, err := zap.NewProduction()
	if err != nil {
		return errors.Wrap(err, "create logger")
	}

	ctx = log.ContextWithLogger(ctx, logger)

	c, err := config.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s as config", path)
	}

	if c.Server == nil {
		pwd, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err, "get working directory")
		}

		c.Server = &config.Server{
			Listen: "127.0.0.1:5515",
			Path:   filepath.Join(pwd, "vuls.db"),
		}
	}

	e := echo.New()
	e.POST("/scan", server.Scan())
	e.POST("/detect", server.Detect(c.Server.Path))

	return e.Start(c.Server.Listen)
}
