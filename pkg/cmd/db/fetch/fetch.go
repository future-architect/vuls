package fetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

type DBFetchOption struct {
	Path      string
	PlainHTTP bool
}

const (
	defaultVulsDBRepository = "ghcr.io/mainek00n/vuls-data/vuls-db"
	defaultTag              = "latest"
	vulsDBConfigMediaType   = "application/vnd.vuls.vuls.db"
	vulsDBLayerMediaType    = "application/vnd.vuls.vuls.db.layer.v1.tar+gzip"
)

func NewCmdFetch() *cobra.Command {
	opts := &DBFetchOption{
		Path: "vuls.db",
	}

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch Vuls DB",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := defaultVulsDBRepository
			if len(args) > 0 {
				p = args[0]
			}
			return fetch(context.Background(), p, opts.Path, opts.PlainHTTP)
		},
		Example: heredoc.Doc(`
			$ vuls db fetch
			$ vuls db fetch ghcr.io/vuls/db
		`),
	}

	cmd.Flags().StringVarP(&opts.Path, "path", "p", "vuls.db", "path to fetch Vuls DB")
	cmd.Flags().BoolVarP(&opts.PlainHTTP, "plain-http", "", false, "container registry is provided with plain http")

	return cmd
}

func fetch(ctx context.Context, ref, dbpath string, plainHTTP bool) error {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return errors.WithStack(err)
	}
	if plainHTTP {
		repo.PlainHTTP = true
	}

	desc, err := repo.Resolve(ctx, defaultTag)
	if err != nil {
		return errors.WithStack(err)
	}
	pulledBlob, err := content.FetchAll(ctx, repo, desc)
	if err != nil {
		return errors.WithStack(err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(pulledBlob, &manifest); err != nil {
		return errors.WithStack(err)
	}

	if manifest.Config.MediaType != vulsDBConfigMediaType {
		return errors.New("not vuls repository")
	}

	for _, l := range manifest.Layers {
		if l.MediaType != vulsDBLayerMediaType {
			continue
		}

		desc, err := repo.Blobs().Resolve(ctx, l.Digest.String())
		if err != nil {
			return errors.WithStack(err)
		}
		rc, err := repo.Fetch(ctx, desc)
		if err != nil {
			return errors.WithStack(err)
		}
		defer rc.Close()

		bs, err := content.ReadAll(rc, desc)
		if err != nil {
			return errors.WithStack(err)
		}

		gr, err := gzip.NewReader(bytes.NewReader(bs))
		if err != nil {
			return errors.WithStack(err)
		}
		defer gr.Close()

		tr := tar.NewReader(gr)
		for {
			header, err := tr.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrap(err, "Next()")
			}

			switch header.Typeflag {
			case tar.TypeDir:
				if err := os.MkdirAll(filepath.Join(dbpath, header.Name), header.FileInfo().Mode()); err != nil {
					return errors.WithStack(err)
				}
			case tar.TypeReg:
				if err := func() error {
					f, err := os.OpenFile(dbpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
					if err != nil {
						return errors.WithStack(err)
					}
					defer f.Close()

					if _, err := io.Copy(f, tr); err != nil {
						return errors.WithStack(err)
					}

					return nil
				}(); err != nil {
					return err
				}
			default:
				return errors.Errorf("unknown type: %s in %s", header.Typeflag, header.Name)
			}
		}
	}

	return nil
}
