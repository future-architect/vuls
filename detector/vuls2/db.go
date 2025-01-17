package vuls2

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/future-architect/vuls/logging"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	progressbar "github.com/schollz/progressbar/v3"
	"golang.org/x/xerrors"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"

	db "github.com/MaineK00n/vuls2/pkg/db/common"
)

const (
	dbMediaType = "application/vnd.vulsio.vuls.db.layer.v1+zstd"
)

var (
	// DefaultGHCRRepository is GitHub Container Registry for vuls2 db
	DefaultGHCRRepository = "ghcr.io/vulsio/vuls-nightly-db"

	// DefaultPath is the path for vuls2 db file
	DefaultPath = func() string {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "vuls.db")
	}()
)

type Config struct {
	Repository string
	Path       string
	SkipUpdate bool
	Quiet      bool
}

func (c Config) Refresh() error {
	lastModified, fileExists, err := c.loadLastModified()
	if err != nil {
		return xerrors.Errorf("Failed to load vuls2 db metadata. err: %w", err)
	}

	if fileExists && time.Now().Before(lastModified.Add(6*time.Hour)) {
		return nil
	}

	if c.SkipUpdate {
		if !fileExists {
			return xerrors.New("Vuls2 db not found, cannot skip update")
		}
		return nil
	}

	logging.Log.Infof("Downloading vuls2 db. repository: %s", c.Repository)
	if err := c.fetch(c.Repository); err != nil {
		return xerrors.Errorf("Failed to fetch vuls2 db. repository: %s, err: %w", c.Repository, err)
	}

	return nil
}

func (c Config) New() (db.DB, error) {
	vuls2Config := db.Config{
		Type: "boltdb",
		Path: c.Path,
	}

	dbc, err := vuls2Config.New()
	if err != nil {
		return nil, xerrors.Errorf("Failed to new vuls2 db. err: %w", err)
	}

	return dbc, nil
}

func (c Config) fetch(repoPath string) error {
	logging.Log.Infof("Fetch vuls.db from %s", repoPath)

	ctx := context.TODO()

	ms := memory.New()

	repo, err := remote.NewRepository(repoPath)
	if err != nil {
		return xerrors.Errorf("Failed to create repository client. repository: %s, err: %w", repoPath, err)
	}

	manifestDescriptor, err := oras.Copy(ctx, repo, strconv.Itoa(db.SchemaVersion), ms, "", oras.DefaultCopyOptions)
	if err != nil {
		return xerrors.Errorf("Failed to copy. repository: %s, err: %w", repoPath, err)
	}

	r, err := ms.Fetch(ctx, manifestDescriptor)
	if err != nil {
		return xerrors.Errorf("Failed to fetch manifest. err: %w", err)
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(content.NewVerifyReader(r, manifestDescriptor)).Decode(&manifest); err != nil {
		return xerrors.Errorf("Failed to decode manifest. err: %w", err)
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == dbMediaType {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return xerrors.Errorf("Failed to find digest and filename from layers. actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return xerrors.Errorf("Failed to fetch content. err: %w", err)
	}
	defer r.Close()

	d, err := zstd.NewReader(content.NewVerifyReader(r, *l))
	if err != nil {
		return errors.Wrap(err, "new zstd reader")
	}
	defer d.Close()

	if err := os.MkdirAll(filepath.Dir(c.Path), 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(c.Path))
	}

	f, err := os.Create(c.Path)
	if err != nil {
		return xerrors.Errorf("Failed to create. file: %s, err:%w", c.Path, err)
	}
	defer f.Close()

	var pb *progressbar.ProgressBar
	pb = progressbar.DefaultBytesSilent(-1)
	if !c.Quiet {
		pb = progressbar.DefaultBytes(-1, "downloading")
	}
	if _, err := d.WriteTo(io.MultiWriter(f, pb)); err != nil {
		return xerrors.Errorf("Failed to write. filename: %s. err: %w", f.Name(), err)
	}
	_ = pb.Finish()

	return nil
}

func (c Config) loadLastModified() (time.Time, bool, error) {
	if _, err := os.Stat(c.Path); errors.Is(err, os.ErrNotExist) {
		return time.Time{}, false, nil
	}

	conf := db.Config{
		Type: "boltdb",
		Path: c.Path,
	}

	dbc, err := conf.New()
	if err != nil {
		return time.Time{}, false, xerrors.Errorf("Failed to new vuls2 db. path: %s, err: %w", c.Path, err)
	}

	if err := dbc.Open(); err != nil {
		return time.Time{}, false, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", c.Path, err)
	}
	defer func() {
		_ = dbc.Close()
	}()

	metadata, err := dbc.GetMetadata()
	if err != nil {
		return time.Time{}, false, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", c.Path, err)
	}
	if metadata == nil {
		return time.Time{}, false, xerrors.Errorf("Unexpected Vuls2 db metadata. metadata: nil,. path: %s", c.Path)
	}

	if metadata.SchemaVersion != db.SchemaVersion {
		return time.Time{}, false, xerrors.Errorf("Unexpected schema version. expected: %d, actual: %d", db.SchemaVersion, metadata.SchemaVersion)
	}

	return metadata.LastModified, true, nil
}
