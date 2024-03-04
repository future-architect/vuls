//go:build !scanner
// +build !scanner

package javadb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

func UpdateJavaDB(trivyOpts config.TrivyOpts, noProgress bool) error {
	repo := fmt.Sprintf("%s:%d", trivyOpts.TrivyJavaDBRepository, db.SchemaVersion)
	dbDir := filepath.Join(trivyOpts.TrivyCacheDBDir, "java-db")

	metac := db.NewMetadata(dbDir)
	meta, err := metac.Get()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return xerrors.Errorf("Failed to get Java DB metadata. err: %w", err)
		} else if trivyOpts.TrivySkipJavaDBUpdate {
			logging.Log.Error("Could not skip, the first run cannot skip downloading Java DB")
			return xerrors.New("'--skip-java-db-update' cannot be specified on the first run")
		}
	}

	if (meta.Version != db.SchemaVersion || meta.NextUpdate.Before(time.Now().UTC())) && !trivyOpts.TrivySkipJavaDBUpdate {
		// Download DB
		logging.Log.Infof("Trivy Java DB Repository: %s", repo)
		logging.Log.Info("Downloading Trivy Java DB...")

		var a *oci.Artifact
		if a, err = oci.NewArtifact(repo, noProgress, types.RegistryOptions{}); err != nil {
			return xerrors.Errorf("oci error: %w", err)
		}
		if err = a.Download(context.Background(), dbDir, oci.DownloadOption{MediaType: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"}); err != nil {
			return xerrors.Errorf("Failed to download Trivy Java DB. err: %w", err)
		}

		// Parse the newly downloaded metadata.json
		meta, err = metac.Get()
		if err != nil {
			return xerrors.Errorf("Failed to get Trivy Java DB metadata. err: %w", err)
		}

		// Update DownloadedAt
		meta.DownloadedAt = time.Now().UTC()
		if err = metac.Update(meta); err != nil {
			return xerrors.Errorf("Failed to update Trivy Java DB metadata. erro: %w", err)
		}
	}

	return nil
}

type DBClient struct {
	driver db.DB
}

func NewClient(cacheDBDir string) (*DBClient, error) {
	driver, err := db.New(filepath.Join(cacheDBDir, "java-db"))
	if err != nil {
		return nil, xerrors.Errorf("Failed to open Trivy Java DB. err: %w", err)
	}
	return &DBClient{driver: driver}, nil
}

func (client *DBClient) Close() error {
	if client == nil {
		return nil
	}

	return client.driver.Close()
}

func (client *DBClient) SearchBySHA1(sha1 string) (jar.Properties, error) {
	index, err := client.driver.SelectIndexBySha1(sha1)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("Failed to select from Trivy Java DB. err: %w", err)
	} else if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}, nil
}
