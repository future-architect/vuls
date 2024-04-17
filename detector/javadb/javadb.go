//go:build !scanner
// +build !scanner

// Package javadb implements functions that wrap trivy-java-db module.
package javadb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// UpdateJavaDB updates Trivy Java DB
func UpdateJavaDB(trivyOpts config.TrivyOpts, noProgress bool) error {
	dbDir := filepath.Join(trivyOpts.TrivyCacheDBDir, "java-db")

	metac := db.NewMetadata(dbDir)
	meta, err := metac.Get()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return xerrors.Errorf("Failed to get Java DB metadata. err: %w", err)
		}
		if trivyOpts.TrivySkipJavaDBUpdate {
			logging.Log.Error("Could not skip, the first run cannot skip downloading Java DB")
			return xerrors.New("'--trivy-skip-java-db-update' cannot be specified on the first run")
		}
	}

	if (meta.Version != db.SchemaVersion || meta.NextUpdate.Before(time.Now().UTC())) && !trivyOpts.TrivySkipJavaDBUpdate {
		// Download DB
		logging.Log.Infof("Trivy Java DB Repository: %s", trivyOpts.TrivyJavaDBRepository)
		logging.Log.Info("Downloading Trivy Java DB...")

		var a *oci.Artifact
		if a, err = oci.NewArtifact(trivyOpts.TrivyJavaDBRepository, noProgress, types.RegistryOptions{}); err != nil {
			return xerrors.Errorf("Failed to new oci artifact. err: %w", err)
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
			return xerrors.Errorf("Failed to update Trivy Java DB metadata. err: %w", err)
		}
	}

	return nil
}

// DBClient is Trivy Java DB Client
type DBClient struct {
	driver db.DB
}

// NewClient returns Trivy Java DB Client
func NewClient(cacheDBDir string) (*DBClient, error) {
	driver, err := db.New(filepath.Join(cacheDBDir, "java-db"))
	if err != nil {
		return nil, xerrors.Errorf("Failed to open Trivy Java DB. err: %w", err)
	}
	return &DBClient{driver: driver}, nil
}

// Close closes Trivy Java DB Client
func (client *DBClient) Close() error {
	if client == nil {
		return nil
	}

	return client.driver.Close()
}

// SearchBySHA1 searches Jar Property by SHA1
func (client *DBClient) SearchBySHA1(sha1 string) (jar.Properties, error) {
	index, err := client.driver.SelectIndexBySha1(sha1)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("Failed to select from Trivy Java DB. err: %w", err)
	}
	if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("Failed to search ArtifactID by digest %s. err: %w", sha1, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}, nil
}
