//go:build !scanner

// Package javadb implements functions that wrap trivy-java-db module.
package javadb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyjavadb "github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// DefaultTrivyJavaDBRepositories is the official repositories of Trivy Java DB
var DefaultTrivyJavaDBRepositories = []string{trivyjavadb.DefaultGCRRepository, trivyjavadb.DefaultGHCRRepository}

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

	if trivyOpts.TrivySkipJavaDBUpdate {
		return nil
	}
	if meta.Version == db.SchemaVersion && isNewDB(meta) {
		return nil
	}

	// Download DB
	if len(trivyOpts.TrivyJavaDBRepositories) == 0 {
		trivyOpts.TrivyJavaDBRepositories = DefaultTrivyJavaDBRepositories
	}
	logging.Log.Infof("Trivy Java DB Repository: %s", strings.Join(trivyOpts.TrivyJavaDBRepositories, ", "))
	logging.Log.Info("Downloading Trivy Java DB...")

	refs := make([]name.Reference, 0, len(trivyOpts.TrivyJavaDBRepositories))
	for _, repo := range trivyOpts.TrivyJavaDBRepositories {
		ref, err := func() (name.Reference, error) {
			ref, err := name.ParseReference(repo, name.WithDefaultTag(""))
			if err != nil {
				return nil, err
			}

			// Add the schema version if the tag is not specified for backward compatibility.
			t, ok := ref.(name.Tag)
			if !ok || t.TagStr() != "" {
				return ref, nil
			}

			ref = t.Tag(fmt.Sprint(trivyjavadb.SchemaVersion))
			logging.Log.Infof("Adding schema version to the DB repository for backward compatibility. repository: %s", ref.String())

			return ref, nil
		}()
		if err != nil {
			return xerrors.Errorf("invalid javadb repository: %w", err)
		}
		refs = append(refs, ref)
	}

	a := oci.NewArtifacts(refs, types.RegistryOptions{})

	if err = a.Download(context.Background(), dbDir, oci.DownloadOption{
		MediaType: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
		Quiet:     noProgress,
	}); err != nil {
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

	return nil
}

func isNewDB(meta db.Metadata) bool {
	now := time.Now().UTC()
	if now.Before(meta.NextUpdate) {
		logging.Log.Debug("Java DB update was skipped because the local Java DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour * 24)) { // 1 day
		logging.Log.Debug("Java DB update was skipped because the local Java DB was downloaded during the last day")
		return true
	}
	return false
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
