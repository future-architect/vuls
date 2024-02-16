package models

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy-db/pkg/db"
	trivyDBTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	tlog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// LibraryScanners is an array of LibraryScanner
type LibraryScanners []LibraryScanner

// Find : find by name
func (lss LibraryScanners) Find(path, name string) map[string]Library {
	filtered := map[string]Library{}
	for _, ls := range lss {
		for _, lib := range ls.Libs {
			if ls.LockfilePath == path && lib.Name == name {
				filtered[ls.LockfilePath] = lib
				break
			}
		}
	}
	return filtered
}

// Total returns total count of pkgs
func (lss LibraryScanners) Total() (total int) {
	for _, lib := range lss {
		total += len(lib.Libs)
	}
	return
}

// LibraryScanner has libraries information
type LibraryScanner struct {
	Type ftypes.LangType
	Libs []Library

	// The path to the Lockfile is stored.
	LockfilePath string `json:"path,omitempty"`
}

// Library holds the attribute of a package library
type Library struct {
	Name    string
	Version string

	// The Path to the library in the container image. Empty string when Lockfile scan.
	// This field is used to convert the result JSON of a `trivy image` using trivy-to-vuls.
	FilePath string
	Digest   string
}

func trivyInit() error {
	if err := tlog.InitLogger(config.Conf.Debug, config.Conf.Quiet); err != nil {
		return xerrors.Errorf("Failed to init trivy logger. err: %w", err)
	}

	javadb.Init(config.Conf.TrivyCacheDBDir, config.Conf.TrivyJavaDBRepository, config.Conf.TrivySkipJavaDBUpdate, config.Conf.Quiet, ftypes.RegistryOptions{})
	return nil
}

var trivyInitOnce = sync.OnceValue(trivyInit)

func trivyInitJavaDB() error {
	javadb.Init(config.Conf.TrivyCacheDBDir, config.Conf.TrivyJavaDBRepository, config.Conf.TrivySkipJavaDBUpdate, config.Conf.Quiet, ftypes.RegistryOptions{})

	javaDBClient, err := javadb.NewClient()
	if err != nil {
		return xerrors.Errorf("Failed to init trivy Java DB. err: %w", err)
	}
	javaDB = *javaDBClient
	return nil
}

var trivyInitJavaDBOnce = sync.OnceValue(trivyInitJavaDB)

var javaDB javadb.DB

// Scan : scan target library
func (s LibraryScanner) Scan() ([]VulnInfo, error) {
	if err := trivyInitOnce(); err != nil {
		return nil, xerrors.Errorf("Failed to init Trivy. err: %w", err)
	}

	if s.Type == ftypes.Jar {
		if err := s.refineJARInfo(); err != nil {
			return nil, xerrors.Errorf("Failed to init Trivy's Java DB. err: %w", err)
		}

	}
	scanner, ok := library.NewDriver(s.Type)
	if !ok {
		return nil, xerrors.Errorf("Failed to new a library driver for %s", s.Type)
	}
	var vulnerabilities = []VulnInfo{}
	for _, pkg := range s.Libs {
		tvulns, err := scanner.DetectVulnerabilities("", pkg.Name, pkg.Version)
		if err != nil {
			return nil, xerrors.Errorf("Failed to detect %s vulnerabilities. err: %w", scanner.Type(), err)
		}
		if len(tvulns) == 0 {
			continue
		}

		vulns := s.convertFanalToVuln(tvulns)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

func (s *LibraryScanner) refineJARInfo() error {
	if err := trivyInitJavaDBOnce(); err != nil {
		return xerrors.Errorf("Failed to init Trivy Java DB. err: %w", err)
	}

	libs := make([]Library, 0, len(s.Libs))

	for _, l := range s.Libs {
		if l.Digest == "" {
			// This is the case from pom.properties, it should be respected as is.
			libs = append(libs, l)
			continue
		}

		algorithm, sha1, found := strings.Cut(l.Digest, ":")
		if !found || algorithm != "sha1" {
			logging.Log.Debugf("No SHA1 hash found for %s in the digest: %q", l.FilePath, l.Digest)
			libs = append(libs, l)
			continue
		}

		foundProps, err := javaDB.SearchBySHA1(sha1)
		if err != nil {
			if !errors.Is(err, jar.ArtifactNotFoundErr) {
				return xerrors.Errorf("Failed to search Trivy's Java DB. err: %w", err)
			}

			logging.Log.Debugf("No record in Java DB for %s by SHA1: %s", l.FilePath, sha1)
			libs = append(libs, l)
			continue
		}

		foundLib := foundProps.Library()
		l.Name = foundLib.Name
		l.Version = foundLib.Version
		libs = append(libs, l)
	}

	libs = lo.UniqBy(libs, func(lib Library) string {
		return fmt.Sprintf("%s::%s::%s", lib.Name, lib.Version, lib.FilePath)
	})

	s.Libs = libs
	return nil
}

func (s LibraryScanner) convertFanalToVuln(tvulns []types.DetectedVulnerability) (vulns []VulnInfo) {
	for _, tvuln := range tvulns {
		vinfo, err := s.getVulnDetail(tvuln)
		if err != nil {
			logging.Log.Debugf("failed to getVulnDetail. err: %+v, tvuln: %#v", err, tvuln)
			continue
		}
		vulns = append(vulns, vinfo)
	}
	return vulns
}

func (s LibraryScanner) getVulnDetail(tvuln types.DetectedVulnerability) (vinfo VulnInfo, err error) {
	vul, err := db.Config{}.GetVulnerability(tvuln.VulnerabilityID)
	if err != nil {
		return vinfo, err
	}

	vinfo.CveID = tvuln.VulnerabilityID
	vinfo.CveContents = getCveContents(tvuln.VulnerabilityID, vul)
	vinfo.LibraryFixedIns = []LibraryFixedIn{
		{
			Key:     s.GetLibraryKey(),
			Name:    tvuln.PkgName,
			FixedIn: tvuln.FixedVersion,
			Path:    s.LockfilePath,
		},
	}
	return vinfo, nil
}

func getCveContents(cveID string, vul trivyDBTypes.Vulnerability) (contents map[CveContentType][]CveContent) {
	contents = map[CveContentType][]CveContent{}
	refs := []Reference{}
	for _, refURL := range vul.References {
		refs = append(refs, Reference{Source: "trivy", Link: refURL})
	}

	contents[Trivy] = []CveContent{
		{
			Type:          Trivy,
			CveID:         cveID,
			Title:         vul.Title,
			Summary:       vul.Description,
			Cvss3Severity: string(vul.Severity),
			References:    refs,
		},
	}
	return contents
}

// FindLockFiles is a list of filenames that is the target of findLock
var FindLockFiles = []string{
	// dart/pub
	ftypes.PubSpecLock,
	// elixir/mix
	ftypes.MixLock,
	// node
	ftypes.NpmPkgLock, ftypes.YarnLock, ftypes.PnpmLock,
	// ruby
	ftypes.GemfileLock, "*.gemspec",
	// rust
	ftypes.CargoLock,
	// php
	ftypes.ComposerLock,
	// python
	ftypes.PipRequirements, ftypes.PipfileLock, ftypes.PoetryLock,
	// .net
	ftypes.NuGetPkgsLock, ftypes.NuGetPkgsConfig, "*.deps.json", "*Packages.props",
	// gomod
	ftypes.GoMod, ftypes.GoSum,
	// java
	ftypes.MavenPom, "*.jar", "*.war", "*.ear", "*.par", "*gradle.lockfile",
	// C / C++
	ftypes.ConanLock,
	// Swift
	ftypes.CocoaPodsLock, ftypes.SwiftResolved,
}

// GetLibraryKey returns target library key
func (s LibraryScanner) GetLibraryKey() string {
	switch s.Type {
	case ftypes.Bundler, ftypes.GemSpec:
		return "ruby"
	case ftypes.Cargo, ftypes.RustBinary:
		return "rust"
	case ftypes.Composer:
		return "php"
	case ftypes.GoBinary, ftypes.GoModule:
		return "gomod"
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle:
		return "java"
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.NodePkg, ftypes.JavaScript:
		return "node"
	case ftypes.NuGet, ftypes.DotNetCore:
		return ".net"
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg:
		return "python"
	case ftypes.Conan:
		return "c"
	case ftypes.Pub:
		return "dart"
	case ftypes.Hex:
		return "elixir"
	case ftypes.Swift, ftypes.Cocoapods:
		return "swift"
	default:
		return ""
	}
}

// LibraryFixedIn has library fixed information
type LibraryFixedIn struct {
	Key     string `json:"key,omitempty"`
	Name    string `json:"name,omitempty"`
	FixedIn string `json:"fixedIn,omitempty"`
	Path    string `json:"path,omitempty"`
}
