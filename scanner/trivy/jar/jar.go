package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/parallel"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJar, newJavaLibraryAnalyzer)
}

const version = 1

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	parallel int
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		parallel: options.Parallel,
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r dio.ReadSeekerAt) (*types.Application, error) {
		p := NewParser(WithSize(info.Size()), WithFilePath(path))
		parsedLibs, err := p.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse %s: %w", path, err)
		}

		return toApplication(types.Jar, path, path, parsedLibs), nil
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	}

	if err := parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult); err != nil {
		return nil, xerrors.Errorf("Failed to Walk dir. err: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func toApplication(fileType types.LangType, filePath, libFilePath string, libs []JarLibrary) *types.Application {
	if len(libs) == 0 {
		return nil
	}

	var pkgs []types.Package
	for _, lib := range libs {
		var licenses []string
		if lib.License != "" {
			licenses = licensing.SplitLicenses(lib.License)
			for i, license := range licenses {
				licenses[i] = licensing.Normalize(strings.TrimSpace(license))
			}
		}

		// This file path is populated for virtual file paths within archives, such as nested JAR files.
		libPath := libFilePath
		if lib.FilePath != "" {
			libPath = lib.FilePath
		}

		newPkg := types.Package{
			ID:       lib.ID,
			Name:     lib.Name,
			Version:  lib.Version,
			Dev:      lib.Dev,
			FilePath: libPath,
			Indirect: lib.Indirect,
			Licenses: licenses,
			Digest:   lib.Digest,
		}
		pkgs = append(pkgs, newPkg)
	}

	return &types.Application{
		Type:      fileType,
		FilePath:  filePath,
		Libraries: pkgs,
	}
}

func (a *javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}
