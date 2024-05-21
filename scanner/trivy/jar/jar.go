package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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
	onFile := func(path string, info fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		p := newParser(withSize(info.Size()), withFilePath(path))
		parsedLibs, err := p.parse(r)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse %s. err: %w", path, err)
		}

		return toApplication(path, parsedLibs), nil
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
		return nil, xerrors.Errorf("Failed to walk dir. err: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func toApplication(rootFilePath string, libs []jarLibrary) *types.Application {
	if len(libs) == 0 {
		return nil
	}

	pkgs := make([]types.Package, 0, len(libs))
	for _, lib := range libs {
		libPath := rootFilePath
		if lib.filePath != "" {
			libPath = lib.filePath
		}

		pkgs = append(pkgs, types.Package{
			Name:     lib.name,
			Version:  lib.version,
			FilePath: libPath,
			Digest:   lib.digest,
		})
	}

	return &types.Application{
		Type:     types.Jar,
		FilePath: rootFilePath,
		Packages: pkgs,
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
