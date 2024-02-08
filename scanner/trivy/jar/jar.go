package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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

type nopClient struct{}

func (c nopClient) Exists(groupID, artifactID string) (bool, error) {
	return true, nil
}

func (c nopClient) SearchBySHA1(sha1 string) (jar.Properties, error) {
	return jar.Properties{}, jar.ArtifactNotFoundErr
}

func (c nopClient) SearchByArtifactID(artifactID, version string) (string, error) {
	return "", jar.ArtifactNotFoundErr
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
	client := nopClient{}

	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r dio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(client, jar.WithSize(info.Size()), jar.WithFilePath(path))
		res, err := language.ParsePackage(types.Jar, path, r, p, input.Options.FileChecksum)
		if res != nil || err != nil {
			return res, err
		}

		// go-dep-parser's jar.go returns nil result if it could not find infomation from pom/manifest/filename.
		// To defer vuls's decision until report/detect phase, add one application only with file path.
		return &types.Application{
			Type:      types.Jar,
			FilePath:  path,
			Libraries: []types.Package{{FilePath: path}},
		}, nil
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
		return nil, xerrors.Errorf("walk dir error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
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
