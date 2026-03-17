package jar

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"golang.org/x/xerrors"
)

// ParseJAR parses a JAR/WAR/EAR/PAR file and returns the detected libraries.
func ParseJAR(filePath string, r xio.ReadSeekerAt) (*types.Application, error) {
	size, err := r.Seek(0, 2) // seek to end to get size
	if err != nil {
		return nil, xerrors.Errorf("Failed to get size of %s: %w", filePath, err)
	}
	if _, err := r.Seek(0, 0); err != nil { // seek back to start
		return nil, xerrors.Errorf("Failed to seek %s: %w", filePath, err)
	}

	p := newParser(withSize(size), withFilePath(filePath))
	libs, err := p.parse(r)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse %s: %w", filePath, err)
	}
	return toApplication(filePath, libs), nil
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
