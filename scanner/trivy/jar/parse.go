package jar

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).[jwep]ar$`)
)

type jarLibrary struct {
	id       string
	name     string
	version  string
	filePath string
	// SHA1 hash for later use at detect phase.
	// When this record has come from pom.properties, no Java DB look up needed and this field must be left empty.
	digest digest.Digest
}

type properties struct {
	groupID    string
	artifactID string
	version    string
	filePath   string // path to file containing these props
	digest     digest.Digest
}

func (p properties) library() jarLibrary {
	return jarLibrary{
		name:     fmt.Sprintf("%s:%s", p.groupID, p.artifactID),
		version:  p.version,
		filePath: p.filePath,
		digest:   p.digest,
	}
}

func (p properties) valid() bool {
	return p.groupID != "" && p.artifactID != "" && p.version != ""
}

func (p properties) string() string {
	return fmt.Sprintf("%s:%s:%s", p.groupID, p.artifactID, p.version)
}

type parser struct {
	rootFilePath string
	size         int64
}

type option func(*parser)

func withFilePath(filePath string) option {
	return func(p *parser) {
		p.rootFilePath = filePath
	}
}

func withSize(size int64) option {
	return func(p *parser) {
		p.size = size
	}
}

func newParser(opts ...option) *parser {
	p := &parser{}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *parser) parse(r xio.ReadSeekerAt) ([]jarLibrary, error) {
	libs, err := p.parseArtifact(p.rootFilePath, p.size, r)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse %s. err: %w", p.rootFilePath, err)
	}
	return removeLibraryDuplicates(libs), nil
}

// This function MUST NOT return empty list unless an error occurred.
// The least element contains file path and SHA1 digest, they can be used at detect phase to
// determine actual name and version.
func (p *parser) parseArtifact(filePath string, size int64, r xio.ReadSeekerAt) ([]jarLibrary, error) {
	log.Debug("Parsing Java artifacts...", log.String("file", filePath))

	sha1, err := digest.CalcSHA1(r)
	if err != nil {
		return nil, xerrors.Errorf("Failed to calculate SHA1. err: %w", err)
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("Failed to open zip. err: %w", err)
	}

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileProps := parseFileName(filePath, sha1)

	var libs []jarLibrary
	var m manifest
	var foundPomProps bool

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar, filePath)
			if err != nil {
				return nil, xerrors.Errorf("Failed to parse %s. err: %w", fileInJar.Name, err)
			}
			libs = append(libs, props.library())

			// Check if the pom.properties is for the original JAR/WAR/EAR
			if fileProps.artifactID == props.artifactID && fileProps.version == props.version {
				foundPomProps = true
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("Failed to parse MANIFEST.MF. err: %w", err)
			}
		case isArtifact(fileInJar.Name):
			innerLibs, err := p.parseInnerJar(fileInJar, filePath) //TODO process inner deps
			if err != nil {
				log.Debugf("Failed to parse %s. err: %s", fileInJar.Name, err)
				continue
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if foundPomProps {
		return libs, nil
	}

	manifestProps := m.properties(filePath, sha1)
	if manifestProps.valid() {
		return append(libs, manifestProps.library()), nil
	}

	// At this point, no library information from pom nor manifests.
	// Add one from fileProps, which may have no artifact ID or version, but it will be
	// rescued at detect phase by SHA1.
	return append(libs, fileProps.library()), nil
}

func (p *parser) parseInnerJar(zf *zip.File, rootPath string) ([]jarLibrary, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, xerrors.Errorf("Failed to open file %s. err: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner-*")
	if err != nil {
		return nil, xerrors.Errorf("Failed to create tmp file for %s. err: %w", zf.Name, err)
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	// Copy the file content to the temp file and rewind it at the beginning
	if _, err = io.Copy(f, fr); err != nil {
		return nil, xerrors.Errorf("Failed to copy file %s. err: %w", zf.Name, err)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("Failed to seek file %s. err: %w", zf.Name, err)
	}

	// build full path to inner jar
	fullPath := path.Join(rootPath, zf.Name)

	// Parse jar/war/ear recursively
	innerLibs, err := p.parseArtifact(fullPath, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse file %s. err: %w", zf.Name, err)
	}

	return innerLibs, nil
}

func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

func parseFileName(filePath string, sha1 digest.Digest) properties {
	fileName := filepath.Base(filePath)
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return properties{
			filePath: filePath,
			digest:   sha1,
		}
	}

	return properties{
		artifactID: packageVersion[1],
		version:    packageVersion[2],
		filePath:   filePath,
		digest:     sha1,
	}
}

func parsePomProperties(f *zip.File, filePath string) (properties, error) {
	file, err := f.Open()
	if err != nil {
		return properties{}, xerrors.Errorf("Failed to open pom.properties. err: %w", err)
	}
	defer file.Close()

	p := properties{
		filePath: filePath,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.groupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.artifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return properties{}, xerrors.Errorf("Failed to scan %s. err: %w", f.Name, err)
	}
	return p, nil
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendor   string
	implementationVendorID string
	specificationTitle     string
	specificationVersion   string
	specificationVendor    string
	bundleName             string
	bundleVersion          string
	bundleSymbolicName     string
}

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, xerrors.Errorf("Failed to open MANIFEST.MF. err: %w", err)
	}
	defer file.Close()

	var m manifest
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip variables. e.g. Bundle-Name: %bundleName
		ss := strings.Fields(line)
		if len(ss) <= 1 || (len(ss) > 1 && strings.HasPrefix(ss[1], "%")) {
			continue
		}

		// It is not determined which fields are present in each application.
		// In some cases, none of them are included, in which case they cannot be detected.
		switch {
		case strings.HasPrefix(line, "Implementation-Version:"):
			m.implementationVersion = strings.TrimPrefix(line, "Implementation-Version:")
		case strings.HasPrefix(line, "Implementation-Title:"):
			m.implementationTitle = strings.TrimPrefix(line, "Implementation-Title:")
		case strings.HasPrefix(line, "Implementation-Vendor:"):
			m.implementationVendor = strings.TrimPrefix(line, "Implementation-Vendor:")
		case strings.HasPrefix(line, "Implementation-Vendor-Id:"):
			m.implementationVendorID = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
		case strings.HasPrefix(line, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(line, "Specification-Version:")
		case strings.HasPrefix(line, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(line, "Specification-Title:")
		case strings.HasPrefix(line, "Specification-Vendor:"):
			m.specificationVendor = strings.TrimPrefix(line, "Specification-Vendor:")
		case strings.HasPrefix(line, "Bundle-Version:"):
			m.bundleVersion = strings.TrimPrefix(line, "Bundle-Version:")
		case strings.HasPrefix(line, "Bundle-Name:"):
			m.bundleName = strings.TrimPrefix(line, "Bundle-Name:")
		case strings.HasPrefix(line, "Bundle-SymbolicName:"):
			m.bundleSymbolicName = strings.TrimPrefix(line, "Bundle-SymbolicName:")
		}
	}

	if err = scanner.Err(); err != nil {
		return manifest{}, xerrors.Errorf("Failed to scan %s. err: %w", f.Name, err)
	}
	return m, nil
}

func (m manifest) properties(filePath string, sha1 digest.Digest) properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return properties{}
	}

	return properties{
		groupID:    groupID,
		artifactID: artifactID,
		version:    version,
		filePath:   filePath,
		digest:     sha1,
	}
}

func (m manifest) determineGroupID() (string, error) {
	var groupID string
	switch {
	case m.implementationVendorID != "":
		groupID = m.implementationVendorID
	case m.bundleSymbolicName != "":
		groupID = m.bundleSymbolicName

		// e.g. "com.fasterxml.jackson.core.jackson-databind" => "com.fasterxml.jackson.core"
		idx := strings.LastIndex(m.bundleSymbolicName, ".")
		if idx > 0 {
			groupID = m.bundleSymbolicName[:idx]
		}
	case m.implementationVendor != "":
		groupID = m.implementationVendor
	case m.specificationVendor != "":
		groupID = m.specificationVendor
	default:
		return "", xerrors.New("No groupID found")
	}
	return strings.TrimSpace(groupID), nil
}

func (m manifest) determineArtifactID() (string, error) {
	var artifactID string
	switch {
	case m.implementationTitle != "":
		artifactID = m.implementationTitle
	case m.specificationTitle != "":
		artifactID = m.specificationTitle
	case m.bundleName != "":
		artifactID = m.bundleName
	default:
		return "", xerrors.New("No artifactID found")
	}
	return strings.TrimSpace(artifactID), nil
}

func (m manifest) determineVersion() (string, error) {
	var version string
	switch {
	case m.implementationVersion != "":
		version = m.implementationVersion
	case m.specificationVersion != "":
		version = m.specificationVersion
	case m.bundleVersion != "":
		version = m.bundleVersion
	default:
		return "", xerrors.New("No version found")
	}
	return strings.TrimSpace(version), nil
}

func removeLibraryDuplicates(libs []jarLibrary) []jarLibrary {
	return lo.UniqBy(libs, func(lib jarLibrary) string {
		return fmt.Sprintf("%s::%s::%s", lib.name, lib.version, lib.filePath)
	})
}
