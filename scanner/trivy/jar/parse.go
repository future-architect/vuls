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

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)
)

type JarLibrary struct {
	ID       string `json:",omitempty"`
	Name     string
	Version  string
	Dev      bool
	Indirect bool   `json:",omitempty"`
	License  string `json:",omitempty"`
	FilePath string `json:",omitempty"` // Required to show nested jars
	Digest   digest.Digest
}

// TODO(shino): make this private
type Properties struct {
	GroupID    string
	ArtifactID string
	Version    string
	FilePath   string // path to file containing these props
	Digest     digest.Digest
}

func (p Properties) Library(hash digest.Digest) JarLibrary {
	return JarLibrary{
		Name:     fmt.Sprintf("%s:%s", p.GroupID, p.ArtifactID),
		Version:  p.Version,
		FilePath: p.FilePath,
		Digest:   hash,
	}
}

func (p Properties) Valid() bool {
	return p.GroupID != "" && p.ArtifactID != "" && p.Version != ""
}

func (p Properties) String() string {
	return fmt.Sprintf("%s:%s:%s", p.GroupID, p.ArtifactID, p.Version)
}

type Parser struct {
	rootFilePath string
	offline      bool
	size         int64
}

type Option func(*Parser)

func WithFilePath(filePath string) Option {
	return func(p *Parser) {
		p.rootFilePath = filePath
	}
}

func WithOffline(offline bool) Option {
	return func(p *Parser) {
		p.offline = offline
	}
}

func WithSize(size int64) Option {
	return func(p *Parser) {
		p.size = size
	}
}

func NewParser(opts ...Option) *Parser {
	fmt.Printf("foo: %+v\n", "foo")
	p := &Parser{}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]JarLibrary, error) {
	libs, err := p.parseArtifact(p.rootFilePath, p.size, r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", p.rootFilePath, err)
	}
	return removeLibraryDuplicates(libs), nil
}

// This function MUST NOT return empty list unless error occured.
// The least element has file path and SHA1 digest, it will be utilized at detect phase.
func (p *Parser) parseArtifact(filePath string, size int64, r dio.ReadSeekerAt) ([]JarLibrary, error) {
	log.Logger.Debugw("Parsing Java artifacts...", zap.String("file", filePath))

	//  TODO(shino): Calculate!
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
	fileProps := parseFileName(filePath)

	var libs []JarLibrary
	var m manifest
	var foundPomProps bool

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar, filePath)
			if err != nil {
				return nil, xerrors.Errorf("Failed to parse %s. err: %w", fileInJar.Name, err)
			}
			libs = append(libs, props.Library(sha1))

			// Check if the pom.properties is for the original JAR/WAR/EAR
			if fileProps.ArtifactID == props.ArtifactID && fileProps.Version == props.Version {
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
				log.Logger.Debugf("Failed to parse %s. err: %s", fileInJar.Name, err)
				continue
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if foundPomProps {
		return libs, nil
	}

	manifestProps := m.properties(filePath)
	if manifestProps.Valid() {
		return append(libs, manifestProps.Library(sha1)), nil
	}

	// Return when artifactId or version from the file name are empty
	if fileProps.ArtifactID == "" || fileProps.Version == "" {
		if len(libs) == 0 {
			return []JarLibrary{{FilePath: filePath, Digest: sha1}}, nil
		}
		return libs, nil
	}
	libs = append(libs, fileProps.Library(sha1))
	return libs, nil
}

func (p *Parser) parseInnerJar(zf *zip.File, rootPath string) ([]JarLibrary, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner")
	if err != nil {
		return nil, xerrors.Errorf("unable to create a temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	// Copy the file content to the temp file
	if _, err = io.Copy(f, fr); err != nil {
		return nil, xerrors.Errorf("file copy error: %w", err)
	}

	// build full path to inner jar
	fullPath := path.Join(rootPath, zf.Name)

	// Parse jar/war/ear recursively
	innerLibs, err := p.parseArtifact(fullPath, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
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

func parseFileName(filePath string) Properties {
	fileName := filepath.Base(filePath)
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return Properties{}
	}

	return Properties{
		ArtifactID: packageVersion[1],
		Version:    packageVersion[2],
		FilePath:   filePath,
	}
}

func parsePomProperties(f *zip.File, filePath string) (Properties, error) {
	file, err := f.Open()
	if err != nil {
		return Properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	p := Properties{
		FilePath: filePath,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.GroupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.Version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return Properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendor   string
	implementationVendorId string
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
		return manifest{}, xerrors.Errorf("unable to open MANIFEST.MF: %w", err)
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
			m.implementationVendorId = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
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
		return manifest{}, xerrors.Errorf("scan error: %w", err)
	}
	return m, nil
}

func (m manifest) properties(filePath string) Properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return Properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return Properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return Properties{}
	}

	return Properties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		FilePath:   filePath,
	}
}

func (m manifest) determineGroupID() (string, error) {
	var groupID string
	switch {
	case m.implementationVendorId != "":
		groupID = m.implementationVendorId
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
		return "", xerrors.New("no groupID found")
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
		return "", xerrors.New("no artifactID found")
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
		return "", xerrors.New("no version found")
	}
	return strings.TrimSpace(version), nil
}

func removeLibraryDuplicates(libs []JarLibrary) []JarLibrary {
	return lo.UniqBy(libs, func(lib JarLibrary) string {
		return fmt.Sprintf("%s::%s::%s", lib.Name, lib.Version, lib.FilePath)
	})
}
