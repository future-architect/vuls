package models

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	trivyDBTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"

	// "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
)

// LibraryScanners is an array of LibraryScanner
type LibraryScanners []LibraryScanner

// Find : find by name
func (lss LibraryScanners) Find(path, name string) map[string]types.Library {
	filtered := map[string]types.Library{}
	for _, ls := range lss {
		for _, lib := range ls.Libs {
			if ls.Path == path && lib.Name == name {
				filtered[ls.Path] = lib
				break
			}
		}
	}
	return filtered
}

// LibraryScanner has libraries information
type LibraryScanner struct {
	Path string
	Libs []types.Library
}

// Scan : scan target library
func (s LibraryScanner) Scan() ([]VulnInfo, error) {
	scanner, err := library.DriverFactory{}.NewDriver(filepath.Base(string(s.Path)))
	if err != nil {
		return nil, xerrors.Errorf("Failed to new a library driver: %w", err)
	}
	var vulnerabilities = []VulnInfo{}
	for _, pkg := range s.Libs {
		v, err := version.NewVersion(pkg.Version)
		if err != nil {
			util.Log.Debugf("new version cant detected %s@%s", pkg.Name, pkg.Version)
			continue
		}

		tvulns, err := scanner.Detect(pkg.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", scanner.Type(), err)
		}
		if len(tvulns) == 0 {
			continue
		}

		vulns := s.convertFanalToVuln(tvulns)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

func (s LibraryScanner) convertFanalToVuln(tvulns []types.DetectedVulnerability) (vulns []VulnInfo) {
	for _, tvuln := range tvulns {
		vinfo, err := s.getVulnDetail(tvuln)
		if err != nil {
			util.Log.Debugf("failed to getVulnDetail. err: %s, tvuln: %#v", err, tvuln)
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
	if tvuln.FixedVersion != "" {
		vinfo.LibraryFixedIns = []LibraryFixedIn{
			{
				Key:     s.GetLibraryKey(),
				Name:    tvuln.PkgName,
				FixedIn: tvuln.FixedVersion,
				Path:    s.Path,
			},
		}
	}
	return vinfo, nil
}

func getCveContents(cveID string, vul trivyDBTypes.Vulnerability) (contents map[CveContentType]CveContent) {
	contents = map[CveContentType]CveContent{}
	refs := []Reference{}
	for _, refURL := range vul.References {
		refs = append(refs, Reference{Source: "trivy", Link: refURL})
	}

	content := CveContent{
		Type:          Trivy,
		CveID:         cveID,
		Title:         vul.Title,
		Summary:       vul.Description,
		Cvss3Severity: string(vul.Severity),
		References:    refs,
	}
	contents[Trivy] = content
	return contents
}

// LibraryMap is filename and library type
var LibraryMap = map[string]string{
	"package-lock.json": "node",
	"yarn.lock":         "node",
	"Gemfile.lock":      "ruby",
	"Cargo.lock":        "rust",
	"composer.lock":     "php",
	"Pipfile.lock":      "python",
	"poetry.lock":       "python",
}

// GetLibraryKey returns target library key
func (s LibraryScanner) GetLibraryKey() string {
	fileName := filepath.Base(s.Path)
	return LibraryMap[fileName]
}

// LibraryFixedIn has library fixed information
type LibraryFixedIn struct {
	Key     string `json:"key,omitempty"`
	Name    string `json:"name,omitempty"`
	FixedIn string `json:"fixedIn,omitempty"`
	Path    string `json:"path,omitempty"`
}
