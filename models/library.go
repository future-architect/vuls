package models

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	trivyDBTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/future-architect/vuls/logging"

	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	// "github.com/aquasecurity/go-dep-parser/pkg/types"
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

// Total returns total count of pkgs
func (lss LibraryScanners) Total() (total int) {
	for _, lib := range lss {
		total += len(lib.Libs)
	}
	return
}

// LibraryScanner has libraries information
type LibraryScanner struct {
	Type string
	Path string
	Libs []types.Library
}

// Scan : scan target library
func (s LibraryScanner) Scan() ([]VulnInfo, error) {
	scanner, err := library.NewDriver(s.Type)
	if err != nil {
		return nil, xerrors.Errorf("Failed to new a library driver: %w", err)
	}
	var vulnerabilities = []VulnInfo{}
	for _, pkg := range s.Libs {
		tvulns, err := scanner.Detect(pkg.Name, pkg.Version)
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
			Path:    s.Path,
		},
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
	"go.sum":            "gomod",
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
