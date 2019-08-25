package models

import (
	"path/filepath"

	"github.com/future-architect/vuls/util"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
)

// LibraryScanner has libraries information
type LibraryScanner struct {
	Path string
	Libs []types.Library
}

// Scan : scan target library
func (s LibraryScanner) Scan() ([]VulnInfo, error) {
	scanner := library.NewScanner(filepath.Base(string(s.Path)))
	if scanner == nil {
		return nil, xerrors.New("unknown file type")
	}

	util.Log.Info("Updating library db...")
	err := scanner.UpdateDB()
	if err != nil {
		return nil, xerrors.Errorf("failed to update %s advisories: %w", scanner.Type(), err)
	}

	var vulnerabilities []VulnInfo
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

		vulns := s.convertFanalToVuln(tvulns)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

func (s LibraryScanner) convertFanalToVuln(tvulns []vulnerability.DetectedVulnerability) (vulns []VulnInfo) {
	for _, tvuln := range tvulns {
		vinfo, _ := s.getVulnDetail(tvuln)
		vulns = append(vulns, vinfo)
	}
	return vulns
}

func (s LibraryScanner) getVulnDetail(tvuln vulnerability.DetectedVulnerability) (vinfo VulnInfo, err error) {
	details, err := vulnerability.Get(tvuln.VulnerabilityID)
	if err != nil {
		return vinfo, err
	} else if len(details) == 0 {
		return vinfo, xerrors.Errorf("Unknown vulnID : %s", tvuln.VulnerabilityID)
	}
	vinfo.CveID = tvuln.VulnerabilityID
	vinfo.CveContents = getCveContents(details)
	if tvuln.FixedVersion != "" {

		vinfo.LibraryFixedIns = []LibraryFixedIn{
			{
				Key:     s.GetLibraryKey(),
				Name:    tvuln.PkgName,
				FixedIn: tvuln.FixedVersion,
			},
		}
	}
	return vinfo, nil
}

func getCveContents(details map[string]vulnerability.Vulnerability) (contents map[CveContentType]CveContent) {
	contents = map[CveContentType]CveContent{}
	for source, detail := range details {
		refs := []Reference{}
		for _, refURL := range detail.References {
			refs = append(refs, Reference{Source: refURL, Link: refURL})
		}

		content := CveContent{
			Type:          NewCveContentType(source),
			CveID:         detail.ID,
			Title:         detail.Title,
			Summary:       detail.Description,
			Cvss3Score:    detail.CvssScoreV3,
			Cvss3Severity: string(detail.SeverityV3),
			Cvss2Score:    detail.CvssScore,
			Cvss2Severity: string(detail.Severity),
			References:    refs,

			//SourceLink    string            `json:"sourceLink"`
			//Cvss2Vector   string            `json:"cvss2Vector"`
			//Cvss3Vector   string            `json:"cvss3Vector"`
			//Cvss3Severity string            `json:"cvss3Severity"`
			//Cpes          []Cpe             `json:"cpes,omitempty"`
			//CweIDs        []string          `json:"cweIDs,omitempty"`
			//Published     time.Time         `json:"published"`
			//LastModified  time.Time         `json:"lastModified"`
			//Mitigation    string            `json:"mitigation"` // RedHat API
			//Optional      map[string]string `json:"optional,omitempty"`
		}
		contents[NewCveContentType(source)] = content
	}
	return contents
}

// LibraryMap is filename and library type
var LibraryMap = map[string]string{
	"package-lock.json": "node",
	"yarn.lock":         "node",
	"Gemfile.lock":      "ruby",
	"Cargo.lock":        "rust",
	"composer.json":     "php",
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
}
