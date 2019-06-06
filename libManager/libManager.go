package libManager

import (
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	godeptypes "github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/scanner/library"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"
)

// FillLibrary fills LibraryScanner informations
func FillLibrary(r *models.ScanResult) (totalCnt int, err error) {

	// initialize trivy's logger and db
	err = log.InitLogger(false)
	if err != nil {
		return 0, err
	}
	if err := db.Init(); err != nil {
		return 0, err
	}

	for _, lib := range r.LibraryScanners {
		vinfos, err := scan(lib.Path, lib.Libs)
		if err != nil {
			return 0, err
		}
		for _, vinfo := range vinfos {
			r.ScannedCves[vinfo.CveID] = vinfo
		}
		totalCnt += len(vinfos)
	}

	return totalCnt, nil
}

func scan(path string, pkgs []godeptypes.Library) ([]models.VulnInfo, error) {
	scanner := library.NewScanner(filepath.Base(string(path)))
	if scanner == nil {
		return nil, xerrors.New("unknown file type")
	}

	err := scanner.UpdateDB()
	if err != nil {
		return nil, xerrors.Errorf("failed to update %s advisories: %w", scanner.Type(), err)
	}

	var vulnerabilities []models.VulnInfo
	for _, pkg := range pkgs {
		v, err := version.NewVersion(pkg.Version)
		if err != nil {
			util.Log.Debugf("new version cant detected %s@%s", pkg.Name, pkg.Version)
			continue
		}

		tvulns, err := scanner.Detect(pkg.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", scanner.Type(), err)
		}

		vulns := convertFanalToVuln(tvulns)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

func convertFanalToVuln(tvulns []vulnerability.DetectedVulnerability) (vulns []models.VulnInfo) {
	for _, tvuln := range tvulns {
		vinfo, _ := getVulnDetail(tvuln)
		vulns = append(vulns, vinfo)
	}
	return vulns
}

func getVulnDetail(tvuln vulnerability.DetectedVulnerability) (vinfo models.VulnInfo, err error) {
	details, err := vulnerability.Get(tvuln.VulnerabilityID)
	if err != nil {
		return vinfo, err
	} else if len(details) == 0 {
		return vinfo, xerrors.Errorf("Unknown vulnID : %s", tvuln.VulnerabilityID)
	}
	vinfo.CveID = tvuln.VulnerabilityID
	vinfo.CveContents = getCveContents(details)
	if tvuln.FixedVersion != "" {
		vinfo.PackageFixedIns = []models.PackageFixedIn{
			{
				Name:    tvuln.PkgName,
				FixedIn: tvuln.FixedVersion,
			},
		}
	}
	return vinfo, nil
}

func getCveContents(details map[string]vulnerability.Vulnerability) (contents map[models.CveContentType]models.CveContent) {
	contents = map[models.CveContentType]models.CveContent{}
	for source, detail := range details {
		refs := []models.Reference{}
		for _, refURL := range detail.References {
			refs = append(refs, models.Reference{Source: refURL, Link: refURL})
		}

		content := models.CveContent{
			Type:          models.NewCveContentType(source),
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
		contents[models.NewCveContentType(source)] = content
	}
	return contents
}
