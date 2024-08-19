//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/hashicorp/go-version"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
)

// Arch is Gost client
type Arch struct {
	Base
}

// ArchIssue is struct of Arch Linux security issue
type ArchIssue struct {
	Name string

	// Contains list of package names
	Packages []string
	Status   string
	Severity string
	Type     string

	// Vulnerable version.
	Affected string

	// Fixed version. May be empty.
	Fixed  string
	Ticket string

	// Contains list of CVEs
	Issues     []string
	Advisories []string
}

func (arch Arch) FetchAllIssues() ([]ArchIssue, error) {
	client := &http.Client{Timeout: 2 * 60 * time.Second}
	r, err := client.Get("https://security.archlinux.org/issues/all.json")
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch files. err: %w", err)
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read response body. err: %w", err)
	}

	var archIssues []ArchIssue
	if err := json.Unmarshal(body, &archIssues); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal. err: %w", err)
	}

	return archIssues, nil
}

func (arch Arch) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	detects := map[string]cveContent{}

	archIssues, _ := arch.FetchAllIssues()
	for _, issue := range archIssues {
		for _, pkgName := range issue.Packages {
			if _, ok := r.Packages[pkgName]; ok {
				pkgVer := r.Packages[pkgName].Version + "-" + r.Packages[pkgName].Release
				for _, content := range arch.detect(issue, pkgName, pkgVer) {
					c, ok := detects[content.cveContent.CveID]
					if ok {
						content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
					}
					detects[content.cveContent.CveID] = content
				}
			}
		}
	}

	for _, content := range detects {
		v, ok := r.ScannedCves[content.cveContent.CveID]
		if ok {
			if v.CveContents == nil {
				v.CveContents = models.NewCveContents(content.cveContent)
			} else {
				v.CveContents[models.ArchLinuxSecurityTracker] = []models.CveContent{content.cveContent}
			}
			v.Confidences.AppendIfMissing(models.ArchLinuxSecurityTrackerMatch)
		} else {
			v = models.VulnInfo{
				CveID:       content.cveContent.CveID,
				CveContents: models.NewCveContents(content.cveContent),
				Confidences: models.Confidences{models.ArchLinuxSecurityTrackerMatch},
			}
		}

		for _, s := range content.fixStatuses {
			v.AffectedPackages = v.AffectedPackages.Store(s)
		}
		r.ScannedCves[content.cveContent.CveID] = v
	}

	return len(unique(maps.Keys(detects))), nil
}

func (arch Arch) detect(issue ArchIssue, pkgName, verStr string) []cveContent {
	var contents []cveContent

	for _, cveId := range issue.Issues {
		c := cveContent{
			cveContent: models.CveContent{
				Type:  models.ArchLinuxSecurityTracker,
				CveID: cveId,
			},
		}

		vera, err := version.NewVersion(verStr)
		if err != nil {
			logging.Log.Debugf("Failed to parse version. version: %s, err: %v", verStr, err)
			continue
		}

		if issue.Fixed != "" {
			verb, err := version.NewVersion(issue.Fixed)
			if err != nil {
				logging.Log.Debugf("Failed to parse version. version: %s, err: %v", issue.Fixed, err)
				continue
			}

			if vera.LessThan(verb) {
				c.fixStatuses = append(c.fixStatuses,
					models.PackageFixStatus{
						Name:    pkgName,
						FixedIn: issue.Fixed,
					})
			}
		} else {
			verb, err := version.NewVersion(issue.Affected)
			if err != nil {
				logging.Log.Debugf("Failed to parse version. version: %s, err: %v", issue.Affected, err)
				continue
			}

			if vera.LessThanOrEqual(verb) {
				c.fixStatuses = append(c.fixStatuses,
					models.PackageFixStatus{
						Name: pkgName,
					})
			}
		}

		if len(c.fixStatuses) > 0 {
			contents = append(contents, c)
		}
	}

	return contents
}
