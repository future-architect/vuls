// +build !scanner

package msf

import (
	"github.com/future-architect/vuls/models"
	"github.com/takuzoo3868/go-msfdb/db"
	metasploitmodels "github.com/takuzoo3868/go-msfdb/models"
)

// FillWithMetasploit fills metasploit module information that has in module
func FillWithMetasploit(driver db.DB, r *models.ScanResult) (nMetasploitCve int, err error) {
	if driver == nil {
		return 0, nil
	}
	for cveID, vuln := range r.ScannedCves {
		if cveID == "" {
			continue
		}
		ms := driver.GetModuleByCveID(cveID)
		if len(ms) == 0 {
			continue
		}
		modules := ConvertToModels(ms)
		vuln.Metasploits = modules
		r.ScannedCves[cveID] = vuln
		nMetasploitCve++
	}

	return nMetasploitCve, nil
}

// ConvertToModels converts gost model to vuls model
func ConvertToModels(ms []*metasploitmodels.Metasploit) (modules []models.Metasploit) {
	for _, m := range ms {
		var links []string
		if 0 < len(m.References) {
			for _, u := range m.References {
				links = append(links, u.Link)
			}
		}
		module := models.Metasploit{
			Name:        m.Name,
			Title:       m.Title,
			Description: m.Description,
			URLs:        links,
		}
		modules = append(modules, module)
	}
	return modules
}
