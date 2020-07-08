package msf

import (
	"fmt"
	"net/http"

	cnf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/parnurzeal/gorequest"
	"github.com/takuzoo3868/go-msfdb/db"
	metasploitmodels "github.com/takuzoo3868/go-msfdb/models"
	"golang.org/x/xerrors"
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

// CheckHTTPHealth do health check
func CheckHTTPHealth() error {
	if !cnf.Conf.Metasploit.IsFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", cnf.Conf.Metasploit.URL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().Get(url).End()
	//  resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to connect to metasploit server. url: %s, errs: %w", url, errs)
	}
	return nil
}
