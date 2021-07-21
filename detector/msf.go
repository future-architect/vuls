// +build !scanner

package detector

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	metasploitdb "github.com/takuzoo3868/go-msfdb/db"
	metasploitmodels "github.com/takuzoo3868/go-msfdb/models"
	"golang.org/x/xerrors"
)

// FillWithMetasploit fills metasploit module information that has in module
func FillWithMetasploit(r *models.ScanResult, cnf config.MetasploitConf) (nMetasploitCve int, err error) {

	driver, locked, err := newMetasploitDB(&cnf)
	if locked {
		return 0, xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
	} else if err != nil {
		return 0, err
	}
	defer func() {
		if err := driver.CloseDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	for cveID, vuln := range r.ScannedCves {
		if cveID == "" {
			continue
		}
		ms := driver.GetModuleByCveID(cveID)
		if len(ms) == 0 {
			continue
		}
		modules := ConvertToModelsMsf(ms)
		vuln.Metasploits = modules
		r.ScannedCves[cveID] = vuln
		nMetasploitCve++
	}

	return nMetasploitCve, nil
}

// ConvertToModelsMsf converts gost model to vuls model
func ConvertToModelsMsf(ms []metasploitmodels.Metasploit) (modules []models.Metasploit) {
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

func newMetasploitDB(cnf config.VulnDictInterface) (driver metasploitdb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = metasploitdb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL()); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("metasploitDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
}
