/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	"flag"
	"os"

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/db"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"golang.org/x/net/context"
)

// ScanCmd is Subcommand of host discovery mode
type ScanCmd struct {
	lang     string
	debug    bool
	debugSQL bool

	configPath string

	dbpath           string
	cveDictionaryURL string
	cvssScoreOver    float64
	httpProxy        string

	useYumPluginSecurity  bool
	useUnattendedUpgrades bool

	// reporting
	reportSlack bool
	reportMail  bool
}

// Name return subcommand name
func (*ScanCmd) Name() string { return "scan" }

// Synopsis return synopsis
func (*ScanCmd) Synopsis() string { return "Scan vulnerabilities." }

// Usage return usage
func (*ScanCmd) Usage() string {
	return `scan:
	scan
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-dbpath=/path/to/vuls.sqlite3]
		[-cve-dictionary-url=http://127.0.0.1:1323]
		[-cvss-over=7]
		[-report-slack]
		[-report-mail]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
`
}

// SetFlags set flag
func (p *ScanCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	defaultConfPath := os.Getenv("PWD") + "/config.toml"
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultDBPath := os.Getenv("PWD") + "/vuls.sqlite3"
	f.StringVar(&p.dbpath, "dbpath", defaultDBPath, "/path/to/sqlite3")

	defaultURL := "http://127.0.0.1:1323"
	f.StringVar(
		&p.cveDictionaryURL,
		"cve-dictionary-url",
		defaultURL,
		"http://CVE.Dictionary")

	f.Float64Var(
		&p.cvssScoreOver,
		"cvss-over",
		0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)

	f.BoolVar(&p.reportSlack, "report-slack", false, "Slack report")
	f.BoolVar(&p.reportMail, "report-mail", false, "Email report")

	f.BoolVar(
		&p.useYumPluginSecurity,
		"use-yum-plugin-security",
		false,
		"[Depricated] For CentOS 5. Scan by yum-plugin-security or not (use yum check-update by default)",
	)

	f.BoolVar(
		&p.useUnattendedUpgrades,
		"use-unattended-upgrades",
		false,
		"[Depricated] For Ubuntu. Scan by unattended-upgrades or not (use apt-get upgrade --dry-run by default)",
	)

}

// Execute execute
func (p *ScanCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	logrus.Infof("Begin scannig (config: %s)", p.configPath)
	err := c.Load(p.configPath)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	target := make(map[string]c.ServerInfo)
	for _, arg := range f.Args() {
		found := false
		for servername, info := range c.Conf.Servers {
			if servername == arg {
				target[servername] = info
				found = true
				break
			}
		}
		if !found {
			logrus.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(f.Args()) {
		c.Conf.Servers = target
	}

	c.Conf.Lang = p.lang
	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL

	// logger
	Log := util.NewCustomLogger(c.ServerInfo{})

	// report
	reports := []report.ResultWriter{
		report.TextWriter{},
		report.LogrusWriter{},
	}
	if p.reportSlack {
		reports = append(reports, report.SlackWriter{})
	}
	if p.reportMail {
		reports = append(reports, report.MailWriter{})
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.CveDictionaryURL = p.cveDictionaryURL
	c.Conf.HTTPProxy = p.httpProxy
	c.Conf.UseYumPluginSecurity = p.useYumPluginSecurity
	c.Conf.UseUnattendedUpgrades = p.useUnattendedUpgrades

	Log.Info("Validating Config...")
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if ok, err := cveapi.CveClient.CheckHealth(); !ok {
		Log.Errorf("CVE HTTP server is not running. %#v", cveapi.CveClient)
		Log.Fatal(err)
		return subcommands.ExitFailure
	}

	Log.Info("Detecting OS... ")
	err = scan.InitServers(Log)
	if err != nil {
		Log.Errorf("Failed to init servers. err: %s", err)
		return subcommands.ExitFailure
	}

	Log.Info("Scanning vulnerabilities... ")
	if errs := scan.Scan(); 0 < len(errs) {
		for _, e := range errs {
			Log.Errorf("Failed to scan. err: %s.", e)
		}
		return subcommands.ExitFailure
	}

	scanResults, err := scan.GetScanResults()
	if err != nil {
		Log.Fatal(err)
		return subcommands.ExitFailure
	}

	Log.Info("Reporting...")
	filtered := scanResults.FilterByCvssOver()
	for _, w := range reports {
		if err := w.Write(filtered); err != nil {
			Log.Fatalf("Failed to output report, err: %s", err)
			return subcommands.ExitFailure
		}
	}

	Log.Info("Insert to DB...")
	if err := db.OpenDB(); err != nil {
		Log.Errorf("Failed to open DB. datafile: %s, err: %s", c.Conf.DBPath, err)
		return subcommands.ExitFailure
	}
	if err := db.MigrateDB(); err != nil {
		Log.Errorf("Failed to migrate. err: %s", err)
		return subcommands.ExitFailure
	}

	if err := db.Insert(scanResults); err != nil {
		Log.Fatalf("Failed to insert. dbpath: %s, err: %s", c.Conf.DBPath, err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
