/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"context"
	"flag"
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/exploit"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
)

// ReportCmd is subcommand for reporting
type ReportCmd struct {
	configPath  string
	cveDict     c.GoCveDictConf
	ovalDict    c.GovalDictConf
	gostConf    c.GostConf
	exploitConf c.ExploitConf
	httpConf    c.HTTPConf
}

// Name return subcommand name
func (*ReportCmd) Name() string { return "report" }

// Synopsis return synopsis
func (*ReportCmd) Synopsis() string { return "Reporting" }

// Usage return usage
func (*ReportCmd) Usage() string {
	return `report:
	report
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-refresh-cve]
		[-cvss-over=7]
		[-diff]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-ignore-github-dismissed]
		[-to-email]
		[-to-http]
		[-to-slack]
		[-to-stride]
		[-to-hipchat]
		[-to-chatwork]
		[-to-telegram]
		[-to-localfile]
		[-to-s3]
		[-to-azure-blob]
		[-to-saas]
		[-format-json]
		[-format-xml]
		[-format-one-email]
		[-format-one-line-text]
		[-format-list]
		[-format-full-text]
		[-gzip]
		[-uuid]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-pipe]
		[-cvedb-type=sqlite3|mysql|postgres|redis|http]
		[-cvedb-sqlite3-path=/path/to/cve.sqlite3]
		[-cvedb-url=http://127.0.0.1:1323 or DB connection string]
		[-ovaldb-type=sqlite3|mysql|redis|http]
		[-ovaldb-sqlite3-path=/path/to/oval.sqlite3]
		[-ovaldb-url=http://127.0.0.1:1324 or DB connection string]
		[-gostdb-type=sqlite3|mysql|redis|http]
		[-gostdb-sqlite3-path=/path/to/gost.sqlite3]
		[-gostdb-url=http://127.0.0.1:1325 or DB connection string]
		[-exploitdb-type=sqlite3|mysql|redis|http]
		[-exploitdb-sqlite3-path=/path/to/exploitdb.sqlite3]
		[-exploitdb-url=http://127.0.0.1:1326 or DB connection string]
		[-http="http://vuls-report-server"]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ReportCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")

	f.BoolVar(&c.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	f.BoolVar(&c.Conf.RefreshCve, "refresh-cve", false,
		"Refresh CVE information in JSON file under results dir")

	f.Float64Var(&c.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(&c.Conf.Diff, "diff", false,
		"Difference between previous result and current result ")

	f.BoolVar(&c.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't report the unscored CVEs")

	f.BoolVar(&c.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't report the unfixed CVEs")

	f.BoolVar(&c.Conf.IgnoreGitHubDismissed, "ignore-github-dismissed", false,
		"Don't report the dismissed CVEs on GitHub Security Alerts")

	f.StringVar(
		&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&c.Conf.FormatJSON, "format-json", false, "JSON format")
	f.BoolVar(&c.Conf.FormatXML, "format-xml", false, "XML format")
	f.BoolVar(&c.Conf.FormatOneEMail, "format-one-email", false,
		"Send all the host report via only one EMail (Specify with -to-email)")
	f.BoolVar(&c.Conf.FormatOneLineText, "format-one-line-text", false,
		"One line summary in plain text")
	f.BoolVar(&c.Conf.FormatList, "format-list", false, "Display as list format")
	f.BoolVar(&c.Conf.FormatFullText, "format-full-text", false,
		"Detail report in plain text")

	f.BoolVar(&c.Conf.ToSlack, "to-slack", false, "Send report via Slack")
	f.BoolVar(&c.Conf.ToStride, "to-stride", false, "Send report via Stride")
	f.BoolVar(&c.Conf.ToHipChat, "to-hipchat", false, "Send report via hipchat")
	f.BoolVar(&c.Conf.ToChatWork, "to-chatwork", false, "Send report via chatwork")
	f.BoolVar(&c.Conf.ToTelegram, "to-telegram", false, "Send report via Telegram")
	f.BoolVar(&c.Conf.ToEmail, "to-email", false, "Send report via Email")
	f.BoolVar(&c.Conf.ToSyslog, "to-syslog", false, "Send report via Syslog")
	f.BoolVar(&c.Conf.ToLocalFile, "to-localfile", false, "Write report to localfile")
	f.BoolVar(&c.Conf.ToS3, "to-s3", false,
		"Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/xml/txt)")
	f.BoolVar(&c.Conf.ToHTTP, "to-http", false, "Send report via HTTP POST")
	f.BoolVar(&c.Conf.ToAzureBlob, "to-azure-blob", false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/xml/txt)")
	f.BoolVar(&c.Conf.ToSaas, "to-saas", false,
		"Upload report to Future Vuls(https://vuls.biz/) before report")

	f.BoolVar(&c.Conf.GZIP, "gzip", false, "gzip compression")
	f.BoolVar(&c.Conf.UUID, "uuid", false,
		"Auto generate of scan target servers and then write to config.toml and scan result")
	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use args passed via PIPE")

	f.StringVar(&p.cveDict.Type, "cvedb-type", "",
		"DB type of go-cve-dictionary (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.cveDict.SQLite3Path, "cvedb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.cveDict.URL, "cvedb-url", "",
		"http://go-cve-dictionary.com:1323 or DB connection string")

	f.StringVar(&p.ovalDict.Type, "ovaldb-type", "",
		"DB type of goval-dictionary (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.ovalDict.SQLite3Path, "ovaldb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.ovalDict.URL, "ovaldb-url", "",
		"http://goval-dictionary.com:1324 or DB connection string")

	f.StringVar(&p.gostConf.Type, "gostdb-type", "",
		"DB type of gost (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.gostConf.SQLite3Path, "gostdb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.gostConf.URL, "gostdb-url", "",
		"http://gost.com:1325 or DB connection string")

	f.StringVar(&p.exploitConf.Type, "exploitdb-type", "",
		"DB type of exploit (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.exploitConf.SQLite3Path, "exploitdb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.exploitConf.URL, "exploitdb-url", "",
		"http://exploit.com:1326 or DB connection string")

	f.StringVar(&p.httpConf.URL, "http", "", "-to-http http://vuls-report")

}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(c.Conf.LogDir, false, c.Conf.Debug, false)

	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.CveDict.Overwrite(p.cveDict)
	c.Conf.OvalDict.Overwrite(p.ovalDict)
	c.Conf.Gost.Overwrite(p.gostConf)
	c.Conf.Exploit.Overwrite(p.exploitConf)
	c.Conf.HTTP.Overwrite(p.httpConf)

	var dir string
	var err error
	if c.Conf.Diff {
		dir, err = report.JSONDir([]string{})
	} else {
		dir, err = report.JSONDir(f.Args())
	}
	if err != nil {
		util.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	// report
	reports := []report.ResultWriter{
		report.StdoutWriter{},
	}

	if c.Conf.ToSlack {
		reports = append(reports, report.SlackWriter{})
	}

	if c.Conf.ToStride {
		reports = append(reports, report.StrideWriter{})
	}

	if c.Conf.ToHipChat {
		reports = append(reports, report.HipChatWriter{})
	}

	if c.Conf.ToChatWork {
		reports = append(reports, report.ChatWorkWriter{})
	}

	if c.Conf.ToTelegram {
		reports = append(reports, report.TelegramWriter{})
	}

	if c.Conf.ToEmail {
		reports = append(reports, report.EMailWriter{})
	}

	if c.Conf.ToSyslog {
		reports = append(reports, report.SyslogWriter{})
	}

	if c.Conf.ToHTTP {
		reports = append(reports, report.HTTPRequestWriter{})
	}

	if c.Conf.ToLocalFile {
		reports = append(reports, report.LocalFileWriter{
			CurrentDir: dir,
		})
	}

	if c.Conf.ToS3 {
		if err := report.CheckIfBucketExists(); err != nil {
			util.Log.Errorf("Check if there is a bucket beforehand: %s, err: %+v",
				c.Conf.AWS.S3Bucket, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.S3Writer{})
	}

	if c.Conf.ToAzureBlob {
		if len(c.Conf.Azure.AccountName) == 0 {
			c.Conf.Azure.AccountName = os.Getenv("AZURE_STORAGE_ACCOUNT")
		}

		if len(c.Conf.Azure.AccountKey) == 0 {
			c.Conf.Azure.AccountKey = os.Getenv("AZURE_STORAGE_ACCESS_KEY")
		}

		if len(c.Conf.Azure.ContainerName) == 0 {
			util.Log.Error("Azure storage container name is required with -azure-container option")
			return subcommands.ExitUsageError
		}
		if err := report.CheckIfAzureContainerExists(); err != nil {
			util.Log.Errorf("Check if there is a container beforehand: %s, err: %+v",
				c.Conf.Azure.ContainerName, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.AzureBlobWriter{})
	}

	if c.Conf.ToSaas {
		if !c.Conf.UUID {
			util.Log.Errorf("If you use the -to-saas option, you need to enable the uuid option")
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.SaasWriter{})
	}

	if !(c.Conf.FormatJSON || c.Conf.FormatOneLineText ||
		c.Conf.FormatList || c.Conf.FormatFullText || c.Conf.FormatXML) {
		c.Conf.FormatList = true
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	var loaded models.ScanResults
	if loaded, err = report.LoadScanResults(dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	util.Log.Infof("Loaded: %s", dir)

	var res models.ScanResults
	hasError := false
	for _, r := range loaded {
		if len(r.Errors) == 0 {
			res = append(res, r)
		} else {
			util.Log.Errorf("Ignored since errors occurred during scanning: %s, err: %v",
				r.ServerName, r.Errors)
			hasError = true
		}
	}

	if len(res) == 0 {
		return subcommands.ExitFailure
	}

	for _, r := range res {
		util.Log.Debugf("%s: %s",
			r.ServerInfo(),
			pp.Sprintf("%s", c.Conf.Servers[r.ServerName]))
	}

	if c.Conf.UUID {
		// Ensure UUIDs of scan target servers in config.toml
		if err := report.EnsureUUIDs(p.configPath, res); err != nil {
			util.Log.Errorf("Failed to ensure UUIDs. err: %+v", err)
			return subcommands.ExitFailure
		}
	}

	if !c.Conf.ToSaas {
		util.Log.Info("Validating db config...")
		if !c.Conf.ValidateOnReportDB() {
			return subcommands.ExitUsageError
		}

		if c.Conf.CveDict.URL != "" {
			if err := report.CveClient.CheckHealth(); err != nil {
				util.Log.Errorf("CVE HTTP server is not running. err: %+v", err)
				util.Log.Errorf("Run go-cve-dictionary as server mode before reporting or run with `-cvedb-type=sqlite3 -cvedb-sqlite3-path` option instead of -cvedb-url")
				return subcommands.ExitFailure
			}
		}

		if c.Conf.OvalDict.URL != "" {
			err := oval.Base{}.CheckHTTPHealth()
			if err != nil {
				util.Log.Errorf("OVAL HTTP server is not running. err: %+v", err)
				util.Log.Errorf("Run goval-dictionary as server mode before reporting or run with `-ovaldb-type=sqlite3 -ovaldb-sqlite3-path` option instead of -ovaldb-url")
				return subcommands.ExitFailure
			}
		}

		if c.Conf.Gost.URL != "" {
			util.Log.Infof("gost: %s", c.Conf.Gost.URL)
			err := gost.Base{}.CheckHTTPHealth()
			if err != nil {
				util.Log.Errorf("gost HTTP server is not running. err: %+v", err)
				util.Log.Errorf("Run gost as server mode before reporting or run with `-gostdb-type=sqlite3 -gostdb-sqlite3-path` option instead of -gostdb-url")
				return subcommands.ExitFailure
			}
		}

		if c.Conf.Exploit.URL != "" {
			err := exploit.CheckHTTPHealth()
			if err != nil {
				util.Log.Errorf("exploit HTTP server is not running. err: %+v", err)
				util.Log.Errorf("Run go-exploitdb as server mode before reporting")
				return subcommands.ExitFailure
			}
		}
		dbclient, locked, err := report.NewDBClient(report.DBClientConf{
			CveDictCnf:  c.Conf.CveDict,
			OvalDictCnf: c.Conf.OvalDict,
			GostCnf:     c.Conf.Gost,
			ExploitCnf:  c.Conf.Exploit,
			DebugSQL:    c.Conf.DebugSQL,
		})
		if locked {
			util.Log.Errorf("SQLite3 is locked. Close other DB connections and try again. err: %+v", err)
			return subcommands.ExitFailure
		}
		if err != nil {
			util.Log.Errorf("Failed to init DB Clients. err: %+v", err)
			return subcommands.ExitFailure
		}
		defer dbclient.CloseDB()

		if res, err = report.FillCveInfos(*dbclient, res, dir); err != nil {
			util.Log.Errorf("%+v", err)
			return subcommands.ExitFailure
		}
	}

	for _, w := range reports {
		if err := w.Write(res...); err != nil {
			util.Log.Errorf("Failed to report. err: %+v", err)
			return subcommands.ExitFailure
		}
	}

	if hasError {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
