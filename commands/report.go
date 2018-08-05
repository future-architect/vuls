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
	"fmt"
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
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
	lang               string
	debug              bool
	debugSQL           bool
	configPath         string
	resultsDir         string
	logDir             string
	refreshCve         bool
	cvssScoreOver      float64
	ignoreUnscoredCves bool
	ignoreUnfixed      bool
	httpProxy          string
	toSlack            bool
	toStride           bool
	toHipChat          bool
	toChatWork         bool
	toEMail            bool
	toSyslog           bool
	toLocalFile        bool
	toS3               bool
	toAzureBlob        bool
	toHTTP             bool
	formatJSON         bool
	formatXML          bool
	formatOneEMail     bool
	formatOneLineText  bool
	formatFullText     bool
	formatList         bool
	gzip               bool
	uuid               bool
	pipe               bool
	diff               bool
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
		[-to-email]
		[-to-http]
		[-to-slack]
		[-to-stride]
		[-to-hipchat]
		[-to-chatwork]
		[-to-localfile]
		[-to-s3]
		[-to-azure-blob]
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
		[-pipe]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ReportCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")

	f.BoolVar(
		&p.refreshCve,
		"refresh-cve",
		false,
		"Refresh CVE information in JSON file under results dir")

	f.Float64Var(
		&p.cvssScoreOver,
		"cvss-over",
		0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(&p.diff,
		"diff",
		false,
		fmt.Sprintf("Difference between previous result and current result "))

	f.BoolVar(
		&p.ignoreUnscoredCves,
		"ignore-unscored-cves",
		false,
		"Don't report the unscored CVEs")

	f.BoolVar(
		&p.ignoreUnfixed,
		"ignore-unfixed",
		false,
		"Don't report the unfixed CVEs")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.formatJSON,
		"format-json",
		false,
		fmt.Sprintf("JSON format"))

	f.BoolVar(&p.formatXML,
		"format-xml",
		false,
		fmt.Sprintf("XML format"))

	f.BoolVar(&p.formatOneEMail,
		"format-one-email",
		false,
		"Send all the host report via only one EMail (Specify with -to-email)")

	f.BoolVar(&p.formatOneLineText,
		"format-one-line-text",
		false,
		fmt.Sprintf("One line summary in plain text"))

	f.BoolVar(&p.formatList,
		"format-list",
		false,
		fmt.Sprintf("Display as list format"))

	f.BoolVar(&p.formatFullText,
		"format-full-text",
		false,
		fmt.Sprintf("Detail report in plain text"))

	f.BoolVar(&p.gzip, "gzip", false, "gzip compression")

	f.BoolVar(&p.toSlack, "to-slack", false, "Send report via Slack")
	f.BoolVar(&p.toStride, "to-stride", false, "Send report via Stride")
	f.BoolVar(&p.toHipChat, "to-hipchat", false, "Send report via hipchat")
	f.BoolVar(&p.toChatWork, "to-chatwork", false, "Send report via chatwork")
	f.BoolVar(&p.toEMail, "to-email", false, "Send report via Email")
	f.BoolVar(&p.toSyslog, "to-syslog", false, "Send report via Syslog")
	f.BoolVar(&p.toLocalFile,
		"to-localfile",
		false,
		fmt.Sprintf("Write report to localfile"))

	f.BoolVar(&p.toS3,
		"to-s3",
		false,
		"Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/xml/txt)")
	f.BoolVar(&p.toHTTP, "to-http", false, "Send report via HTTP POST")

	f.BoolVar(&p.toAzureBlob,
		"to-azure-blob",
		false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/xml/txt)")

	f.BoolVar(&p.uuid, "uuid", false, "Auto generate of scan target servers and then write to config.toml and scan result")

	f.BoolVar(
		&p.pipe,
		"pipe",
		false,
		"Use args passed via PIPE")
}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL
	c.Conf.LogDir = p.logDir
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(p.logDir, false, c.Conf.Debug, false)

	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.Lang = p.lang
	c.Conf.ResultsDir = p.resultsDir
	c.Conf.RefreshCve = p.refreshCve

	c.Conf.CvssScoreOver = p.cvssScoreOver
	c.Conf.IgnoreUnscoredCves = p.ignoreUnscoredCves
	c.Conf.IgnoreUnfixed = p.ignoreUnfixed
	c.Conf.HTTPProxy = p.httpProxy

	c.Conf.ToSlack = p.toSlack
	c.Conf.ToStride = p.toStride
	c.Conf.ToHipChat = p.toHipChat
	c.Conf.ToChatWork = p.toChatWork
	c.Conf.ToEmail = p.toEMail
	c.Conf.ToHTTP = p.toHTTP
	c.Conf.ToSyslog = p.toSyslog
	c.Conf.ToLocalFile = p.toLocalFile
	c.Conf.ToS3 = p.toS3
	c.Conf.ToAzureBlob = p.toAzureBlob

	c.Conf.FormatXML = p.formatXML
	c.Conf.FormatJSON = p.formatJSON
	c.Conf.FormatOneEMail = p.formatOneEMail
	c.Conf.FormatOneLineText = p.formatOneLineText
	c.Conf.FormatList = p.formatList
	c.Conf.FormatFullText = p.formatFullText

	c.Conf.GZIP = p.gzip
	c.Conf.Diff = p.diff
	c.Conf.Pipe = p.pipe
	c.Conf.UUID = p.uuid

	var dir string
	var err error
	if p.diff {
		dir, err = report.JSONDir([]string{})
	} else {
		dir, err = report.JSONDir(f.Args())
	}
	if err != nil {
		util.Log.Errorf("Failed to read from JSON: %s", err)
		return subcommands.ExitFailure
	}

	// report
	reports := []report.ResultWriter{
		report.StdoutWriter{},
	}

	if p.toSlack {
		reports = append(reports, report.SlackWriter{})
	}

	if p.toStride {
		reports = append(reports, report.StrideWriter{})
	}

	if p.toHipChat {
		reports = append(reports, report.HipChatWriter{})
	}

	if p.toChatWork {
		reports = append(reports, report.ChatWorkWriter{})
	}

	if p.toEMail {
		reports = append(reports, report.EMailWriter{})
	}

	if p.toSyslog {
		reports = append(reports, report.SyslogWriter{})
	}

	if p.toHTTP {
		reports = append(reports, report.HTTPRequestWriter{})
	}

	if p.toLocalFile {
		reports = append(reports, report.LocalFileWriter{
			CurrentDir: dir,
		})
	}

	if p.toS3 {
		if err := report.CheckIfBucketExists(); err != nil {
			util.Log.Errorf("Check if there is a bucket beforehand: %s, err: %s",
				c.Conf.AWS.S3Bucket, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.S3Writer{})
	}

	if p.toAzureBlob {
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
			util.Log.Errorf("Check if there is a container beforehand: %s, err: %s",
				c.Conf.Azure.ContainerName, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.AzureBlobWriter{})
	}

	if !(p.formatJSON || p.formatOneLineText ||
		p.formatList || p.formatFullText || p.formatXML) {
		c.Conf.FormatList = true
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}
	if err := report.CveClient.CheckHealth(); err != nil {
		util.Log.Errorf("CVE HTTP server is not running. err: %s", err)
		util.Log.Errorf("Run go-cve-dictionary as server mode before reporting or run with -cvedb-path option instead of -cvedb-url")
		return subcommands.ExitFailure
	}
	if c.Conf.CveDict.URL != "" {
		util.Log.Infof("cve-dictionary: %s", c.Conf.CveDict.URL)
	} else {
		if c.Conf.CveDict.Type == "sqlite3" {
			util.Log.Infof("cve-dictionary: %s", c.Conf.CveDict.Path)
		}
	}

	if c.Conf.OvalDict.URL != "" {
		util.Log.Infof("oval-dictionary: %s", c.Conf.OvalDict.URL)
		err := oval.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("OVAL HTTP server is not running. err: %s", err)
			util.Log.Errorf("Run goval-dictionary as server mode before reporting or run with -ovaldb-path option instead of -ovaldb-url")
			return subcommands.ExitFailure
		}
	} else {
		if c.Conf.OvalDict.Type == "sqlite3" {
			util.Log.Infof("oval-dictionary: %s", c.Conf.OvalDict.Path)
		}
	}

	if c.Conf.Gost.URL != "" {
		util.Log.Infof("gost: %s", c.Conf.Gost.URL)
		err := gost.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("gost HTTP server is not running. err: %s", err)
			util.Log.Errorf("Run gost as server mode before reporting or run with -gostdb-path option instead of -gostdb-url")
			return subcommands.ExitFailure
		}
	} else {
		if c.Conf.Gost.Type == "sqlite3" {
			util.Log.Infof("gost: %s", c.Conf.Gost.Path)
		}
	}

	var loaded models.ScanResults
	if loaded, err = report.LoadScanResults(dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	util.Log.Infof("Loaded: %s", dir)

	var res models.ScanResults
	for _, r := range loaded {
		if len(r.Errors) == 0 {
			res = append(res, r)
		} else {
			util.Log.Warnf("Ignored since errors occurred during scanning: %s",
				r.ServerName)
		}
	}

	for _, r := range res {
		util.Log.Debugf("%s: %s",
			r.ServerInfo(),
			pp.Sprintf("%s", c.Conf.Servers[r.ServerName]))
	}

	if c.Conf.UUID {
		// Ensure UUIDs of scan target servers in config.toml
		if err := report.EnsureUUIDs(p.configPath, res); err != nil {
			util.Log.Errorf("Failed to ensure UUIDs: %s", err)
			return subcommands.ExitFailure
		}
	}

	dbclient, locked, err := report.NewDBClient(report.DBClientConf{
		CveDictCnf:  c.Conf.CveDict,
		OvalDictCnf: c.Conf.OvalDict,
		GostCnf:     c.Conf.Gost,
		DebugSQL:    c.Conf.DebugSQL,
	})
	if locked {
		util.Log.Errorf("SQLite3 is locked. Close other DB connections and try again: %s", err)
		return subcommands.ExitFailure
	}
	if err != nil {
		util.Log.Errorf("Failed to init DB Clients: %s", err)
		return subcommands.ExitFailure
	}
	defer dbclient.CloseDB()

	if res, err = report.FillCveInfos(*dbclient, res, dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}

	for _, w := range reports {
		if err := w.Write(res...); err != nil {
			util.Log.Errorf("Failed to report: %s", err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
