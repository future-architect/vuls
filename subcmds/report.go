// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/future-architect/vuls/config"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// ReportCmd is subcommand for reporting
type ReportCmd struct {
	configPath string
	httpConf   c.HTTPConf
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
		[-diff-minus]
		[-diff-plus]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-ignore-github-dismissed]
		[-to-email]
		[-to-http]
		[-to-slack]
		[-to-chatwork]
		[-to-telegram]
		[-to-localfile]
		[-to-s3]
		[-to-azure-blob]
		[-format-json]
		[-format-one-email]
		[-format-one-line-text]
		[-format-list]
		[-format-full-text]
		[-gzip]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-progress]
		[-pipe]
		[-http="http://vuls-report-server"]
		[-trivy-cachedb-dir=/path/to/dir]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ReportCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")
	f.BoolVar(&c.Conf.NoProgress, "no-progress", false, "Suppress progress bar")

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

	f.BoolVar(&c.Conf.DiffMinus, "diff-minus", false,
		"Minus Difference between previous result and current result")

	f.BoolVar(&c.Conf.DiffPlus, "diff-plus", false,
		"Plus Difference between previous result and current result")

	f.BoolVar(&c.Conf.Diff, "diff", false,
		"Plus & Minus Difference between previous result and current result")

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
	f.BoolVar(&c.Conf.FormatCsvList, "format-csv", false, "CSV format")
	f.BoolVar(&c.Conf.FormatOneEMail, "format-one-email", false,
		"Send all the host report via only one EMail (Specify with -to-email)")
	f.BoolVar(&c.Conf.FormatOneLineText, "format-one-line-text", false,
		"One line summary in plain text")
	f.BoolVar(&c.Conf.FormatList, "format-list", false, "Display as list format")
	f.BoolVar(&c.Conf.FormatFullText, "format-full-text", false,
		"Detail report in plain text")

	f.BoolVar(&c.Conf.ToSlack, "to-slack", false, "Send report via Slack")
	f.BoolVar(&c.Conf.ToChatWork, "to-chatwork", false, "Send report via chatwork")
	f.BoolVar(&c.Conf.ToTelegram, "to-telegram", false, "Send report via Telegram")
	f.BoolVar(&c.Conf.ToEmail, "to-email", false, "Send report via Email")
	f.BoolVar(&c.Conf.ToSyslog, "to-syslog", false, "Send report via Syslog")
	f.BoolVar(&c.Conf.ToLocalFile, "to-localfile", false, "Write report to localfile")
	f.BoolVar(&c.Conf.ToS3, "to-s3", false,
		"Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/txt)")
	f.BoolVar(&c.Conf.ToHTTP, "to-http", false, "Send report via HTTP POST")
	f.BoolVar(&c.Conf.ToAzureBlob, "to-azure-blob", false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/txt)")

	f.BoolVar(&c.Conf.GZIP, "gzip", false, "gzip compression")
	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use args passed via PIPE")

	f.StringVar(&p.httpConf.URL, "http", "", "-to-http http://vuls-report")

	f.StringVar(&c.Conf.TrivyCacheDBDir, "trivy-cachedb-dir",
		utils.DefaultCacheDir(), "/path/to/dir")
}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}
	c.Conf.HTTP.Init(p.httpConf)

	if c.Conf.Diff {
		c.Conf.DiffPlus = true
		c.Conf.DiffMinus = true
	}

	var dir string
	var err error
	if c.Conf.DiffPlus || c.Conf.DiffMinus {
		dir, err = report.JSONDir([]string{})
	} else {
		dir, err = report.JSONDir(f.Args())
	}
	if err != nil {
		util.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	if !(c.Conf.FormatJSON || c.Conf.FormatOneLineText ||
		c.Conf.FormatList || c.Conf.FormatFullText || c.Conf.FormatCsvList) {
		c.Conf.FormatList = true
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

	util.Log.Info("Validating db config...")
	if !c.Conf.ValidateOnReportDB() {
		return subcommands.ExitUsageError
	}

	for _, cnf := range []config.VulnSrcConf{
		&c.Conf.CveDict,
		&c.Conf.OvalDict,
		&c.Conf.Gost,
		&c.Conf.Exploit,
		&c.Conf.Metasploit,
	} {
		if err := cnf.CheckHTTPHealth(); err != nil {
			util.Log.Errorf("Run as server mode before reporting: %+v", err)
			return subcommands.ExitFailure
		}
	}

	dbclient, locked, err := report.NewDBClient(report.DBClientConf{
		CveDictCnf:    c.Conf.CveDict,
		OvalDictCnf:   c.Conf.OvalDict,
		GostCnf:       c.Conf.Gost,
		ExploitCnf:    c.Conf.Exploit,
		MetasploitCnf: c.Conf.Metasploit,
		DebugSQL:      c.Conf.DebugSQL,
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

	// report
	reports := []report.ResultWriter{
		report.StdoutWriter{},
	}

	if c.Conf.ToSlack {
		reports = append(reports, report.SlackWriter{})
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
			DiffPlus:   c.Conf.DiffPlus,
			DiffMinus:  c.Conf.DiffMinus,
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
