// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/utils"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// ReportCmd is subcommand for reporting
type ReportCmd struct {
	configPath string

	formatJSON        bool
	formatOneEMail    bool
	formatCsv         bool
	formatFullText    bool
	formatOneLineText bool
	formatList        bool
	gzip              bool

	toSlack     bool
	toChatWork  bool
	toTelegram  bool
	toEmail     bool
	toSyslog    bool
	toLocalFile bool
	toS3        bool
	toAzureBlob bool
	toHTTP      bool
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

	defaultLogDir := logging.GetDefaultLogDir()
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

	f.BoolVar(&p.formatJSON, "format-json", false, "JSON format")
	f.BoolVar(&p.formatCsv, "format-csv", false, "CSV format")
	f.BoolVar(&p.formatOneEMail, "format-one-email", false,
		"Send all the host report via only one EMail (Specify with -to-email)")
	f.BoolVar(&p.formatOneLineText, "format-one-line-text", false,
		"One line summary in plain text")
	f.BoolVar(&p.formatList, "format-list", false, "Display as list format")
	f.BoolVar(&p.formatFullText, "format-full-text", false,
		"Detail report in plain text")

	f.BoolVar(&p.toSlack, "to-slack", false, "Send report via Slack")
	f.BoolVar(&p.toChatWork, "to-chatwork", false, "Send report via chatwork")
	f.BoolVar(&p.toTelegram, "to-telegram", false, "Send report via Telegram")
	f.BoolVar(&p.toEmail, "to-email", false, "Send report via Email")
	f.BoolVar(&p.toSyslog, "to-syslog", false, "Send report via Syslog")
	f.BoolVar(&p.toLocalFile, "to-localfile", false, "Write report to localfile")
	f.BoolVar(&p.toS3, "to-s3", false, "Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/txt)")
	f.BoolVar(&p.toHTTP, "to-http", false, "Send report via HTTP POST")
	f.BoolVar(&p.toAzureBlob, "to-azure-blob", false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/txt)")

	f.BoolVar(&p.gzip, "gzip", false, "gzip compression")
	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use args passed via PIPE")

	f.StringVar(&c.Conf.TrivyCacheDBDir, "trivy-cachedb-dir",
		utils.DefaultCacheDir(), "/path/to/dir")
}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(c.Conf.Debug, c.Conf.Quiet, c.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", c.Version, c.Revision)

	if err := c.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}
	c.Conf.Slack.Enabled = p.toSlack
	c.Conf.ChatWork.Enabled = p.toChatWork
	c.Conf.Telegram.Enabled = p.toTelegram
	c.Conf.EMail.Enabled = p.toEmail
	c.Conf.Syslog.Enabled = p.toSyslog
	c.Conf.AWS.Enabled = p.toS3
	c.Conf.Azure.Enabled = p.toAzureBlob
	c.Conf.HTTP.Enabled = p.toHTTP

	if c.Conf.Diff {
		c.Conf.DiffPlus, c.Conf.DiffMinus = true, true
	}

	var dir string
	var err error
	if c.Conf.DiffPlus || c.Conf.DiffMinus {
		dir, err = reporter.JSONDir([]string{})
	} else {
		dir, err = reporter.JSONDir(f.Args())
	}
	if err != nil {
		logging.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	if !(p.formatJSON || p.formatOneLineText ||
		p.formatList || p.formatFullText || p.formatCsv) {
		p.formatList = true
	}

	var loaded models.ScanResults
	if loaded, err = reporter.LoadScanResults(dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}
	logging.Log.Infof("Loaded: %s", dir)

	var res models.ScanResults
	hasError := false
	for _, r := range loaded {
		if len(r.Errors) == 0 {
			res = append(res, r)
		} else {
			logging.Log.Errorf("Ignored since errors occurred during scanning: %s, err: %v",
				r.ServerName, r.Errors)
			hasError = true
		}
	}

	if len(res) == 0 {
		return subcommands.ExitFailure
	}

	for _, r := range res {
		logging.Log.Debugf("%s: %s",
			r.ServerInfo(), pp.Sprintf("%s", c.Conf.Servers[r.ServerName]))
	}

	dbclient, err := detector.NewDBClient(
		&c.Conf.CveDict,
		&c.Conf.OvalDict,
		&c.Conf.Gost,
		&c.Conf.Exploit,
		&c.Conf.Metasploit,
		c.Conf.DebugSQL,
	)
	if err != nil {
		logging.Log.Errorf("Failed to init DB Clients. err: %+v", err)
		return subcommands.ExitFailure
	}
	defer func() {
		for _, err := range dbclient.CloseDB() {
			logging.Log.Errorf("Failed to CloseDB. err: %+v", err)
		}
	}()

	if res, err = detector.Detect(*dbclient, res, dir); err != nil {
		logging.Log.Errorf("%+v", err)
		return subcommands.ExitFailure
	}

	// report
	reports := []reporter.ResultWriter{
		reporter.StdoutWriter{
			FormatCsv:         p.formatCsv,
			FormatFullText:    p.formatFullText,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
		},
	}

	if p.toSlack {
		reports = append(reports, reporter.SlackWriter{
			FormatOneLineText: p.formatOneLineText,
		})
	}

	if p.toChatWork {
		reports = append(reports, reporter.ChatWorkWriter{})
	}

	if p.toTelegram {
		reports = append(reports, reporter.TelegramWriter{})
	}

	if p.toEmail {
		reports = append(reports, reporter.EMailWriter{
			FormatOneEMail:    p.formatOneEMail,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
		})
	}

	if p.toSyslog {
		reports = append(reports, reporter.SyslogWriter{})
	}

	if p.toHTTP {
		reports = append(reports, reporter.HTTPRequestWriter{})
	}

	if p.toLocalFile {
		reports = append(reports, reporter.LocalFileWriter{
			CurrentDir:        dir,
			DiffPlus:          c.Conf.DiffPlus,
			DiffMinus:         c.Conf.DiffMinus,
			FormatJSON:        p.formatJSON,
			FormatCsv:         p.formatCsv,
			FormatFullText:    p.formatFullText,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
			Gzip:              p.gzip,
		})
	}

	if p.toS3 {
		w := reporter.S3Writer{
			FormatJSON:        p.formatJSON,
			FormatFullText:    p.formatFullText,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
			Gzip:              p.gzip,
			AWSConf:           c.Conf.AWS,
		}
		if err := w.Validate(); err != nil {
			logging.Log.Errorf("Check if there is a bucket beforehand: %s, err: %+v", c.Conf.AWS.S3Bucket, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, w)
	}

	if p.toAzureBlob {
		w := reporter.AzureBlobWriter{
			FormatJSON:        p.formatJSON,
			FormatFullText:    p.formatFullText,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
			Gzip:              p.gzip,
			AzureConf:         c.Conf.Azure,
		}
		if err := w.Validate(); err != nil {
			logging.Log.Errorf("Check if there is a container beforehand: %s, err: %+v", c.Conf.Azure.ContainerName, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, w)
	}

	for _, w := range reports {
		if err := w.Write(res...); err != nil {
			logging.Log.Errorf("Failed to report. err: %+v", err)
			return subcommands.ExitFailure
		}
	}

	if hasError {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
