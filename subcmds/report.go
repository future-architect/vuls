// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/future-architect/vuls/config"
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

	toSlack      bool
	toChatWork   bool
	toGoogleChat bool
	toTelegram   bool
	toEmail      bool
	toSyslog     bool
	toLocalFile  bool
	toS3         bool
	toAzureBlob  bool
	toHTTP       bool
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
		[-log-to-file]
		[-log-dir=/path/to/log]
		[-refresh-cve]
		[-cvss-over=7]
		[-diff]
		[-diff-minus]
		[-diff-plus]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-to-email]
		[-to-http]
		[-to-slack]
		[-to-chatwork]
		[-to-googlechat]
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
	f.StringVar(&config.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&config.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&config.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&config.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")
	f.BoolVar(&config.Conf.NoProgress, "no-progress", false, "Suppress progress bar")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "Output log to file")

	f.BoolVar(&config.Conf.RefreshCve, "refresh-cve", false,
		"Refresh CVE information in JSON file under results dir")

	f.Float64Var(&config.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(&config.Conf.DiffMinus, "diff-minus", false,
		"Minus Difference between previous result and current result")

	f.BoolVar(&config.Conf.DiffPlus, "diff-plus", false,
		"Plus Difference between previous result and current result")

	f.BoolVar(&config.Conf.Diff, "diff", false,
		"Plus & Minus Difference between previous result and current result")

	f.BoolVar(&config.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't report the unscored CVEs")

	f.BoolVar(&config.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't report the unfixed CVEs")

	f.StringVar(
		&config.Conf.HTTPProxy, "http-proxy", "",
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
	f.BoolVar(&p.toGoogleChat, "to-googlechat", false, "Send report via Google Chat")
	f.BoolVar(&p.toTelegram, "to-telegram", false, "Send report via Telegram")
	f.BoolVar(&p.toEmail, "to-email", false, "Send report via Email")
	f.BoolVar(&p.toSyslog, "to-syslog", false, "Send report via Syslog")
	f.BoolVar(&p.toLocalFile, "to-localfile", false, "Write report to localfile")
	f.BoolVar(&p.toS3, "to-s3", false, "Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/txt)")
	f.BoolVar(&p.toHTTP, "to-http", false, "Send report via HTTP POST")
	f.BoolVar(&p.toAzureBlob, "to-azure-blob", false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/txt)")

	f.BoolVar(&p.gzip, "gzip", false, "gzip compression")
	f.BoolVar(&config.Conf.Pipe, "pipe", false, "Use args passed via PIPE")

	f.StringVar(&config.Conf.TrivyCacheDBDir, "trivy-cachedb-dir",
		utils.DefaultCacheDir(), "/path/to/dir")
}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)

	if err := config.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}
	config.Conf.Slack.Enabled = p.toSlack
	config.Conf.ChatWork.Enabled = p.toChatWork
	config.Conf.GoogleChat.Enabled = p.toGoogleChat
	config.Conf.Telegram.Enabled = p.toTelegram
	config.Conf.EMail.Enabled = p.toEmail
	config.Conf.Syslog.Enabled = p.toSyslog
	config.Conf.AWS.Enabled = p.toS3
	config.Conf.Azure.Enabled = p.toAzureBlob
	config.Conf.HTTP.Enabled = p.toHTTP

	if config.Conf.Diff {
		config.Conf.DiffPlus, config.Conf.DiffMinus = true, true
	}

	var dir string
	var err error
	if config.Conf.DiffPlus || config.Conf.DiffMinus {
		dir, err = reporter.JSONDir(config.Conf.ResultsDir, []string{})
	} else {
		dir, err = reporter.JSONDir(config.Conf.ResultsDir, f.Args())
	}
	if err != nil {
		logging.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
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
			r.ServerInfo(), pp.Sprintf("%s", config.Conf.Servers[r.ServerName]))
	}

	if res, err = detector.Detect(res, dir); err != nil {
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
			Cnf:               config.Conf.Slack,
			Proxy:             config.Conf.HTTPProxy,
		})
	}

	if p.toChatWork {
		reports = append(reports, reporter.ChatWorkWriter{Cnf: config.Conf.ChatWork, Proxy: config.Conf.HTTPProxy})
	}

	if p.toGoogleChat {
		reports = append(reports, reporter.GoogleChatWriter{Cnf: config.Conf.GoogleChat, Proxy: config.Conf.HTTPProxy})
	}

	if p.toTelegram {
		reports = append(reports, reporter.TelegramWriter{Cnf: config.Conf.Telegram})
	}

	if p.toEmail {
		reports = append(reports, reporter.EMailWriter{
			FormatOneEMail:    p.formatOneEMail,
			FormatOneLineText: p.formatOneLineText,
			FormatList:        p.formatList,
			Cnf:               config.Conf.EMail,
		})
	}

	if p.toSyslog {
		reports = append(reports, reporter.SyslogWriter{Cnf: config.Conf.Syslog})
	}

	if p.toHTTP {
		reports = append(reports, reporter.HTTPRequestWriter{URL: config.Conf.HTTP.URL})
	}

	if p.toLocalFile {
		reports = append(reports, reporter.LocalFileWriter{
			CurrentDir:        dir,
			DiffPlus:          config.Conf.DiffPlus,
			DiffMinus:         config.Conf.DiffMinus,
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
			AWSConf:           config.Conf.AWS,
		}
		if err := w.Validate(); err != nil {
			logging.Log.Errorf("Check if there is a bucket beforehand: %s, err: %+v", config.Conf.AWS.S3Bucket, err)
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
			AzureConf:         config.Conf.Azure,
		}
		if err := w.Validate(); err != nil {
			logging.Log.Errorf("Check if there is a container beforehand: %s, err: %+v", config.Conf.Azure.ContainerName, err)
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
