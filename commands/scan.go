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
	"fmt"
	"os"
	"path/filepath"

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
	cvedbpath        string
	cveDictionaryURL string

	cvssScoreOver      float64
	ignoreUnscoredCves bool

	httpProxy string

	// reporting
	reportSlack bool
	reportMail  bool
	reportJSON  bool
	reportText  bool
	reportS3    bool

	askSudoPassword bool
	askKeyPassword  bool

	useYumPluginSecurity  bool
	useUnattendedUpgrades bool

	awsProfile  string
	awsS3Bucket string
	awsRegion   string

	sshExternal bool
}

// Name return subcommand name
func (*ScanCmd) Name() string { return "scan" }

// Synopsis return synopsis
func (*ScanCmd) Synopsis() string { return "Scan vulnerabilities" }

// Usage return usage
func (*ScanCmd) Usage() string {
	return `scan:
	scan
		[SERVER]...
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-dbpath=/path/to/vuls.sqlite3]
		[-cve-dictionary-dbpath=/path/to/cve.sqlite3]
		[-cve-dictionary-url=http://127.0.0.1:1323]
		[-cvss-over=7]
		[-ignore-unscored-cves]
		[-ssh-external]
		[-report-json]
		[-report-mail]
		[-report-s3]
		[-report-slack]
		[-report-text]
		[-http-proxy=http://192.168.0.1:8080]
		[-ask-sudo-password]
		[-ask-key-password]
		[-debug]
		[-debug-sql]
		[-aws-profile=default]
		[-aws-region=us-west-2]
		[-aws-s3-bucket=bucket_name]
`
}

// SetFlags set flag
func (p *ScanCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultDBPath := filepath.Join(wd, "vuls.sqlite3")
	f.StringVar(&p.dbpath, "dbpath", defaultDBPath, "/path/to/sqlite3")

	f.StringVar(
		&p.cvedbpath,
		"cve-dictionary-dbpath",
		"",
		"/path/to/sqlite3 (For get cve detail from cve.sqlite3)")

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

	f.BoolVar(
		&p.ignoreUnscoredCves,
		"ignore-unscored-cves",
		false,
		"Don't report the unscored CVEs")

	f.BoolVar(
		&p.sshExternal,
		"ssh-external",
		false,
		"Use external ssh command. Default: Use the Go native implementation")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)

	f.BoolVar(&p.reportSlack, "report-slack", false, "Send report via Slack")
	f.BoolVar(&p.reportMail, "report-mail", false, "Send report via Email")
	f.BoolVar(&p.reportJSON,
		"report-json",
		false,
		fmt.Sprintf("Write report to JSON files (%s/results/current)", wd),
	)
	f.BoolVar(&p.reportText,
		"report-text",
		false,
		fmt.Sprintf("Write report to text files (%s/results/current)", wd),
	)

	f.BoolVar(&p.reportS3,
		"report-s3",
		false,
		"Write report to S3 (bucket/yyyyMMdd_HHmm)",
	)
	f.StringVar(&p.awsProfile, "aws-profile", "default", "AWS Profile to use")
	f.StringVar(&p.awsRegion, "aws-region", "us-east-1", "AWS Region to use")
	f.StringVar(&p.awsS3Bucket, "aws-s3-bucket", "", "S3 bucket name")

	f.BoolVar(
		&p.askKeyPassword,
		"ask-key-password",
		false,
		"Ask ssh privatekey password before scanning",
	)

	f.BoolVar(
		&p.askSudoPassword,
		"ask-sudo-password",
		false,
		"Ask sudo password of target servers before scanning",
	)

	f.BoolVar(
		&p.useYumPluginSecurity,
		"use-yum-plugin-security",
		false,
		"[Deprecated] For CentOS 5. Scan by yum-plugin-security or not (use yum check-update by default)",
	)

	f.BoolVar(
		&p.useUnattendedUpgrades,
		"use-unattended-upgrades",
		false,
		"[Deprecated] For Ubuntu. Scan by unattended-upgrades or not (use apt-get upgrade --dry-run by default)",
	)

}

// Execute execute
func (p *ScanCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var keyPass, sudoPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			logrus.Error(err)
			return subcommands.ExitFailure
		}
	}
	if p.askSudoPassword {
		prompt := "sudo password: "
		if sudoPass, err = getPasswd(prompt); err != nil {
			logrus.Error(err)
			return subcommands.ExitFailure
		}
	}

	err = c.Load(p.configPath, keyPass, sudoPass)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	logrus.Info("Start scanning")
	logrus.Infof("config: %s", p.configPath)
	if p.cvedbpath != "" {
		logrus.Infof("cve-dictionary: %s", p.cvedbpath)
	} else {
		logrus.Infof("cve-dictionary: %s", p.cveDictionaryURL)
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
		report.StdoutWriter{},
		report.LogrusWriter{},
	}
	if p.reportSlack {
		reports = append(reports, report.SlackWriter{})
	}
	if p.reportMail {
		reports = append(reports, report.MailWriter{})
	}
	if p.reportJSON {
		reports = append(reports, report.JSONWriter{})
	}
	if p.reportText {
		reports = append(reports, report.TextFileWriter{})
	}
	if p.reportS3 {
		c.Conf.AwsRegion = p.awsRegion
		c.Conf.AwsProfile = p.awsProfile
		c.Conf.S3Bucket = p.awsS3Bucket
		if err := report.CheckIfBucketExists(); err != nil {
			Log.Errorf("Failed to access to the S3 bucket. err: %s", err)
			Log.Error("Ensure the bucket or check AWS config before scanning")
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.S3Writer{})
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.CveDBPath = p.cvedbpath
	c.Conf.CveDictionaryURL = p.cveDictionaryURL
	c.Conf.CvssScoreOver = p.cvssScoreOver
	c.Conf.IgnoreUnscoredCves = p.ignoreUnscoredCves
	c.Conf.SSHExternal = p.sshExternal
	c.Conf.HTTPProxy = p.httpProxy
	c.Conf.UseYumPluginSecurity = p.useYumPluginSecurity
	c.Conf.UseUnattendedUpgrades = p.useUnattendedUpgrades

	Log.Info("Validating Config...")
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if ok, err := cveapi.CveClient.CheckHealth(); !ok {
		Log.Errorf("CVE HTTP server is not running. err: %s", err)
		Log.Errorf("Run go-cve-dictionary as server mode or specify -cve-dictionary-dbpath option")
		return subcommands.ExitFailure
	}

	Log.Info("Detecting Server OS... ")
	err = scan.InitServers(Log)
	if err != nil {
		Log.Errorf("Failed to init servers. Check the configuration. err: %s", err)
		return subcommands.ExitFailure
	}

	Log.Info("Scanning vulnerabilities... ")
	if errs := scan.Scan(); 0 < len(errs) {
		for _, e := range errs {
			Log.Errorf("Failed to scan. err: %s", e)
		}
		return subcommands.ExitFailure
	}

	scanResults, err := scan.GetScanResults()
	if err != nil {
		Log.Fatal(err)
		return subcommands.ExitFailure
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

	Log.Info("Reporting...")
	filtered := scanResults.FilterByCvssOver()
	for _, w := range reports {
		if err := w.Write(filtered); err != nil {
			Log.Fatalf("Failed to report, err: %s", err)
			return subcommands.ExitFailure
		}
	}

	return subcommands.ExitSuccess
}
