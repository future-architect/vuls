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
	"strings"
	"text/template"

	"github.com/google/subcommands"

	ps "github.com/kotakanbe/go-pingscanner"
	"github.com/sirupsen/logrus"
)

// DiscoverCmd is Subcommand of host discovery mode
type DiscoverCmd struct {
}

// Name return subcommand name
func (*DiscoverCmd) Name() string { return "discover" }

// Synopsis return synopsis
func (*DiscoverCmd) Synopsis() string { return "Host discovery in the CIDR" }

// Usage return usage
func (*DiscoverCmd) Usage() string {
	return `discover:
	discover 192.168.0.0/24

`
}

// SetFlags set flag
func (p *DiscoverCmd) SetFlags(f *flag.FlagSet) {
}

// Execute execute
func (p *DiscoverCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// validate
	if len(f.Args()) == 0 {
		logrus.Errorf("Usage: " + p.Usage())
		return subcommands.ExitUsageError
	}

	for _, cidr := range f.Args() {
		scanner := ps.PingScanner{
			CIDR: cidr,
			PingOptions: []string{
				"-c1",
			},
			NumOfConcurrency: 100,
		}
		hosts, err := scanner.Scan()

		if err != nil {
			logrus.Errorf("Host Discovery failed. err: %s", err)
			return subcommands.ExitFailure
		}

		if len(hosts) < 1 {
			logrus.Errorf("Active hosts not found in %s", cidr)
			return subcommands.ExitSuccess
		} else if err := printConfigToml(hosts); err != nil {
			logrus.Errorf("Failed to parse template. err: %s", err)
			return subcommands.ExitFailure
		}
	}
	return subcommands.ExitSuccess
}

// Output the template of config.toml
func printConfigToml(ips []string) (err error) {
	const tomlTemplate = `

# https://vuls.io/docs/en/usage-settings.html
[cveDict]
type        = "sqlite3"
sqlite3Path = "/path/to/cve.sqlite3"
#url        = ""

[ovalDict]
type        = "sqlite3"
sqlite3Path = "/path/to/oval.sqlite3"
#url        = ""

[gost]
type        = "sqlite3"
sqlite3Path = "/path/to/gost.sqlite3"
#url        = ""

[exploit]
type        = "sqlite3"
sqlite3Path = "/path/to/go-exploitdb.sqlite3"
#url        = ""

# https://vuls.io/docs/en/usage-settings.html#slack-section
#[slack]
#hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
##legacyToken = "xoxp-11111111111-222222222222-3333333333"
#channel      = "#channel-name"
##channel     = "${servername}"
#iconEmoji    = ":ghost:"
#authUser     = "username"
#notifyUsers  = ["@username"]

# https://vuls.io/docs/en/usage-settings.html#email-section
#[email]
#smtpAddr      = "smtp.example.com"
#smtpPort      = "587"
#user          = "username"
#password      = "password"
#from          = "from@example.com"
#to            = ["to@example.com"]
#cc            = ["cc@example.com"]
#subjectPrefix = "[vuls]"

# https://vuls.io/docs/en/usage-settings.html#http-section
#[http]
#url = "http://localhost:11234"

# https://vuls.io/docs/en/usage-settings.html#syslog-section
#[syslog]
#protocol    = "tcp"
#host        = "localhost"
#port        = "514"
#tag         = "vuls"
#facility    = "local0"
#severity    = "alert"
#verbose     = false

# https://vuls.io/docs/en/usage-report.html#example-put-results-in-s3-bucket
#[aws]
#profile                = "default"
#region                 = "ap-northeast-1"
#s3Bucket               = "vuls"
#s3ResultsDir           = "/path/to/result"
#s3ServerSideEncryption = "AES256"

# https://vuls.io/docs/en/usage-report.html#example-put-results-in-azure-blob-storage<Paste>
#[azure]
#accountName   = "default"
#accountKey    = "xxxxxxxxxxxxxx"
#containerName = "vuls"

# https://vuls.io/docs/en/usage-settings.html#stride-section
#[stride]
#hookURL   = "xxxxxxxxxxxxxxx"
#authToken = "xxxxxxxxxxxxxx"

# https://vuls.io/docs/en/usage-settings.html#hipchat-section
#[hipchat]
#room      = "vuls"
#authToken = "xxxxxxxxxxxxxx"

# https://vuls.io/docs/en/usage-settings.html#chatwork-section
#[chatwork]
#room     = "xxxxxxxxxxx"
#apiToken = "xxxxxxxxxxxxxxxxxx"

# https://vuls.io/docs/en/usage-settings.html#telegram-section
#[telegram]
#chatID     = "xxxxxxxxxxx"
#token = "xxxxxxxxxxxxxxxxxx"

# https://vuls.io/docs/en/usage-settings.html#default-section
[default]
#port               = "22"
#user               = "username"
#keyPath            = "/home/username/.ssh/id_rsa"
#scanMode           = ["fast", "fast-root", "deep", "offline"]
#cpeNames = [
#  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
#]
#owaspDCXMLPath     = "/tmp/dependency-check-report.xml"
#ignoreCves         = ["CVE-2014-6271"]
#containerType      = "docker" #or "lxd" or "lxc" default: docker
#containersIncluded = ["${running}"]
#containersExcluded = ["container_name_a"]

# https://vuls.io/docs/en/usage-settings.html#servers-section
[servers]
{{- $names:=  .Names}}
{{range $i, $ip := .IPs}}
[servers.{{index $names $i}}]
host                = "{{$ip}}"
#port               = "22"
#user               = "root"
#keyPath            = "/home/username/.ssh/id_rsa"
#scanMode           = ["fast", "fast-root", "deep", "offline"]
#type               = "pseudo"
#memo               = "DB Server"
#cpeNames           = [ "cpe:/a:rubyonrails:ruby_on_rails:4.2.1" ]
#owaspDCXMLPath     = "/path/to/dependency-check-report.xml"
#ignoreCves         = ["CVE-2014-0160"]
#containerType      = "docker" #or "lxd" or "lxc" default: docker
#containersIncluded = ["${running}"]
#containersExcluded = ["container_name_a"]

#[servers.{{index $names $i}}.containers.container_name_a]
#cpeNames       = [ "cpe:/a:rubyonrails:ruby_on_rails:4.2.1" ]
#owaspDCXMLPath = "/path/to/dependency-check-report.xml"
#ignoreCves     = ["CVE-2014-0160"]

#[servers.{{index $names $i}}.githubs."owner/repo"]
#token   = "yourToken"

#[servers.{{index $names $i}}.wordpress]
#cmdPath = "/usr/local/bin/wp"
#osUser = "wordpress"
#docRoot = "/path/to/DocumentRoot/"
#wpVulnDBToken = "xxxxTokenxxxx"
#ignoreInactive = true

#[servers.{{index $names $i}}.optional]
#key = "value1"

{{end}}

`
	var tpl *template.Template
	if tpl, err = template.New("template").Parse(tomlTemplate); err != nil {
		return
	}

	type activeHosts struct {
		IPs   []string
		Names []string
	}

	a := activeHosts{IPs: ips}
	names := []string{}
	for _, ip := range ips {
		// TOML section header must not contain "."
		name := strings.Replace(ip, ".", "-", -1)
		names = append(names, name)
	}
	a.Names = names

	fmt.Println("# Create config.toml using below and then ./vuls -config=/path/to/config.toml")
	if err = tpl.Execute(os.Stdout, a); err != nil {
		return
	}
	return
}
