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
	"strings"
	"text/template"

	"github.com/google/subcommands"
	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	ps "github.com/kotakanbe/go-pingscanner"
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
		return subcommands.ExitUsageError
	}

	for _, cidr := range f.Args() {
		scanner := ps.PingScanner{
			CIDR: cidr,
			PingOptions: []string{
				"-c1",
				"-t1",
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

// Output the tmeplate of config.toml
func printConfigToml(ips []string) (err error) {
	const tomlTempale = `
[slack]
hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
channel      = "#channel-name"
#channel      = "#{servername}"
iconEmoji    = ":ghost:"
authUser     = "username"
notifyUsers  = ["@username"]

[mail]
smtpAddr      = "smtp.gmail.com"
smtpPort      = 465
user          = "username"
password      = "password"
from          = "from@address.com"
to            = ["to@address.com"]
cc            = ["cc@address.com"]
subjectPrefix = "[vuls]"

[default]
#port        = "22"
#user        = "username"
#password    = "password"
#keyPath     = "/home/username/.ssh/id_rsa"
#keyPassword = "password"

[servers]
{{- $names:=  .Names}}
{{range $i, $ip := .IPs}}
[servers.{{index $names $i}}]
host         = "{{$ip}}"
#port        = "22"
#user        = "root"
#password    = "password"
#keyPath     = "/home/username/.ssh/id_rsa"
#keyPassword = "password"
#cpeNames = [
#  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
#]
{{end}}

`
	var tpl *template.Template
	if tpl, err = template.New("tempalte").Parse(tomlTempale); err != nil {
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

	fmt.Println("# Create config.toml using below and then ./vuls --config=/path/to/config.toml")
	if err = tpl.Execute(os.Stdout, a); err != nil {
		return
	}
	return
}
