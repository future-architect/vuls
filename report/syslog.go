/* Vuls - Vulnerability Scanner
Copyright (C) 2018  Future Architect, Inc. Japan.

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

package report

import (
	"fmt"
	"log/syslog"
	"strings"

	"github.com/pkg/errors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// SyslogWriter send report to syslog
type SyslogWriter struct{}

func (w SyslogWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Syslog
	facility, _ := conf.GetFacility()
	severity, _ := conf.GetSeverity()
	raddr := fmt.Sprintf("%s:%s", conf.Host, conf.Port)

	sysLog, err := syslog.Dial(conf.Protocol, raddr, severity|facility, conf.Tag)
	if err != nil {
		return errors.Wrap(err, "Failed to initialize syslog client")
	}

	for _, r := range rs {
		messages := w.encodeSyslog(r)
		for _, m := range messages {
			if _, err = fmt.Fprintf(sysLog, m); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w SyslogWriter) encodeSyslog(result models.ScanResult) (messages []string) {
	ipv4Addrs := strings.Join(result.IPv4Addrs, ",")
	ipv6Addrs := strings.Join(result.IPv6Addrs, ",")

	for cveID, vinfo := range result.ScannedCves {
		var kvPairs []string
		kvPairs = append(kvPairs, fmt.Sprintf(`scanned_at="%s"`, result.ScannedAt))
		kvPairs = append(kvPairs, fmt.Sprintf(`server_name="%s"`, result.ServerName))
		kvPairs = append(kvPairs, fmt.Sprintf(`os_family="%s"`, result.Family))
		kvPairs = append(kvPairs, fmt.Sprintf(`os_release="%s"`, result.Release))
		kvPairs = append(kvPairs, fmt.Sprintf(`ipv4_addr="%s"`, ipv4Addrs))
		kvPairs = append(kvPairs, fmt.Sprintf(`ipv6_addr="%s"`, ipv6Addrs))

		var pkgNames []string
		for _, pkg := range vinfo.AffectedPackages {
			pkgNames = append(pkgNames, pkg.Name)
		}
		pkgs := strings.Join(pkgNames, ",")
		kvPairs = append(kvPairs, fmt.Sprintf(`packages="%s"`, pkgs))

		kvPairs = append(kvPairs, fmt.Sprintf(`cve_id="%s"`, cveID))
		for _, cvss := range vinfo.Cvss2Scores() {
			if cvss.Type != models.NVD {
				continue
			}
			kvPairs = append(kvPairs, fmt.Sprintf(`severity="%s"`, cvss.Value.Severity))
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_score_v2="%.2f"`, cvss.Value.Score))
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_vector_v2="%s"`, cvss.Value.Vector))
		}

		if content, ok := vinfo.CveContents[models.NVD]; ok {
			kvPairs = append(kvPairs, fmt.Sprintf(`cwe_id="%s"`, content.CweID))
			if config.Conf.Syslog.Verbose {
				kvPairs = append(kvPairs, fmt.Sprintf(`source_link="%s"`, content.SourceLink))
				kvPairs = append(kvPairs, fmt.Sprintf(`summary="%s"`, content.Summary))
			}
		}

		// message: key1="value1" key2="value2"...
		messages = append(messages, strings.Join(kvPairs, " "))
	}
	return messages
}
