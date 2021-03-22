package reporter

import (
	"fmt"
	"log/syslog"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// SyslogWriter send report to syslog
type SyslogWriter struct {
	Cnf config.SyslogConf
}

func (w SyslogWriter) Write(rs ...models.ScanResult) (err error) {
	facility, _ := w.Cnf.GetFacility()
	severity, _ := w.Cnf.GetSeverity()
	raddr := fmt.Sprintf("%s:%s", w.Cnf.Host, w.Cnf.Port)

	sysLog, err := syslog.Dial(w.Cnf.Protocol, raddr, severity|facility, w.Cnf.Tag)
	if err != nil {
		return xerrors.Errorf("Failed to initialize syslog client: %w", err)
	}

	for _, r := range rs {
		messages := w.encodeSyslog(r)
		for _, m := range messages {
			if _, err = fmt.Fprint(sysLog, m); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w SyslogWriter) encodeSyslog(result models.ScanResult) (messages []string) {
	ipv4Addrs := strings.Join(result.IPv4Addrs, ",")
	ipv6Addrs := strings.Join(result.IPv6Addrs, ",")

	var commonKvPairs []string
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`scanned_at="%s"`, result.ScannedAt))
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`server_name="%s"`, result.ServerName))
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`os_family="%s"`, result.Family))
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`os_release="%s"`, result.Release))
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`ipv4_addr="%s"`, ipv4Addrs))
	commonKvPairs = append(commonKvPairs, fmt.Sprintf(`ipv6_addr="%s"`, ipv6Addrs))

	for cveID, vinfo := range result.ScannedCves {
		kvPairs := commonKvPairs

		var pkgNames []string
		for _, pkg := range vinfo.AffectedPackages {
			pkgNames = append(pkgNames, pkg.Name)
		}
		pkgs := strings.Join(pkgNames, ",")
		kvPairs = append(kvPairs, fmt.Sprintf(`packages="%s"`, pkgs))

		kvPairs = append(kvPairs, fmt.Sprintf(`cve_id="%s"`, cveID))
		for _, cvss := range vinfo.Cvss2Scores() {
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_score_%s_v2="%.2f"`, cvss.Type, cvss.Value.Score))
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_vector_%s_v2="%s"`, cvss.Type, cvss.Value.Vector))
		}

		for _, cvss := range vinfo.Cvss3Scores() {
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_score_%s_v3="%.2f"`, cvss.Type, cvss.Value.Score))
			kvPairs = append(kvPairs, fmt.Sprintf(`cvss_vector_%s_v3="%s"`, cvss.Type, cvss.Value.Vector))
		}

		if content, ok := vinfo.CveContents[models.Nvd]; ok {
			cwes := strings.Join(content.CweIDs, ",")
			kvPairs = append(kvPairs, fmt.Sprintf(`cwe_ids="%s"`, cwes))
			if w.Cnf.Verbose {
				kvPairs = append(kvPairs, fmt.Sprintf(`source_link="%s"`, content.SourceLink))
				kvPairs = append(kvPairs, fmt.Sprintf(`summary="%s"`, content.Summary))
			}
		}
		if content, ok := vinfo.CveContents[models.RedHat]; ok {
			kvPairs = append(kvPairs, fmt.Sprintf(`title="%s"`, content.Title))
		}

		// message: key1="value1" key2="value2"...
		messages = append(messages, strings.Join(kvPairs, " "))
	}

	if len(messages) == 0 {
		commonKvPairs = append(commonKvPairs, `message="No CVE-IDs are found"`)
		messages = append(messages, strings.Join(commonKvPairs, " "))
	}
	return messages
}
