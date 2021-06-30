package reporter

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// GoogleChatWriter send report to GoogleChat
type GoogleChatWriter struct {
	Cnf   config.GoogleChatConf
	Proxy string
}

func (w GoogleChatWriter) Write(rs ...models.ScanResult) (err error) {
	re := regexp.MustCompile(w.Cnf.ServerNameRegexp)

	for _, r := range rs {
		if re.Match([]byte(r.FormatServerName())) {
			continue
		}
		msgs := []string{fmt.Sprintf("*%s*\n%s\t%s\t%s",
			r.ServerInfo(),
			r.ScannedCves.FormatCveSummary(),
			r.ScannedCves.FormatFixedStatus(r.Packages),
			r.FormatUpdatablePkgsSummary())}
		for _, vinfo := range r.ScannedCves.ToSortedSlice() {
			max := vinfo.MaxCvssScore().Value.Score

			exploits := ""
			if 0 < len(vinfo.Exploits) || 0 < len(vinfo.Metasploits) {
				exploits = "*PoC*"
			}

			link := ""
			if strings.HasPrefix(vinfo.CveID, "CVE-") {
				link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vinfo.CveID)
			} else if strings.HasPrefix(vinfo.CveID, "WPVDBID-") {
				link = fmt.Sprintf("https://wpscan.com/vulnerabilities/%s", strings.TrimPrefix(vinfo.CveID, "WPVDBID-"))
			}

			msgs = append(msgs, fmt.Sprintf(`%s %s %4.1f %5s %s`,
				vinfo.CveIDDiffFormat(),
				link,
				max,
				vinfo.AttackVector(),
				exploits))
			if len(msgs) == 50 {
				msgs = append(msgs, "(The rest is omitted.)")
				break
			}
		}
		if len(msgs) == 1 && w.Cnf.SkipIfNoCve {
			msgs = []string{}
		}
		if len(msgs) != 0 {
			if err = w.postMessage(strings.Join(msgs, "\n")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w GoogleChatWriter) postMessage(message string) error {
	uri := fmt.Sprintf("%s", w.Cnf.WebHookURL)
	payload := `{"text": "` + message + `" }`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBuffer([]byte(payload)))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	client, err := util.GetHTTPClient(w.Proxy)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if checkResponse(resp) != nil && err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (w GoogleChatWriter) checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return xerrors.Errorf("API call to %s failed: %s", r.Request.URL.String(), r.Status)
}
