package reporter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// ChatWorkWriter send report to ChatWork
type ChatWorkWriter struct {
	Cnf   config.ChatWorkConf
	Proxy string
}

func (w ChatWorkWriter) Write(rs ...models.ScanResult) (err error) {

	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		if err = w.chatWorkpostMessage(serverInfo); err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message := fmt.Sprintf(`%s[info][title]"https://nvd.nist.gov/vuln/detail/%s" %s %s[/title]%s[/info]`,
				serverInfo,
				vinfo.CveID,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity,
				vinfo.Summaries(r.Lang, r.Family)[0].Value)

			if err = w.chatWorkpostMessage(message); err != nil {
				return err
			}
		}

	}
	return nil
}

func (w ChatWorkWriter) chatWorkpostMessage(message string) error {
	uri := fmt.Sprintf("https://api.chatwork.com/v2/rooms/%s/messages=%s", w.Cnf.Room, w.Cnf.APIToken)
	payload := url.Values{"body": {message}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(payload.Encode()))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Add("X-ChatWorkToken", w.Cnf.APIToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client, err := util.GetHTTPClient(w.Proxy)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
