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

// GoogleChatWriter send report to GoogleChat
type GoogleChatWriter struct {
	Cnf   config.GoogleChatConf
	Proxy string
}

func (w GoogleChatWriter) Write(rs ...models.ScanResult) (err error) {

	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		if err = w.googleChatpostMessage(serverInfo); err != nil {
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

			if err = w.googleChatpostMessage(message); err != nil {
				return err
			}
		}

	}
	return nil
}

func (w GoogleChatWriter) googleChatpostMessage(message string) error {
	uri := fmt.Sprintf("%s", w.Cnf.WebHookURL)
	payload := url.Values{"body": {message}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(payload.Encode()))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
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
