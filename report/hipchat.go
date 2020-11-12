package report

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// HipChatWriter send report to HipChat
type HipChatWriter struct{}

func (w HipChatWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.HipChat

	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		if err = postMessage(conf.Room, conf.AuthToken, serverInfo); err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message := fmt.Sprintf(`<a href="https://nvd.nist.gov/vuln/detail\%s"> %s </a> <br/>%s (%s)<br/>%s`,
				vinfo.CveID,
				vinfo.CveID,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity,
				vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value,
			)

			if err = postMessage(conf.Room, conf.AuthToken, message); err != nil {
				return err
			}
		}

	}
	return nil
}

func postMessage(room, token, message string) error {
	uri := fmt.Sprintf("https://api.hipchat.com/v2/room/%s/notification?auth_token=%s", room, token)

	payload := url.Values{
		"color":          {"purple"},
		"message_format": {"html"},
		"message":        {message},
	}
	reqs, err := http.NewRequest("POST", uri, strings.NewReader(payload.Encode()))
	if err != nil {
		return err
	}

	reqs.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}

	resp, err := client.Do(reqs)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
