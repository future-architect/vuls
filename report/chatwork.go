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

// ChatWorkWriter send report to ChatWork
type ChatWorkWriter struct{}

func (w ChatWorkWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.ChatWork

	var message string
	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		if err = ChatWorkpostMessage(conf.Room, conf.ApiToken, serverInfo); err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message = serverInfo + "[info]" + "[title]" + `https://nvd.nist.gov/vuln/detail/` + vinfo.CveID + "  " + strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64) + " " + "(" + severity + ")" + "[/title]" + vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value + "[/info]"

			if err = ChatWorkpostMessage(conf.Room, conf.ApiToken, message); err != nil {
				return err
			}
		}

	}
	return nil
}

func ChatWorkpostMessage(room, token, message string) error {
	uri := fmt.Sprintf("https://api.chatwork.com/v2/rooms/%s/messages=%s", room, token)

	payload := url.Values{
		"body": {message},
	}

	reqs, err := http.NewRequest("POST", uri, strings.NewReader(payload.Encode()))

	reqs.Header.Add("X-ChatWorkToken", token)
	reqs.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return err
	}
	client := &http.Client{}

	resp, err := client.Do(reqs)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
