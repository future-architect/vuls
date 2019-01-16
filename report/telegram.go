package report

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/future-architect/vuks/models"
	"github.com/future-architect/vuls/config"
)

// ChatWorkWriter send report to ChatWork
type TelegramWriter struct{}

func (w TelegramWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Telegram

	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		if err = sendMessage(conf.Channel, conf.Token, serverInfo); err != nil {
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
				vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value)

			if err = sendMessage(conf.Channel, conf.Token, message); err != nil {
				return err
			}
		}

	}
	return nil
}

func sendMessage(channel, token, message string) error {
	uri := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payload := `{"text": "` + message + `", "chat_id": "@` + channel + `" }`

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(payload)))

	req.Header.Add("Content-Type", "application/json")

	if err != nil {
		return err
	}
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
