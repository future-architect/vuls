package report

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// TelegramWriter sends report to Telegram
type TelegramWriter struct{}

func (w TelegramWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Telegram

	for _, r := range rs {
		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		counter := 0
		message := ""
		for _, vinfo := range r.ScannedCves {
			counter++
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message += fmt.Sprintf(`*%s* \n [%s](https://nvd.nist.gov/vuln/detail/%s) _%s %s_\n %s\n\n`,
				serverInfo,
				vinfo.CveID,
				vinfo.CveID,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity,
				vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value)
			if counter == 10 {
				message = ""
				if err = sendMessage(conf.ChatID, conf.Token, message); err != nil {
					return err
				}
			}
		}
		if message != "" {
			if err = sendMessage(conf.ChatID, conf.Token, message); err != nil {
				return err
			}
		}

	}
	return nil
}

func sendMessage(chatID, token, message string) error {
	uri := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := `{"text": "` + message + `", "chat_id": "` + chatID + `", "parse_mode": "Markdown" }`

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(payload)))
	req.Header.Add("Content-Type", "application/json")

	if err != nil {
		return err
	}
	client := &http.Client{}

	resp, err := client.Do(req)
	if checkResponse(resp) != nil && err != nil {
		fmt.Println(err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return fmt.Errorf("API call to %s failed: %s", r.Request.URL.String(), r.Status)
}
