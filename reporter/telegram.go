package reporter

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// TelegramWriter sends report to Telegram
type TelegramWriter struct {
	Cnf   config.TelegramConf
	Proxy string
}

func (w TelegramWriter) Write(rs ...models.ScanResult) (err error) {
	for _, r := range rs {
		msgs := []string{fmt.Sprintf("*%s*\n%s\n%s\n%s",
			r.ServerInfo(),
			r.ScannedCves.FormatCveSummary(),
			r.ScannedCves.FormatFixedStatus(r.Packages),
			r.FormatUpdatablePkgsSummary())}
		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}
			msgs = append(msgs, fmt.Sprintf(`[%s](https://nvd.nist.gov/vuln/detail/%s) _%s %s %s_\n%s`,
				vinfo.CveID,
				vinfo.CveID,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity,
				maxCvss.Value.Vector,
				vinfo.Summaries(r.Lang, r.Family)[0].Value))
			if len(msgs) == 5 {
				if err = w.sendMessage(w.Cnf.ChatID, w.Cnf.Token, strings.Join(msgs, "\n\n")); err != nil {
					return err
				}
				msgs = []string{}
			}
		}
		if len(msgs) != 0 {
			if err = w.sendMessage(w.Cnf.ChatID, w.Cnf.Token, strings.Join(msgs, "\n\n")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w TelegramWriter) sendMessage(chatID, token, message string) error {
	uri := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := `{"text": "` + strings.Replace(message, `"`, `\"`, -1) + `", "chat_id": "` + chatID + `", "parse_mode": "Markdown" }`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBuffer([]byte(payload)))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

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

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return xerrors.Errorf("API call to %s failed: %s", r.Request.URL.String(), r.Status)
}
