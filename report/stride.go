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

// StrideWriter send report to Stride
type StrideWriter struct{}

func (w StrideWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.HipChat

	var message string
	for _, r := range rs {
		err = postMessage(conf.Room, conf.AuthToken, r.ServerName)
		if err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message = `<a href="https://nvd.nist.gov/vuln/detail\` + vinfo.CveID + ">" + vinfo.CveID + ">" + vinfo.CveID + "</a>" + "<br/>" + strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64) + " " + "(" + severity + ")" + "<br/>" + vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value

			err = postMessage(conf.Room, conf.AuthToken, message)
			if err != nil {
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
