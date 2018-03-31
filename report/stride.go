package report

import (
	"bytes"
	"net/http"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"strconv"
	"strings"
)

// StrideWriter send report to Stride
type StrideWriter struct{}

func (w StrideWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Stride

	for _, r := range rs {
		jsonStr := `{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + r.ServerName + `"}]}]}}`
		err = sendMessage(conf.HookURL, conf.AuthToken, jsonStr)
		if err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			jsonStr = `{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + vinfo.CveID + `","marks": [ { "type": "link", "attrs": { "href": "https://nvd.nist.gov/vuln/detail/`+ vinfo.CveID + `", "title": "cve" } } ]}]}]}}`
			sendMessage(conf.HookURL, conf.AuthToken, jsonStr)
			if err != nil {
				return err
			}
			jsonStr = `{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64) + "(" + severity + ")" + `"}]}]}}`
			sendMessage(conf.HookURL, conf.AuthToken, jsonStr)
			if err != nil {
				return err
			}

			jsonStr = `{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value + `"}]}]}}`
			sendMessage(conf.HookURL, conf.AuthToken, jsonStr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func sendMessage(uri, token, jsonStr string) error {

	reqs, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(jsonStr)))

	reqs.Header.Add("Content-Type", "application/json")
	reqs.Header.Add("Authorization", "Bearer "+token)

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
