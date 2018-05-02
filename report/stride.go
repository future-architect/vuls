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

// StrideWriter send report to Stride
type StrideWriter struct{}
type strideSender struct{}

func (w StrideWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Stride

	for _, r := range rs {
		w := strideSender{}

		serverInfo := fmt.Sprintf("%s", r.ServerInfo())
		message := fmt.Sprintf(`{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":" %s  "}]}]}}`,
			serverInfo,
		)
		if err = w.sendMessage(conf.HookURL, conf.AuthToken, message); err != nil {
			return err
		}

		for _, vinfo := range r.ScannedCves {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}

			message = fmt.Sprintf(`{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":" %s ","marks": [ { "type": "link", "attrs": { "href": "https://nvd.nist.gov/vuln/detail/%s", "title": "cve" } } ]}]}]}}`,
				vinfo.CveID,
				vinfo.CveID,
			)
			if err = w.sendMessage(conf.HookURL, conf.AuthToken, message); err != nil {
				return err
			}

			message = fmt.Sprintf(`{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":" %s (%s) "}]}]}}`,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity,
			)
			if err = w.sendMessage(conf.HookURL, conf.AuthToken, message); err != nil {
				return err
			}

			message = fmt.Sprintf(`{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":" %s "}]}]}}`,
				vinfo.Summaries(config.Conf.Lang, r.Family)[0].Value,
			)
			if err = w.sendMessage(conf.HookURL, conf.AuthToken, message); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w strideSender) sendMessage(uri, token, jsonStr string) error {
	reqs, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(jsonStr)))
	if err != nil {
		return err
	}
	reqs.Header.Add("Content-Type", "application/json")
	reqs.Header.Add("Authorization", "Bearer "+token)
	client := &http.Client{}
	resp, err := client.Do(reqs)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
