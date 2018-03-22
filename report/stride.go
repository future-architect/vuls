package report

import (
	"net/http"
	"bytes"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// StrideWriter send report to Stride
type StrideWriter struct{}

func (w StrideWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Stride
	sendMessage(conf.HookURL, conf.AuthToken)
	return nil
}

func sendMessage(uri, token string) error {

	jsonStr := `{"body":{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"message"}]}]}}`

	reqs, err := http.NewRequest("POST", uri, bytes.NewBuffer([]byte(jsonStr)))

	reqs.Header.Add("Content-Type", "application/json")
	reqs.Header.Add("Authorization", "Bearer " + token)


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
