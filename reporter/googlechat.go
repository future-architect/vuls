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

// GoogleChatWriter send report to GoogleChat
type GoogleChatWriter struct {
	Cnf   config.GoogleChatConf
	Proxy string
}

func (w GoogleChatWriter) Write(rs ...models.ScanResult) (err error) {
	for _, r := range rs {
		msgs := []string{fmt.Sprintf("*%s*\n%s\t%s\t%s",
			r.ServerInfo(),
			r.ScannedCves.FormatCveSummary(),
			r.ScannedCves.FormatFixedStatus(r.Packages),
			r.FormatUpdatablePkgsSummary())}
		for _, vinfo := range r.ScannedCves.ToSortedSlice() {
			maxCvss := vinfo.MaxCvssScore()
			severity := strings.ToUpper(maxCvss.Value.Severity)
			if severity == "" {
				severity = "?"
			}
			msgs = append(msgs, fmt.Sprintf(`[%s](https://nvd.nist.gov/vuln/detail/%s) _%s %s_`,
				vinfo.CveID,
				vinfo.CveID,
				strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
				severity))
			if len(msgs) == 50 {
				msgs = append(msgs, "(The rest is omitted.)")
				break
			}
		}
		if len(msgs) == 1 && w.Cnf.SkipHealthy {
			msgs = []string{}
		}
		if len(msgs) != 0 {
			if err = w.postMessage(strings.Join(msgs, "\n")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w GoogleChatWriter) postMessage(message string) error {
	uri := fmt.Sprintf("%s", w.Cnf.WebHookURL)
	payload := `{"text": "` + message + `" }`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBuffer([]byte(payload)))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
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

func (w GoogleChatWriter) checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return xerrors.Errorf("API call to %s failed: %s", r.Request.URL.String(), r.Status)
}
