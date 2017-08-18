/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
)

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}
type attachment struct {
	Title     string   `json:"title"`
	TitleLink string   `json:"title_link"`
	Fallback  string   `json:"fallback"`
	Text      string   `json:"text"`
	Pretext   string   `json:"pretext"`
	Color     string   `json:"color"`
	Fields    []*field `json:"fields"`
	MrkdwnIn  []string `json:"mrkdwn_in"`
	Footer    string   `json:"footer"`
}
type message struct {
	Text        string        `json:"text"`
	Username    string        `json:"username"`
	IconEmoji   string        `json:"icon_emoji"`
	Channel     string        `json:"channel"`
	Attachments []*attachment `json:"attachments"`
}

// SlackWriter send report to slack
type SlackWriter struct{}

func (w SlackWriter) Write(rs ...models.ScanResult) error {
	conf := config.Conf.Slack
	channel := conf.Channel

	for _, r := range rs {
		if channel == "${servername}" {
			channel = fmt.Sprintf("#%s", r.ServerName)
		}

		if 0 < len(r.Errors) {
			serverInfo := fmt.Sprintf("*%s*", r.ServerInfo())
			notifyUsers := getNotifyUsers(config.Conf.Slack.NotifyUsers)
			txt := fmt.Sprintf("%s\n%s\nError: %s",
				notifyUsers, serverInfo, r.Errors)
			msg := message{
				Text:      txt,
				Username:  conf.AuthUser,
				IconEmoji: conf.IconEmoji,
				Channel:   channel,
			}
			if err := send(msg); err != nil {
				return err
			}
			continue
		}

		// A maximum of 100 attachments are allowed on a message.
		// Split into chunks with 100 elements
		// https://api.slack.com/methods/chat.postMessage
		maxAttachments := 100
		m := map[int][]*attachment{}
		for i, a := range toSlackAttachments(r) {
			m[i/maxAttachments] = append(m[i/maxAttachments], a)
		}
		chunkKeys := []int{}
		for k := range m {
			chunkKeys = append(chunkKeys, k)
		}
		sort.Ints(chunkKeys)

		for i, k := range chunkKeys {
			txt := ""
			if i == 0 {
				txt = msgText(r)
			}
			msg := message{
				Text:        txt,
				Username:    conf.AuthUser,
				IconEmoji:   conf.IconEmoji,
				Channel:     channel,
				Attachments: m[k],
			}
			if err := send(msg); err != nil {
				return err
			}
		}
	}
	return nil
}

func send(msg message) error {
	conf := config.Conf.Slack
	count, retryMax := 0, 10

	bytes, _ := json.Marshal(msg)
	jsonBody := string(bytes)

	f := func() (err error) {
		resp, body, errs := gorequest.New().Proxy(config.Conf.HTTPProxy).Post(conf.HookURL).Send(string(jsonBody)).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			count++
			if count == retryMax {
				return nil
			}
			return fmt.Errorf(
				"HTTP POST error: %v, url: %s, resp: %v, body: %s",
				errs, conf.HookURL, resp, body)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Error %s", err)
		log.Warn("Retrying in ", t)
	}
	boff := backoff.NewExponentialBackOff()
	if err := backoff.RetryNotify(f, boff, notify); err != nil {
		return fmt.Errorf("HTTP error: %s", err)
	}
	if count == retryMax {
		return fmt.Errorf("Retry count exceeded")
	}
	return nil
}

func msgText(r models.ScanResult) string {
	notifyUsers := ""
	if 0 < len(r.ScannedCves) {
		notifyUsers = getNotifyUsers(config.Conf.Slack.NotifyUsers)
	}
	serverInfo := fmt.Sprintf("*%s*", r.ServerInfo())
	return fmt.Sprintf("%s\n%s\n>%s",
		notifyUsers,
		serverInfo,
		r.ScannedCves.FormatCveSummary())
}

func toSlackAttachments(r models.ScanResult) (attaches []*attachment) {
	var vinfos []models.VulnInfo
	if config.Conf.IgnoreUnscoredCves {
		vinfos = r.ScannedCves.FindScoredVulns().ToSortedSlice()
	} else {
		vinfos = r.ScannedCves.ToSortedSlice()
	}

	for _, vinfo := range vinfos {
		curent := []string{}
		for _, affected := range vinfo.AffectedPackages {
			if p, ok := r.Packages[affected.Name]; ok {
				curent = append(curent,
					fmt.Sprintf("%s-%s", p.Name, p.FormatVer()))
			} else {
				curent = append(curent, affected.Name)
			}
		}
		for _, n := range vinfo.CpeNames {
			curent = append(curent, n)
		}

		new := []string{}
		for _, affected := range vinfo.AffectedPackages {
			if p, ok := r.Packages[affected.Name]; ok {
				if affected.NotFixedYet {
					new = append(new, "Not Fixed Yet")
				} else {
					new = append(new, p.FormatNewVer())
				}
			} else {
				new = append(new, "?")
			}
		}
		for range vinfo.CpeNames {
			new = append(new, "?")
		}

		a := attachment{
			Title:     vinfo.CveID,
			TitleLink: "https://nvd.nist.gov/vuln/detail/" + vinfo.CveID,
			Text:      attachmentText(vinfo, r.Family),
			MrkdwnIn:  []string{"text", "pretext"},
			Fields: []*field{
				{
					// Title: "Current Package/CPE",
					Title: "Installed",
					Value: strings.Join(curent, "\n"),
					Short: true,
				},
				{
					Title: "Candidate",
					Value: strings.Join(new, "\n"),
					Short: true,
				},
			},
			Color: color(vinfo.MaxCvssScore().Value.Score),
		}
		attaches = append(attaches, &a)
	}
	return
}

// https://api.slack.com/docs/attachments
func color(cvssScore float64) string {
	switch {
	case 7 <= cvssScore:
		return "danger"
	case 4 <= cvssScore && cvssScore < 7:
		return "warning"
	case cvssScore < 0:
		return "#C0C0C0"
	default:
		return "good"
	}
}

func attachmentText(vinfo models.VulnInfo, osFamily string) string {
	maxCvss := vinfo.MaxCvssScore()
	vectors := []string{}
	for _, cvss := range vinfo.Cvss2Scores() {
		calcURL := ""
		switch cvss.Value.Type {
		case models.CVSS2:
			calcURL = fmt.Sprintf(
				"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=%s",
				vinfo.CveID)
		case models.CVSS3:
			calcURL = fmt.Sprintf(
				"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=%s",
				vinfo.CveID)
		}

		if cont, ok := vinfo.CveContents[cvss.Type]; ok {
			v := fmt.Sprintf("<%s|%s> (<%s|%s>)",
				calcURL,
				cvss.Value.Format(),
				cont.SourceLink,
				cvss.Type)
			vectors = append(vectors, v)

		} else {
			if 0 < len(vinfo.DistroAdvisories) {
				links := []string{}
				for k, v := range vinfo.VendorLinks(osFamily) {
					links = append(links, fmt.Sprintf("<%s|%s>",
						v, k))
				}

				v := fmt.Sprintf("<%s|%s> (%s)",
					calcURL,
					cvss.Value.Format(),
					strings.Join(links, ", "))
				vectors = append(vectors, v)
			}
		}
	}

	severity := strings.ToUpper(maxCvss.Value.Severity)
	if severity == "" {
		severity = "?"
	}

	return fmt.Sprintf("*%4.1f (%s)* %s\n%s\n```%s```",
		maxCvss.Value.Score,
		severity,
		cweIDs(vinfo, osFamily),
		strings.Join(vectors, "\n"),
		vinfo.Summaries(config.Conf.Lang, osFamily)[0].Value,
	)
}

func cweIDs(vinfo models.VulnInfo, osFamily string) string {
	links := []string{}
	for _, cwe := range vinfo.CveContents.CweIDs(osFamily) {
		if config.Conf.Lang == "ja" {
			links = append(links, fmt.Sprintf("<%s|%s>",
				cweJvnURL(cwe.Value), cwe.Value))
		} else {
			links = append(links, fmt.Sprintf("<%s|%s>",
				cweURL(cwe.Value), cwe.Value))
		}
	}
	return strings.Join(links, " / ")
}

// See testcase
func getNotifyUsers(notifyUsers []string) string {
	slackStyleTexts := []string{}
	for _, username := range notifyUsers {
		slackStyleTexts = append(slackStyleTexts, fmt.Sprintf("<%s>", username))
	}
	return strings.Join(slackStyleTexts, " ")
}
