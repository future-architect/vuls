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
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/parnurzeal/gorequest"
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

func (w SlackWriter) Write(scanResults []models.ScanResult) error {
	conf := config.Conf.Slack
	for _, s := range scanResults {
		channel := conf.Channel
		if channel == "${servername}" {
			channel = fmt.Sprintf("#%s", s.ServerName)
		}

		msg := message{
			Text:        msgText(s),
			Username:    conf.AuthUser,
			IconEmoji:   conf.IconEmoji,
			Channel:     channel,
			Attachments: toSlackAttachments(s),
		}

		bytes, _ := json.Marshal(msg)
		jsonBody := string(bytes)
		f := func() (err error) {
			resp, body, errs := gorequest.New().Proxy(config.Conf.HTTPProxy).Post(conf.HookURL).
				Send(string(jsonBody)).End()
			if resp.StatusCode != 200 {
				log.Errorf("Resonse body: %s", body)
				if 0 < len(errs) {
					return errs[0]
				}
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
			log.Warn("Retrying in ", t)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return fmt.Errorf("HTTP Error: %s", err)
		}
	}
	return nil
}

func msgText(r models.ScanResult) string {
	notifyUsers := ""
	if 0 < len(r.KnownCves) || 0 < len(r.UnknownCves) {
		notifyUsers = getNotifyUsers(config.Conf.Slack.NotifyUsers)
	}

	serverInfo := fmt.Sprintf("*%s*", r.ServerInfo())
	return fmt.Sprintf("%s\n%s\n>%s", notifyUsers, serverInfo, r.CveSummary())
}

func toSlackAttachments(scanResult models.ScanResult) (attaches []*attachment) {
	cves := scanResult.KnownCves
	if !config.Conf.IgnoreUnscoredCves {
		cves = append(cves, scanResult.UnknownCves...)
	}

	for _, cveInfo := range cves {
		cveID := cveInfo.CveDetail.CveID

		curentPackages := []string{}
		for _, p := range cveInfo.Packages {
			curentPackages = append(curentPackages, p.ToStringCurrentVersion())
		}
		for _, cpename := range cveInfo.CpeNames {
			curentPackages = append(curentPackages, cpename.Name)
		}

		newPackages := []string{}
		for _, p := range cveInfo.Packages {
			newPackages = append(newPackages, p.ToStringNewVersion())
		}

		a := attachment{
			Title:     cveID,
			TitleLink: fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID),
			Text:      attachmentText(cveInfo, scanResult.Family),
			MrkdwnIn:  []string{"text", "pretext"},
			Fields: []*field{
				{
					//  Title: "Current Package/CPE",
					Title: "Installed",
					Value: strings.Join(curentPackages, "\n"),
					Short: true,
				},
				{
					Title: "Candidate",
					Value: strings.Join(newPackages, "\n"),
					Short: true,
				},
			},
			Color: color(cveInfo.CveDetail.CvssScore(config.Conf.Lang)),
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

func attachmentText(cveInfo models.CveInfo, osFamily string) string {

	linkText := links(cveInfo, osFamily)

	switch {
	case config.Conf.Lang == "ja" &&
		0 < cveInfo.CveDetail.Jvn.CvssScore():

		jvn := cveInfo.CveDetail.Jvn
		return fmt.Sprintf("*%4.1f (%s)* <%s|%s>\n%s\n%s",
			cveInfo.CveDetail.CvssScore(config.Conf.Lang),
			jvn.CvssSeverity(),
			fmt.Sprintf(cvssV2CalcURLTemplate, cveInfo.CveDetail.CveID, jvn.CvssVector()),
			jvn.CvssVector(),
			jvn.CveTitle(),
			linkText,
		)

	case 0 < cveInfo.CveDetail.CvssScore("en"):
		nvd := cveInfo.CveDetail.Nvd
		return fmt.Sprintf("*%4.1f (%s)* <%s|%s>\n%s\n%s",
			cveInfo.CveDetail.CvssScore(config.Conf.Lang),
			nvd.CvssSeverity(),
			fmt.Sprintf(cvssV2CalcURLTemplate, cveInfo.CveDetail.CveID, nvd.CvssVector()),
			nvd.CvssVector(),
			nvd.CveSummary(),
			linkText,
		)
	default:
		nvd := cveInfo.CveDetail.Nvd
		return fmt.Sprintf("?\n%s\n%s", nvd.CveSummary(), linkText)
	}
}

func links(cveInfo models.CveInfo, osFamily string) string {
	links := []string{}

	cweID := cveInfo.CveDetail.CweID()
	if 0 < len(cweID) {
		links = append(links, fmt.Sprintf("<%s|%s>",
			cweURL(cweID), cweID))
		if config.Conf.Lang == "ja" {
			links = append(links, fmt.Sprintf("<%s|%s(JVN)>",
				cweJvnURL(cweID), cweID))
		}
	}

	cveID := cveInfo.CveDetail.CveID
	if config.Conf.Lang == "ja" && 0 < len(cveInfo.CveDetail.Jvn.Link()) {
		jvn := fmt.Sprintf("<%s|JVN>", cveInfo.CveDetail.Jvn.Link())
		links = append(links, jvn)
	}
	links = append(links, fmt.Sprintf("<%s|CVEDetails>",
		fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID)))
	links = append(links, fmt.Sprintf("<%s|MITRE>",
		fmt.Sprintf("%s%s", mitreBaseURL, cveID)))

	dlinks := distroLinks(cveInfo, osFamily)
	for _, link := range dlinks {
		links = append(links,
			fmt.Sprintf("<%s|%s>", link.url, link.title))
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
