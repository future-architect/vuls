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

func (w SlackWriter) Write(rs ...models.ScanResult) error {
	conf := config.Conf.Slack
	channel := conf.Channel

	for _, r := range rs {
		if channel == "${servername}" {
			channel = fmt.Sprintf("#%s", r.ServerName)
		}

		if 0 < len(r.Errors) {
			//TODO
			//  serverInfo := fmt.Sprintf("*%s*", r.ServerInfo())
			//  notifyUsers := getNotifyUsers(config.Conf.Slack.NotifyUsers)
			//  txt := fmt.Sprintf("%s\n%s\nError: %s", notifyUsers, serverInfo, r.Errors)
			msg := message{
				//  Text:      txt,
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
	//  if 0 < len(r.KnownCves) || 0 < len(r.UnknownCves) {
	//      notifyUsers = getNotifyUsers(config.Conf.Slack.NotifyUsers)
	//  }
	serverInfo := fmt.Sprintf("*%s*", r.ServerInfo())
	return fmt.Sprintf("%s\n%s\n>%s",
		notifyUsers,
		serverInfo,
		r.ScannedCves.FormatCveSummary())
}

func toSlackAttachments(scanResult models.ScanResult) (attaches []*attachment) {
	//  cves := scanResult.KnownCves
	//  if !config.Conf.IgnoreUnscoredCves {
	//      cves = append(cves, scanResult.UnknownCves...)
	//  }

	//  for _, cveInfo := range cves {
	//      cveID := cveInfo.VulnInfo.CveID

	//      curentPackages := []string{}
	//      for _, p := range cveInfo.Packages {
	//          curentPackages = append(curentPackages, p.FormatCurrentVer())
	//      }
	//      for _, n := range cveInfo.CpeNames {
	//          curentPackages = append(curentPackages, n)
	//      }

	//      newPackages := []string{}
	//      for _, p := range cveInfo.Packages {
	//          newPackages = append(newPackages, p.FormatNewVer())
	//      }

	//      a := attachment{
	//          Title:     cveID,
	//          TitleLink: fmt.Sprintf("%s/%s", nvdBaseURL, cveID),
	//          Text:      attachmentText(cveInfo, scanResult.Family),
	//          MrkdwnIn:  []string{"text", "pretext"},
	//          Fields: []*field{
	//              {
	//                  //  Title: "Current Package/CPE",
	//                  Title: "Installed",
	//                  Value: strings.Join(curentPackages, "\n"),
	//                  Short: true,
	//              },
	//              {
	//                  Title: "Candidate",
	//                  Value: strings.Join(newPackages, "\n"),
	//                  Short: true,
	//              },
	//          },
	//          Color: color(cveInfo.CvssV2Score()),
	//      }
	//      attaches = append(attaches, &a)
	//  }
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

//  func attachmentText(cveInfo models.CveInfo, osFamily string) string {
//  linkText := links(cveInfo, osFamily)
//TODO
//  return ""
//  switch {
//  case config.Conf.Lang == "ja" &&
//      0 < cveInfo.CveDetail.Jvn.CvssScore():

//      jvn := cveInfo.CveDetail.Jvn
//      return fmt.Sprintf("*%4.1f (%s)* <%s|%s>\n%s\n%s\n*Confidence:* %v",
//          cveInfo.CveDetail.CvssScore(config.Conf.Lang),
//          jvn.CvssSeverity(),
//          fmt.Sprintf(cvssV2CalcBaseURL, cveInfo.CveDetail.CveID),
//          jvn.CvssVector(),
//          jvn.CveTitle(),
//          linkText,
//          cveInfo.VulnInfo.Confidence,
//      )
//  case 0 < cveInfo.CveDetail.CvssScore("en"):
//      nvd := cveInfo.CveDetail.Nvd
//      return fmt.Sprintf("*%4.1f (%s)* <%s|%s>\n%s\n%s\n*Confidence:* %v",
//          cveInfo.CveDetail.CvssScore(config.Conf.Lang),
//          nvd.CvssSeverity(),
//          fmt.Sprintf(cvssV2CalcBaseURL, cveInfo.CveDetail.CveID),
//          nvd.CvssVector(),
//          nvd.CveSummary(),
//          linkText,
//          cveInfo.VulnInfo.Confidence,
//      )
//  default:
//      nvd := cveInfo.CveDetail.Nvd
//      return fmt.Sprintf("?\n%s\n%s\n*Confidence:* %v",
//          nvd.CveSummary(), linkText, cveInfo.VulnInfo.Confidence)
//  }
//  }

//  func links(cveInfo models.CveInfo, osFamily string) string {
//      links := []string{}

//      //TODO
//      //  cweID := cveInfo.CveDetail.CweID()
//      //  if 0 < len(cweID) {
//      //      links = append(links, fmt.Sprintf("<%s|%s>",
//      //          cweURL(cweID), cweID))
//      //      if config.Conf.Lang == "ja" {
//      //          links = append(links, fmt.Sprintf("<%s|%s(JVN)>",
//      //              cweJvnURL(cweID), cweID))
//      //      }
//      //  }

//      cveID := cveInfo.VulnInfo.CveID
//      //TODO
//      //  if config.Conf.Lang == "ja" && 0 < len(cveInfo.CveDetail.Jvn.Link()) {
//      //      jvn := fmt.Sprintf("<%s|JVN>", cveInfo.CveDetail.Jvn.Link())
//      //      links = append(links, jvn)
//      //  }
//      dlinks := distroLinks(cveInfo, osFamily)
//      for _, link := range dlinks {
//          links = append(links,
//              fmt.Sprintf("<%s|%s>", link.url, link.title))
//      }
//      links = append(links, fmt.Sprintf("<%s|MITRE>",
//          fmt.Sprintf("%s%s", mitreBaseURL, cveID)))
//      links = append(links, fmt.Sprintf("<%s|CVEDetails>",
//          fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID)))

//      return strings.Join(links, " / ")
//  }

//  // See testcase
//  func getNotifyUsers(notifyUsers []string) string {
//      slackStyleTexts := []string{}
//      for _, username := range notifyUsers {
//          slackStyleTexts = append(slackStyleTexts, fmt.Sprintf("<%s>", username))
//      }
//      return strings.Join(slackStyleTexts, " ")
//  }
