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
	"github.com/nlopes/slack"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type message struct {
	Text        string             `json:"text"`
	Username    string             `json:"username"`
	IconEmoji   string             `json:"icon_emoji"`
	Channel     string             `json:"channel"`
	Attachments []slack.Attachment `json:"attachments"`
}

// SlackWriter send report to slack
type SlackWriter struct{}

func (w SlackWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf.Slack
	channel := conf.Channel
	token := conf.LegacyToken

	for _, r := range rs {
		if channel == "${servername}" {
			channel = fmt.Sprintf("#%s", r.ServerName)
		}

		// A maximum of 100 attachments are allowed on a message.
		// Split into chunks with 100 elements
		// https://api.slack.com/methods/chat.postMessage
		maxAttachments := 100
		m := map[int][]slack.Attachment{}
		for i, a := range toSlackAttachments(r) {
			m[i/maxAttachments] = append(m[i/maxAttachments], a)
		}
		chunkKeys := []int{}
		for k := range m {
			chunkKeys = append(chunkKeys, k)
		}
		sort.Ints(chunkKeys)

		summary := fmt.Sprintf("%s\n%s",
			getNotifyUsers(config.Conf.Slack.NotifyUsers),
			formatOneLineSummary(r))

		// Send slack by API
		if 0 < len(token) {
			api := slack.New(token)
			msgPrms := slack.PostMessageParameters{
				Username:  conf.AuthUser,
				IconEmoji: conf.IconEmoji,
			}

			var ts string
			if _, ts, err = api.PostMessage(
				channel,
				slack.MsgOptionText(summary, true),
				slack.MsgOptionPostMessageParameters(msgPrms),
			); err != nil {
				return err
			}

			if config.Conf.FormatOneLineText || 0 < len(r.Errors) {
				continue
			}

			for _, k := range chunkKeys {
				params := slack.PostMessageParameters{
					Username:        conf.AuthUser,
					IconEmoji:       conf.IconEmoji,
					ThreadTimestamp: ts,
				}
				if _, _, err = api.PostMessage(
					channel,
					slack.MsgOptionText("", false),
					slack.MsgOptionPostMessageParameters(params),
					slack.MsgOptionAttachments(m[k]...),
				); err != nil {
					return err
				}
			}
		} else {
			msg := message{
				Text:      summary,
				Username:  conf.AuthUser,
				IconEmoji: conf.IconEmoji,
				Channel:   channel,
			}
			if err := send(msg); err != nil {
				return err
			}

			if config.Conf.FormatOneLineText || 0 < len(r.Errors) {
				continue
			}

			for _, k := range chunkKeys {
				txt := fmt.Sprintf("%d/%d for %s",
					k+1,
					len(chunkKeys),
					r.FormatServerName())

				msg := message{
					Text:        txt,
					Username:    conf.AuthUser,
					IconEmoji:   conf.IconEmoji,
					Channel:     channel,
					Attachments: m[k],
				}
				if err = send(msg); err != nil {
					return err
				}
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
			return xerrors.Errorf(
				"HTTP POST error. url: %s, resp: %v, body: %s, err: %w",
				conf.HookURL, resp, body, errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Error %s", err)
		log.Warn("Retrying in ", t)
	}
	boff := backoff.NewExponentialBackOff()
	if err := backoff.RetryNotify(f, boff, notify); err != nil {
		return xerrors.Errorf("HTTP error: %w", err)
	}
	if count == retryMax {
		return xerrors.New("Retry count exceeded")
	}
	return nil
}

func toSlackAttachments(r models.ScanResult) (attaches []slack.Attachment) {
	vinfos := r.ScannedCves.ToSortedSlice()
	for _, vinfo := range vinfos {

		installed, candidate := []string{}, []string{}
		for _, affected := range vinfo.AffectedPackages {
			if p, ok := r.Packages[affected.Name]; ok {
				installed = append(installed,
					fmt.Sprintf("%s-%s", p.Name, p.FormatVer()))
			} else {
				installed = append(installed, affected.Name)
			}

			if p, ok := r.Packages[affected.Name]; ok {
				if affected.NotFixedYet {
					candidate = append(candidate, "Not Fixed Yet")
				} else {
					candidate = append(candidate, p.FormatNewVer())
				}
			} else {
				candidate = append(candidate, "?")
			}
		}

		for _, n := range vinfo.CpeURIs {
			installed = append(installed, n)
			candidate = append(candidate, "?")
		}
		for _, n := range vinfo.GitHubSecurityAlerts {
			installed = append(installed, n.PackageName)
			candidate = append(candidate, "?")
		}

		for _, wp := range vinfo.WpPackageFixStats {
			if p, ok := r.WordPressPackages.Find(wp.Name); ok {
				installed = append(installed, fmt.Sprintf("%s-%s", wp.Name, p.Version))
				candidate = append(candidate, wp.FixedIn)
			} else {
				installed = append(installed, wp.Name)
				candidate = append(candidate, "?")
			}
		}

		a := slack.Attachment{
			Title:      vinfo.CveID,
			TitleLink:  "https://nvd.nist.gov/vuln/detail/" + vinfo.CveID,
			Text:       attachmentText(vinfo, r.Family, r.CweDict, r.Packages),
			MarkdownIn: []string{"text", "pretext"},
			Fields: []slack.AttachmentField{
				{
					// Title: "Current Package/CPE",
					Title: "Installed",
					Value: strings.Join(installed, "\n"),
					Short: true,
				},
				{
					Title: "Candidate",
					Value: strings.Join(candidate, "\n"),
					Short: true,
				},
			},
			Color: cvssColor(vinfo.MaxCvssScore().Value.Score),
		}
		attaches = append(attaches, a)
	}
	return
}

// https://api.slack.com/docs/attachments
func cvssColor(cvssScore float64) string {
	switch {
	case 7 <= cvssScore:
		return "danger"
	case 4 <= cvssScore && cvssScore < 7:
		return "warning"
	case cvssScore == 0:
		return "#C0C0C0"
	default:
		return "good"
	}
}

func attachmentText(vinfo models.VulnInfo, osFamily string, cweDict map[string]models.CweDictEntry, packs models.Packages) string {
	maxCvss := vinfo.MaxCvssScore()
	vectors := []string{}

	scores := append(vinfo.Cvss3Scores(), vinfo.Cvss2Scores(osFamily)...)
	for _, cvss := range scores {
		if cvss.Value.Severity == "" {
			continue
		}
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
			v := fmt.Sprintf("<%s|%s> %s (<%s|%s>)",
				calcURL,
				fmt.Sprintf("%3.1f/%s", cvss.Value.Score, cvss.Value.Vector),
				cvss.Value.Severity,
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

				v := fmt.Sprintf("<%s|%s> %s (%s)",
					calcURL,
					fmt.Sprintf("%3.1f/%s", cvss.Value.Score, cvss.Value.Vector),
					cvss.Value.Severity,
					strings.Join(links, ", "))
				vectors = append(vectors, v)
			}
		}
	}

	severity := strings.ToUpper(maxCvss.Value.Severity)
	if severity == "" {
		severity = "?"
	}

	nwvec := vinfo.AttackVector()
	if nwvec == "Network" || nwvec == "remote" {
		nwvec = fmt.Sprintf("*%s*", nwvec)
	}

	mitigation := ""
	if vinfo.Mitigations(osFamily)[0].Type != models.Unknown {
		mitigation = fmt.Sprintf("\nMitigation:\n```%s```\n",
			vinfo.Mitigations(osFamily)[0].Value)
	}

	return fmt.Sprintf("*%4.1f (%s)* %s %s\n%s\n```\n%s\n```%s\n%s\n",
		maxCvss.Value.Score,
		severity,
		nwvec,
		vinfo.PatchStatus(packs),
		strings.Join(vectors, "\n"),
		vinfo.Summaries(config.Conf.Lang, osFamily)[0].Value,
		mitigation,
		cweIDs(vinfo, osFamily, cweDict),
	)
}

func cweIDs(vinfo models.VulnInfo, osFamily string, cweDict models.CweDict) string {
	links := []string{}
	for _, c := range vinfo.CveContents.UniqCweIDs(osFamily) {
		name, url, top10Rank, top10URL, cweTop25Rank, cweTop25URL, sansTop25Rank, sansTop25URL := cweDict.Get(c.Value, osFamily)
		line := ""
		if top10Rank != "" {
			line = fmt.Sprintf("<%s|[OWASP Top %s]>",
				top10URL, top10Rank)
		}
		if cweTop25Rank != "" {
			line = fmt.Sprintf("<%s|[CWE Top %s]>",
				cweTop25URL, cweTop25Rank)
		}
		if sansTop25Rank != "" {
			line = fmt.Sprintf("<%s|[CWE/SANS Top %s]>",
				sansTop25URL, sansTop25Rank)
		}
		if top10Rank == "" && cweTop25Rank == "" && sansTop25Rank == "" {
			links = append(links, fmt.Sprintf("%s <%s|%s>: %s",
				line, url, c.Value, name))
		}
	}
	return strings.Join(links, "\n")
}

// See testcase
func getNotifyUsers(notifyUsers []string) string {
	slackStyleTexts := []string{}
	for _, username := range notifyUsers {
		slackStyleTexts = append(slackStyleTexts, fmt.Sprintf("<%s>", username))
	}
	return strings.Join(slackStyleTexts, " ")
}
