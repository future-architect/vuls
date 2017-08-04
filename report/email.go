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
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// EMailWriter send mail
type EMailWriter struct{}

func (w EMailWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf
	var message string
	sender := NewEMailSender()

	m := map[string]int{}
	for _, r := range rs {
		if conf.FormatOneEMail {
			message += formatFullPlainText(r) + "\r\n\r\n"

			mm := r.ScannedCves.CountGroupBySeverity()
			keys := []string{"High", "Medium", "Low", "Unknown"}
			for _, k := range keys {
				m[k] += mm[k]
			}
		} else {
			var subject string
			if len(r.Errors) != 0 {
				subject = fmt.Sprintf("%s%s An error occurred while scanning",
					conf.EMail.SubjectPrefix, r.ServerInfo())
			} else {
				subject = fmt.Sprintf("%s%s %s",
					conf.EMail.SubjectPrefix,
					r.ServerInfo(),
					r.ScannedCves.FormatCveSummary())
			}
			message = formatFullPlainText(r)
			if err := sender.Send(subject, message); err != nil {
				return err
			}
		}
	}

	summary := ""
	if config.Conf.IgnoreUnscoredCves {
		summary = fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			m["High"]+m["Medium"]+m["Low"], m["High"], m["Medium"], m["Low"])
	}
	summary = fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
		m["High"]+m["Medium"]+m["Low"]+m["Unknown"],
		m["High"], m["Medium"], m["Low"], m["Unknown"])

	if conf.FormatOneEMail {
		message = fmt.Sprintf(
			`
One Line Summary
================
%s


%s`,
			formatOneLineSummary(rs...), message)

		subject := fmt.Sprintf("%s %s",
			conf.EMail.SubjectPrefix, summary)
		return sender.Send(subject, message)
	}
	return nil
}

// EMailSender is interface of sending e-mail
type EMailSender interface {
	Send(subject, body string) error
}

type emailSender struct {
	conf config.SMTPConf
	send func(string, smtp.Auth, string, []string, []byte) error
}

func (e *emailSender) Send(subject, body string) (err error) {
	emailConf := e.conf
	to := strings.Join(emailConf.To[:], ", ")
	cc := strings.Join(emailConf.Cc[:], ", ")
	mailAddresses := append(emailConf.To, emailConf.Cc...)
	if _, err := mail.ParseAddressList(strings.Join(mailAddresses[:], ", ")); err != nil {
		return fmt.Errorf("Failed to parse email addresses: %s", err)
	}

	headers := make(map[string]string)
	headers["From"] = emailConf.From
	headers["To"] = to
	headers["Cc"] = cc
	headers["Subject"] = subject
	headers["Date"] = time.Now().Format(time.RFC1123Z)
	headers["Content-Type"] = "text/plain; charset=utf-8"

	var header string
	for k, v := range headers {
		header += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message := fmt.Sprintf("%s\r\n%s", header, body)

	smtpServer := net.JoinHostPort(emailConf.SMTPAddr, emailConf.SMTPPort)
	err = e.send(
		smtpServer,
		smtp.PlainAuth(
			"",
			emailConf.User,
			emailConf.Password,
			emailConf.SMTPAddr,
		),
		emailConf.From,
		mailAddresses,
		[]byte(message),
	)
	if err != nil {
		return fmt.Errorf("Failed to send emails: %s", err)
	}
	return nil
}

// NewEMailSender creates emailSender
func NewEMailSender() EMailSender {
	return &emailSender{config.Conf.EMail, smtp.SendMail}
}
