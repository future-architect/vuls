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
	to := strings.Join(conf.EMail.To[:], ", ")
	cc := strings.Join(conf.EMail.Cc[:], ", ")
	mailAddresses := append(conf.EMail.To, conf.EMail.Cc...)
	if _, err := mail.ParseAddressList(strings.Join(mailAddresses[:], ", ")); err != nil {
		return fmt.Errorf("Failed to parse email addresses: %s", err)
	}

	for _, r := range rs {
		var subject string
		if len(r.Errors) != 0 {
			subject = fmt.Sprintf("%s%s An error occurred while scanning",
				conf.EMail.SubjectPrefix, r.ServerInfo())
		} else {
			subject = fmt.Sprintf("%s%s %s",
				conf.EMail.SubjectPrefix, r.ServerInfo(), r.CveSummary())
		}

		headers := make(map[string]string)
		headers["From"] = conf.EMail.From
		headers["To"] = to
		headers["Cc"] = cc
		headers["Subject"] = subject
		headers["Date"] = time.Now().Format(time.RFC1123Z)
		headers["Content-Type"] = "text/plain; charset=utf-8"

		var message string
		for k, v := range headers {
			message += fmt.Sprintf("%s: %s\r\n", k, v)
		}
		message += "\r\n" + toFullPlainText(r)

		smtpServer := net.JoinHostPort(conf.EMail.SMTPAddr, conf.EMail.SMTPPort)
		err = smtp.SendMail(
			smtpServer,
			smtp.PlainAuth(
				"",
				conf.EMail.User,
				conf.EMail.Password,
				conf.EMail.SMTPAddr,
			),
			conf.EMail.From,
			conf.EMail.To,
			[]byte(message),
		)

		if err != nil {
			return fmt.Errorf("Failed to send emails: %s", err)
		}
	}
	return nil
}
