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

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// MailWriter send mail
type MailWriter struct{}

func (w MailWriter) Write(scanResults []models.ScanResult) (err error) {
	conf := config.Conf
	for _, s := range scanResults {
		to := strings.Join(conf.Mail.To[:], ", ")
		cc := strings.Join(conf.Mail.Cc[:], ", ")
		mailAddresses := append(conf.Mail.To, conf.Mail.Cc...)
		if _, err := mail.ParseAddressList(strings.Join(mailAddresses[:], ", ")); err != nil {
			return fmt.Errorf("Failed to parse email addresses: %s", err)
		}

		subject := fmt.Sprintf("%s%s %s",
			conf.Mail.SubjectPrefix,
			s.ServerInfo(),
			s.CveSummary(),
		)

		headers := make(map[string]string)
		headers["From"] = conf.Mail.From
		headers["To"] = to
		headers["Cc"] = cc
		headers["Subject"] = subject

		var message string
		for k, v := range headers {
			message += fmt.Sprintf("%s: %s\r\n", k, v)
		}

		var body string
		if body, err = toPlainText(s); err != nil {
			return err
		}
		message += "\r\n" + body

		smtpServer := net.JoinHostPort(conf.Mail.SMTPAddr, conf.Mail.SMTPPort)

		err := smtp.SendMail(
			smtpServer,
			smtp.PlainAuth(
				"",
				conf.Mail.User,
				conf.Mail.Password,
				conf.Mail.SMTPAddr,
			),
			conf.Mail.From,
			conf.Mail.To,
			[]byte(message),
		)

		if err != nil {
			return fmt.Errorf("Failed to send emails: %s", err)
		}
	}
	return nil
}
