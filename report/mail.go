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
	"crypto/tls"
	"fmt"
	"strconv"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"gopkg.in/gomail.v2"
)

// MailWriter send mail
type MailWriter struct{}

func (w MailWriter) Write(scanResults []models.ScanResult) (err error) {
	conf := config.Conf
	for _, s := range scanResults {
		m := gomail.NewMessage()
		m.SetHeader("From", conf.Mail.From)
		m.SetHeader("To", conf.Mail.To...)
		m.SetHeader("Cc", conf.Mail.Cc...)

		subject := fmt.Sprintf("%s%s %s",
			conf.Mail.SubjectPrefix,
			s.ServerName,
			s.CveSummary(),
		)
		m.SetHeader("Subject", subject)

		var body string
		if body, err = toPlainText(s); err != nil {
			return err
		}
		m.SetBody("text/plain", body)
		port, _ := strconv.Atoi(conf.Mail.SMTPPort)
		d := gomail.NewPlainDialer(
			conf.Mail.SMTPAddr,
			port,
			conf.Mail.User,
			conf.Mail.Password,
		)

		d.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		if err := d.DialAndSend(m); err != nil {
			panic(err)
		}
	}
	return nil
}
