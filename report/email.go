package report

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
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
			if conf.FormatList {
				message = formatList(r)
			} else {
				message = formatFullPlainText(r)
			}
			if conf.FormatOneLineText {
				message = fmt.Sprintf("One Line Summary\r\n================\r\n%s", formatOneLineSummary(r))
			}
			if err := sender.Send(subject, message); err != nil {
				return err
			}
		}
	}
	var summary string
	if config.Conf.IgnoreUnscoredCves {
		summary = fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			m["High"]+m["Medium"]+m["Low"], m["High"], m["Medium"], m["Low"])
	} else {
		summary = fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
			m["High"]+m["Medium"]+m["Low"]+m["Unknown"],
			m["High"], m["Medium"], m["Low"], m["Unknown"])
	}
	origmessage := message
	if conf.FormatOneEMail {
		message = fmt.Sprintf("One Line Summary\r\n================\r\n%s", formatOneLineSummary(rs...))
		if !conf.FormatOneLineText {
			message += fmt.Sprintf("\r\n\r\n%s", origmessage)
		}

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

func smtps(emailConf config.SMTPConf, message string) (err error) {
	auth := smtp.PlainAuth("",
		emailConf.User,
		emailConf.Password,
		emailConf.SMTPAddr,
	)

	//TLS Config
	tlsConfig := &tls.Config{
		ServerName: emailConf.SMTPAddr,
	}

	smtpServer := net.JoinHostPort(emailConf.SMTPAddr, emailConf.SMTPPort)
	//New TLS connection
	con, err := tls.Dial("tcp", smtpServer, tlsConfig)
	if err != nil {
		return xerrors.Errorf("Failed to create TLS connection: %w", err)
	}
	defer con.Close()

	c, err := smtp.NewClient(con, emailConf.SMTPAddr)
	if err != nil {
		return xerrors.Errorf("Failed to create new client: %w", err)
	}
	if err = c.Auth(auth); err != nil {
		return xerrors.Errorf("Failed to authenticate: %w", err)
	}
	if err = c.Mail(emailConf.From); err != nil {
		return xerrors.Errorf("Failed to send Mail command: %w", err)
	}
	for _, to := range emailConf.To {
		if err = c.Rcpt(to); err != nil {
			return xerrors.Errorf("Failed to send Rcpt command: %w", err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return xerrors.Errorf("Failed to send Data command: %w", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return xerrors.Errorf("Failed to write EMail message: %w", err)
	}
	err = w.Close()
	if err != nil {
		return xerrors.Errorf("Failed to close Writer: %w", err)
	}
	err = c.Quit()
	if err != nil {
		return xerrors.Errorf("Failed to close connection: %w", err)
	}
	return nil
}

func (e *emailSender) Send(subject, body string) (err error) {
	emailConf := e.conf
	to := strings.Join(emailConf.To[:], ", ")
	cc := strings.Join(emailConf.Cc[:], ", ")
	mailAddresses := append(emailConf.To, emailConf.Cc...)
	if _, err := mail.ParseAddressList(strings.Join(mailAddresses[:], ", ")); err != nil {
		return xerrors.Errorf("Failed to parse email addresses: %w", err)
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

	if emailConf.User != "" && emailConf.Password != "" {
		switch emailConf.SMTPPort {
		case "465":
			err := smtps(emailConf, message)
			if err != nil {
				return xerrors.Errorf("Failed to send emails: %w", err)
			}
		default:
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
				return xerrors.Errorf("Failed to send emails: %w", err)
			}
		}
		return nil
	}
	err = e.send(
		smtpServer,
		nil,
		emailConf.From,
		mailAddresses,
		[]byte(message),
	)
	if err != nil {
		return xerrors.Errorf("Failed to send emails: %w", err)
	}
	return nil
}

// NewEMailSender creates emailSender
func NewEMailSender() EMailSender {
	return &emailSender{config.Conf.EMail, smtp.SendMail}
}
