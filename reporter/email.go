package reporter

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// EMailWriter send mail
type EMailWriter struct {
	FormatOneEMail    bool
	FormatOneLineText bool
	FormatList        bool
	Cnf               config.SMTPConf
}

// Write results to Email
func (w EMailWriter) Write(rs ...models.ScanResult) (err error) {
	var message string
	sender := NewEMailSender(w.Cnf)
	m := map[string]int{}
	for _, r := range rs {
		if w.FormatOneEMail {
			text, err := formatFullPlainText(r)
			if err != nil {
				return xerrors.Errorf("Failed to format full plain text. err: %w", err)
			}
			message += text + "\r\n\r\n"
			mm := r.ScannedCves.CountGroupBySeverity()
			keys := []string{"Critical", "High", "Medium", "Low", "Unknown"}
			for _, k := range keys {
				m[k] += mm[k]
			}
		} else {
			var subject string
			if len(r.Errors) != 0 {
				subject = fmt.Sprintf("%s%s An error occurred while scanning",
					w.Cnf.SubjectPrefix, r.ServerInfo())
			} else {
				subject = fmt.Sprintf("%s%s %s",
					w.Cnf.SubjectPrefix,
					r.ServerInfo(),
					r.ScannedCves.FormatCveSummary())
			}
			if w.FormatList {
				message, err = formatList(r)
				if err != nil {
					return xerrors.Errorf("Failed to format list. err: %w", err)
				}
			} else {
				message, err = formatFullPlainText(r)
				if err != nil {
					return xerrors.Errorf("Failed to format full plain text. err: %w", err)
				}
			}
			if w.FormatOneLineText {
				message = fmt.Sprintf("One Line Summary\r\n================\r\n%s", formatOneLineSummary(r))
			}
			if err := sender.Send(subject, message); err != nil {
				return err
			}
		}
	}

	summary := fmt.Sprintf("Total: %d (Critical:%d High:%d Medium:%d Low:%d ?:%d)",
		m["Critical"]+m["High"]+m["Medium"]+m["Low"]+m["Unknown"],
		m["Critical"], m["High"], m["Medium"], m["Low"], m["Unknown"])

	origmessage := message
	if w.FormatOneEMail {
		message = fmt.Sprintf("One Line Summary\r\n================\r\n%s", formatOneLineSummary(rs...))
		if !w.FormatOneLineText {
			message += fmt.Sprintf("\r\n\r\n%s", origmessage)
		}

		subject := fmt.Sprintf("%s %s",
			w.Cnf.SubjectPrefix, summary)
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
}

func (e *emailSender) sendMail(smtpServerAddr, message string) (err error) {
	var auth sasl.Client
	emailConf := e.conf
	tlsConfig := &tls.Config{
		ServerName:         emailConf.SMTPAddr,
		InsecureSkipVerify: emailConf.TLSInsecureSkipVerify,
	}

	var c *smtp.Client
	switch emailConf.TLSMode {
	case "":
		switch emailConf.SMTPPort {
		case "465":
			c, err = smtp.DialTLS(smtpServerAddr, tlsConfig)
			if err != nil {
				return xerrors.Errorf("Failed to create TLS connection to SMTP server: %w", err)
			}
			defer c.Close()
		default:
			c, err = smtp.Dial(smtpServerAddr)
			if err != nil {
				return xerrors.Errorf("Failed to create connection to SMTP server: %w", err)
			}
			defer c.Close()

			if ok, _ := c.Extension("STARTTLS"); ok {
				c, err = smtp.DialStartTLS(smtpServerAddr, tlsConfig)
				if err != nil {
					return xerrors.Errorf("Failed to create STARTTLS connection to SMTP server: %w", err)
				}
				defer c.Close()
			}
		}
	case "None":
		c, err = smtp.Dial(smtpServerAddr)
		if err != nil {
			return xerrors.Errorf("Failed to create connection to SMTP server: %w", err)
		}
		defer c.Close()
	case "STARTTLS":
		c, err = smtp.DialStartTLS(smtpServerAddr, tlsConfig)
		if err != nil {
			return xerrors.Errorf("Failed to create STARTTLS connection to SMTP server: %w", err)
		}
		defer c.Close()
	case "SMTPS":
		c, err = smtp.DialTLS(smtpServerAddr, tlsConfig)
		if err != nil {
			return xerrors.Errorf("Failed to create TLS connection to SMTP server: %w", err)
		}
		defer c.Close()
	default:
		return xerrors.New(`invalid TLS mode. accepts: ["", "None", "STARTTLS", "SMTPS"]`)
	}

	if ok, param := c.Extension("AUTH"); ok {
		authList := strings.Split(param, " ")
		auth = e.newSaslClient(authList)
		if err = c.Auth(auth); err != nil {
			return xerrors.Errorf("Failed to authenticate: %w", err)
		}
	}

	if err = c.Mail(emailConf.From, nil); err != nil {
		return xerrors.Errorf("Failed to send Mail command: %w", err)
	}
	for _, to := range emailConf.To {
		if err = c.Rcpt(to, nil); err != nil {
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
	if err := e.sendMail(net.JoinHostPort(emailConf.SMTPAddr, emailConf.SMTPPort), fmt.Sprintf("%s\r\n%s", header, body)); err != nil {
		return xerrors.Errorf("Failed to send emails: %w", err)
	}
	return nil
}

// NewEMailSender creates emailSender
func NewEMailSender(cnf config.SMTPConf) EMailSender {
	return &emailSender{cnf}
}

func (e *emailSender) newSaslClient(authList []string) sasl.Client {
	for _, v := range authList {
		switch v {
		case "PLAIN":
			auth := sasl.NewPlainClient("", e.conf.User, e.conf.Password)
			return auth
		case "LOGIN":
			auth := sasl.NewLoginClient(e.conf.User, e.conf.Password)
			return auth
		}
	}
	return nil
}
