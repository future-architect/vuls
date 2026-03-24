package reporter

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// plainAuth implements smtp.Auth for the PLAIN mechanism without
// stdlib's TLS enforcement, preserving behavioral parity with the
// previously used go-smtp library for TLSMode "None" configurations.
type plainAuth struct {
	identity, username, password, host string
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		advertised := false
		for _, mech := range server.Auth {
			if strings.EqualFold(mech, "PLAIN") {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, xerrors.New("unencrypted connection: PLAIN auth requires TLS or explicit server advertisement")
		}
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, xerrors.New("unexpected server challenge")
	}
	return nil, nil
}

// loginAuth implements smtp.Auth for the LOGIN mechanism.
type loginAuth struct {
	username, password string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		advertised := false
		for _, mech := range server.Auth {
			if strings.EqualFold(mech, "LOGIN") {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, xerrors.New("unencrypted connection: LOGIN auth requires TLS or explicit server advertisement")
		}
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.TrimSpace(strings.ToLower(string(fromServer)))
	switch {
	case strings.Contains(prompt, "username"):
		return []byte(a.username), nil
	case strings.Contains(prompt, "password"):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected server challenge: %q", fromServer)
	}
}

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

func (e *emailSender) dialTLS(addr string, tlsConfig *tls.Config) (*smtp.Client, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create TLS connection to SMTP server: %w", err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.Close()
		return nil, xerrors.Errorf("Failed to parse SMTP server address: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, xerrors.Errorf("Failed to create SMTP client over TLS: %w", err)
	}
	return c, nil
}

func (e *emailSender) dialStartTLS(addr string, tlsConfig *tls.Config) (*smtp.Client, error) {
	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create connection to SMTP server: %w", err)
	}
	if err := c.StartTLS(tlsConfig); err != nil {
		_ = c.Close()
		return nil, xerrors.Errorf("Failed to STARTTLS: %w", err)
	}
	return c, nil
}

func (e *emailSender) sendMail(smtpServerAddr, message string) (err error) {
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
			c, err = e.dialTLS(smtpServerAddr, tlsConfig)
			if err != nil {
				return err
			}
		default:
			c, err = smtp.Dial(smtpServerAddr)
			if err != nil {
				return xerrors.Errorf("Failed to create connection to SMTP server: %w", err)
			}
			if ok, _ := c.Extension("STARTTLS"); ok {
				if err := c.StartTLS(tlsConfig); err != nil {
					_ = c.Close()
					return xerrors.Errorf("Failed to STARTTLS: %w", err)
				}
			}
		}
	case "None":
		c, err = smtp.Dial(smtpServerAddr)
		if err != nil {
			return xerrors.Errorf("Failed to create connection to SMTP server: %w", err)
		}
	case "STARTTLS":
		c, err = e.dialStartTLS(smtpServerAddr, tlsConfig)
		if err != nil {
			return err
		}
	case "SMTPS":
		c, err = e.dialTLS(smtpServerAddr, tlsConfig)
		if err != nil {
			return err
		}
	default:
		return xerrors.New(`invalid TLS mode. accepts: ["", "None", "STARTTLS", "SMTPS"]`)
	}
	defer c.Close()

	if ok, param := c.Extension("AUTH"); ok {
		authList := strings.Fields(param)
		auth := e.newAuth(authList)
		if auth != nil {
			if err = c.Auth(auth); err != nil {
				return xerrors.Errorf("Failed to authenticate: %w", err)
			}
		}
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

	var header strings.Builder
	for k, v := range headers {
		header.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	if err := e.sendMail(net.JoinHostPort(emailConf.SMTPAddr, emailConf.SMTPPort), fmt.Sprintf("%s\r\n%s", header.String(), body)); err != nil {
		return xerrors.Errorf("Failed to send emails: %w", err)
	}
	return nil
}

// NewEMailSender creates emailSender
func NewEMailSender(cnf config.SMTPConf) EMailSender {
	return &emailSender{cnf}
}

func (e *emailSender) newAuth(authList []string) smtp.Auth {
	for _, v := range authList {
		switch strings.ToUpper(v) {
		case "PLAIN":
			return &plainAuth{identity: "", username: e.conf.User, password: e.conf.Password, host: e.conf.SMTPAddr}
		case "LOGIN":
			return &loginAuth{username: e.conf.User, password: e.conf.Password}
		}
	}
	return nil
}
