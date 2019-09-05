package report

import (
	"net/smtp"
	"reflect"
	"strings"
	"testing"

	"github.com/future-architect/vuls/config"
)

type emailRecorder struct {
	addr string
	auth smtp.Auth
	from string
	to   []string
	body string
}

type mailTest struct {
	in  config.SMTPConf
	out emailRecorder
}

var mailTests = []mailTest{
	{
		config.SMTPConf{
			SMTPAddr: "127.0.0.1",
			SMTPPort: "25",

			From: "from@address.com",
			To:   []string{"to@address.com"},
			Cc:   []string{"cc@address.com"},
		},
		emailRecorder{
			addr: "127.0.0.1:25",
			auth: smtp.PlainAuth("", "", "", "127.0.0.1"),
			from: "from@address.com",
			to:   []string{"to@address.com", "cc@address.com"},
			body: "body",
		},
	},
	{
		config.SMTPConf{
			SMTPAddr: "127.0.0.1",
			SMTPPort: "25",

			User:     "vuls",
			Password: "password",

			From: "from@address.com",
			To:   []string{"to1@address.com", "to2@address.com"},
			Cc:   []string{"cc1@address.com", "cc2@address.com"},
		},
		emailRecorder{
			addr: "127.0.0.1:25",
			auth: smtp.PlainAuth(
				"",
				"vuls",
				"password",
				"127.0.0.1",
			),
			from: "from@address.com",
			to: []string{"to1@address.com", "to2@address.com",
				"cc1@address.com", "cc2@address.com"},
			body: "body",
		},
	},
}

func TestSend(t *testing.T) {
	for i, test := range mailTests {
		f, r := mockSend(nil)
		sender := &emailSender{conf: test.in, send: f}

		subject := "subject"
		body := "body"
		if err := sender.Send(subject, body); err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if r.addr != test.out.addr {
			t.Errorf("#%d: wrong 'addr' field.\r\nexpected: %s\n got: %s", i, test.out.addr, r.addr)
		}

		if !reflect.DeepEqual(r.auth, test.out.auth) && r.auth != nil {
			t.Errorf("#%d: wrong 'auth' field.\r\nexpected: %v\n got: %v", i, test.out.auth, r.auth)
		}

		if r.from != test.out.from {
			t.Errorf("#%d: wrong 'from' field.\r\nexpected: %v\n got: %v", i, test.out.from, r.from)
		}

		if !reflect.DeepEqual(r.to, test.out.to) {
			t.Errorf("#%d: wrong 'to' field.\r\nexpected: %v\n got: %v", i, test.out.to, r.to)
		}

		if r.body != test.out.body {
			t.Errorf("#%d: wrong 'body' field.\r\nexpected: %v\n got: %v", i, test.out.body, r.body)
		}

	}

}

func mockSend(errToReturn error) (func(string, smtp.Auth, string, []string, []byte) error, *emailRecorder) {
	r := new(emailRecorder)
	return func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		// Split into header and body
		messages := strings.Split(string(msg), "\r\n\r\n")
		body := messages[1]
		*r = emailRecorder{addr, a, from, to, body}
		return errToReturn
	}, r
}
