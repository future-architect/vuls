package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// SMTPConf is smtp config
type SMTPConf struct {
	SMTPAddr      string   `toml:"smtpAddr,omitempty" json:"-"`
	SMTPPort      string   `toml:"smtpPort,omitempty" valid:"port" json:"-"`
	User          string   `toml:"user,omitempty" json:"-"`
	Password      string   `toml:"password,omitempty" json:"-"`
	From          string   `toml:"from,omitempty" json:"-"`
	To            []string `toml:"to,omitempty" json:"-"`
	Cc            []string `toml:"cc,omitempty" json:"-"`
	SubjectPrefix string   `toml:"subjectPrefix,omitempty" json:"-"`
	Enabled       bool     `toml:"-" json:"-"`
}

func checkEmails(emails []string) (errs []error) {
	for _, addr := range emails {
		if len(addr) == 0 {
			return
		}
		if ok := govalidator.IsEmail(addr); !ok {
			errs = append(errs, xerrors.Errorf("Invalid email address. email: %s", addr))
		}
	}
	return
}

// Validate SMTP configuration
func (c *SMTPConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	emails := []string{}
	emails = append(emails, c.From)
	emails = append(emails, c.To...)
	emails = append(emails, c.Cc...)

	if emailErrs := checkEmails(emails); 0 < len(emailErrs) {
		errs = append(errs, emailErrs...)
	}

	if c.SMTPAddr == "" {
		errs = append(errs, xerrors.New("email.smtpAddr must not be empty"))
	}
	if c.SMTPPort == "" {
		errs = append(errs, xerrors.New("email.smtpPort must not be empty"))
	}
	if len(c.To) == 0 {
		errs = append(errs, xerrors.New("email.To required at least one address"))
	}
	if len(c.From) == 0 {
		errs = append(errs, xerrors.New("email.From required at least one address"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
