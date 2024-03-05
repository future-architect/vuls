package syslog

// Conf is syslog config
type Conf struct {
	Protocol string `json:"-"`
	Host     string `valid:"host" json:"-"`
	Port     string `valid:"port" json:"-"`
	Severity string `json:"-"`
	Facility string `json:"-"`
	Tag      string `json:"-"`
	Verbose  bool   `json:"-"`
	Enabled  bool   `toml:"-" json:"-"`
}
