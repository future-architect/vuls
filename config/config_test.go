package config

import (
	"testing"

	. "github.com/future-architect/vuls/constant"
)

func TestSyslogConfValidate(t *testing.T) {
	var tests = []struct {
		conf              SyslogConf
		expectedErrLength int
	}{
		{
			conf:              SyslogConf{},
			expectedErrLength: 0,
		},
		{
			conf: SyslogConf{
				Protocol: "tcp",
				Port:     "5140",
			},
			expectedErrLength: 0,
		},
		{
			conf: SyslogConf{
				Protocol: "udp",
				Port:     "12345",
				Severity: "emerg",
				Facility: "user",
			},
			expectedErrLength: 0,
		},
		{
			conf: SyslogConf{
				Protocol: "foo",
				Port:     "514",
			},
			expectedErrLength: 1,
		},
		{
			conf: SyslogConf{
				Protocol: "invalid",
				Port:     "-1",
			},
			expectedErrLength: 2,
		},
		{
			conf: SyslogConf{
				Protocol: "invalid",
				Port:     "invalid",
				Severity: "invalid",
				Facility: "invalid",
			},
			expectedErrLength: 4,
		},
	}

	for i, tt := range tests {
		tt.conf.Enabled = true
		errs := tt.conf.Validate()
		if len(errs) != tt.expectedErrLength {
			t.Errorf("test: %d, expected %d, actual %d", i, tt.expectedErrLength, len(errs))
		}
	}
}

func TestDistro_MajorVersion(t *testing.T) {
	var tests = []struct {
		in  Distro
		out int
	}{
		{
			in: Distro{
				Family:  Amazon,
				Release: "2 (2017.12)",
			},
			out: 2,
		},
		{
			in: Distro{
				Family:  Amazon,
				Release: "2017.12",
			},
			out: 1,
		},
		{
			in: Distro{
				Family:  CentOS,
				Release: "7.10",
			},
			out: 7,
		},
	}

	for i, tt := range tests {
		ver, err := tt.in.MajorVersion()
		if err != nil {
			t.Errorf("[%d] err occurred: %s", i, err)
		}
		if tt.out != ver {
			t.Errorf("[%d] expected %d, actual %d", i, tt.out, ver)
		}
	}
}
