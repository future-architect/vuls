package config

import (
	"testing"
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
		errs := tt.conf.Validate()
		if len(errs) != tt.expectedErrLength {
			t.Errorf("test: %d, expected %d, actual %d", i, tt.expectedErrLength, len(errs))
		}
	}
}
