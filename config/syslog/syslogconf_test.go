//go:build !windows

package syslog

import (
	"testing"
)

func TestSyslogConfValidate(t *testing.T) {
	var tests = []struct {
		conf              Conf
		expectedErrLength int
	}{
		{
			conf:              Conf{},
			expectedErrLength: 0,
		},
		{
			conf: Conf{
				Protocol: "tcp",
				Port:     "5140",
			},
			expectedErrLength: 0,
		},
		{
			conf: Conf{
				Protocol: "udp",
				Port:     "12345",
				Severity: "emerg",
				Facility: "user",
			},
			expectedErrLength: 0,
		},
		{
			conf: Conf{
				Protocol: "foo",
				Port:     "514",
			},
			expectedErrLength: 1,
		},
		{
			conf: Conf{
				Protocol: "invalid",
				Port:     "-1",
			},
			expectedErrLength: 2,
		},
		{
			conf: Conf{
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
