package config

import (
	"testing"

	"github.com/future-architect/vuls/constant"
)

func TestDistro_MajorVersion(t *testing.T) {
	var tests = []struct {
		in  Distro
		out int
	}{
		{
			in: Distro{
				Family:  constant.Amazon,
				Release: "2022 (Amazon Linux)",
			},
			out: 2022,
		},
		{
			in: Distro{
				Family:  constant.Amazon,
				Release: "2 (2017.12)",
			},
			out: 2,
		},
		{
			in: Distro{
				Family:  constant.Amazon,
				Release: "2017.12",
			},
			out: 1,
		},
		{
			in: Distro{
				Family:  constant.CentOS,
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
