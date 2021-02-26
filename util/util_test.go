package util

import (
	"testing"

	"github.com/future-architect/vuls/config"
)

func TestUrlJoin(t *testing.T) {
	var tests = []struct {
		in  []string
		out string
	}{
		{
			[]string{
				"http://hoge.com:8080",
				"status",
			},
			"http://hoge.com:8080/status",
		},
		{
			[]string{
				"http://hoge.com:8080/",
				"status",
			},
			"http://hoge.com:8080/status",
		},
		{
			[]string{
				"http://hoge.com:8080",
				"/status",
			},
			"http://hoge.com:8080/status",
		},
		{
			[]string{
				"http://hoge.com:8080/",
				"/status",
			},
			"http://hoge.com:8080/status",
		},
		{
			[]string{
				"http://hoge.com:8080/",
				"/status",
			},
			"http://hoge.com:8080/status",
		},
		{
			[]string{
				"http://hoge.com:8080/",
				"",
				"hega",
				"",
			},
			"http://hoge.com:8080/hega",
		},
		{
			[]string{
				"http://hoge.com:8080/",
				"status",
				"/fuga",
			},
			"http://hoge.com:8080/status/fuga",
		},
	}
	for _, tt := range tests {
		baseurl := tt.in[0]
		paths := tt.in[1:]
		actual, err := URLPathJoin(baseurl, paths...)
		if err != nil {
			t.Errorf("\nunexpected error occurred, err: %+v,\ninput:%#v\nexpected: %s\n  actual: %s", err, tt.in, tt.out, actual)
		}
		if actual != tt.out {
			t.Errorf("\ninput:%#v\nexpected: %s\n  actual: %s", tt.in, tt.out, actual)
		}
	}

}

func TestPrependHTTPProxyEnv(t *testing.T) {
	var tests = []struct {
		in  []string
		out string
	}{
		{
			[]string{
				"http://proxy.co.jp:8080",
				"yum check-update",
			},
			` http_proxy="http://proxy.co.jp:8080" https_proxy="http://proxy.co.jp:8080" HTTP_PROXY="http://proxy.co.jp:8080" HTTPS_PROXY="http://proxy.co.jp:8080" yum check-update`,
		},
		{
			[]string{
				"http://proxy.co.jp:8080",
				"",
			},
			` http_proxy="http://proxy.co.jp:8080" https_proxy="http://proxy.co.jp:8080" HTTP_PROXY="http://proxy.co.jp:8080" HTTPS_PROXY="http://proxy.co.jp:8080" `,
		},
		{
			[]string{
				"",
				"yum check-update",
			},
			`yum check-update`,
		},
	}
	for _, tt := range tests {
		config.Conf.HTTPProxy = tt.in[0]
		actual := PrependProxyEnv(tt.in[1])
		if actual != tt.out {
			t.Errorf("\nexpected: %s\n  actual: %s", tt.out, actual)
		}
	}

}

func TestTruncate(t *testing.T) {
	var tests = []struct {
		in     string
		length int
		out    string
	}{
		{
			in:     "abcde",
			length: 3,
			out:    "abc",
		},
		{
			in:     "abcdefg",
			length: 5,
			out:    "abcde",
		},
		{
			in:     "abcdefg",
			length: 10,
			out:    "abcdefg",
		},
		{
			in:     "abcdefg",
			length: 0,
			out:    "",
		},
		{
			in:     "abcdefg",
			length: -1,
			out:    "abcdefg",
		},
	}
	for _, tt := range tests {
		actual := Truncate(tt.in, tt.length)
		if actual != tt.out {
			t.Errorf("\nexpected: %s\n  actual: %s", tt.out, actual)
		}
	}
}

func Test_major(t *testing.T) {
	var tests = []struct {
		in       string
		expected string
	}{
		{
			in:       "",
			expected: "",
		},
		{
			in:       "4.1",
			expected: "4",
		},
		{
			in:       "0:4.1",
			expected: "4",
		},
	}
	for i, tt := range tests {
		a := Major(tt.in)
		if tt.expected != a {
			t.Errorf("[%d]\nexpected: %s\n  actual: %s\n", i, tt.expected, a)
		}
	}
}
