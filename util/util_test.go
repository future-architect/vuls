/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
			t.Errorf("\nunexpected error occurred, err: %s,\ninput:%#v\nexpected: %s\n  actual: %s", err, tt.in, tt.out, actual)
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
