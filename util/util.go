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
	"fmt"
	"net/url"
	"strings"

	"github.com/future-architect/vuls/config"
)

// GenWorkers generates goroutine
// http://qiita.com/na-o-ys/items/65373132b1c5bc973cca
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			defer func() {
				if p := recover(); p != nil {
					log := NewCustomLogger(config.ServerInfo{})
					log.Debugf("Panic: %s")
				}
			}()
			for f := range tasks {
				f()
			}
		}()
	}
	return tasks
}

// AppendIfMissing append to the slice if missing
func AppendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}

// URLPathJoin make URL
func URLPathJoin(baseURL string, paths ...string) (string, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	trimedPaths := []string{}
	for _, path := range paths {
		trimed := strings.Trim(path, " /")
		if len(trimed) != 0 {
			trimedPaths = append(trimedPaths, trimed)
		}
	}
	var url *url.URL
	url, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	url.Path += strings.Join(trimedPaths, "/")
	return url.String(), nil
}

// URLPathParamJoin make URL
func URLPathParamJoin(baseURL string, paths []string, params map[string]string) (string, error) {
	urlPath, err := URLPathJoin(baseURL, paths...)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(urlPath)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	for key := range params {
		parameters.Add(key, params[key])
	}
	u.RawQuery = parameters.Encode()
	return u.String(), nil
}

// ProxyEnv returns shell environment variables to set proxy
func ProxyEnv() string {
	httpProxyEnv := ""
	keys := []string{
		"http_proxy",
		"https_proxy",
		"HTTP_PROXY",
		"HTTPS_PROXY",
	}
	for _, key := range keys {
		httpProxyEnv += fmt.Sprintf(
			` %s="%s"`, key, config.Conf.HTTPProxy)
	}
	return httpProxyEnv
}

// PrependProxyEnv prepends proxy enviroment variable
func PrependProxyEnv(cmd string) string {
	if len(config.Conf.HTTPProxy) == 0 {
		return cmd
	}
	return fmt.Sprintf("%s %s", ProxyEnv(), cmd)
}

//  func unixtime(s string) (time.Time, error) {
//      i, err := strconv.ParseInt(s, 10, 64)
//      if err != nil {
//          return time.Time{}, err
//      }
//      return time.Unix(i, 0), nil
//  }

// Truncate truncates string to the length
func Truncate(str string, length int) string {
	if length < 0 {
		return str
	}
	if length <= len(str) {
		return str[:length]
	}
	return str
}

// Distinct a slice
func Distinct(ss []string) (distincted []string) {
	m := map[string]bool{}
	for _, s := range ss {
		if _, found := m[s]; !found {
			m[s] = true
			distincted = append(distincted, s)
		}
	}
	return
}
