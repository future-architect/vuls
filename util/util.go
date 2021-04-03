package util

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// GenWorkers generates goroutine
// http://qiita.com/na-o-ys/items/65373132b1c5bc973cca
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			defer func() {
				if p := recover(); p != nil {
					logging.Log.Errorf("run time panic: %+v", p)
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
	trimmedPaths := []string{}
	for _, path := range paths {
		trimmed := strings.Trim(path, " /")
		if len(trimmed) != 0 {
			trimmedPaths = append(trimmedPaths, trimmed)
		}
	}
	var url *url.URL
	url, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	url.Path += "/" + strings.Join(trimmedPaths, "/")
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

// IP returns scanner network ip addresses
func IP() (ipv4Addrs []string, ipv6Addrs []string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// only global unicast address
			if !ip.IsGlobalUnicast() {
				continue
			}

			if ok := ip.To4(); ok != nil {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			} else {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		}
	}
	return ipv4Addrs, ipv6Addrs, nil
}

// PrependProxyEnv prepends proxy environment variable
func PrependProxyEnv(cmd string) string {
	if config.Conf.HTTPProxy == "" {
		return cmd
	}
	return fmt.Sprintf("%s %s", proxyEnv(), cmd)
}

// proxyEnv returns shell environment variables to set proxy
func proxyEnv() string {
	httpProxyEnv := ""
	keys := []string{
		"http_proxy",
		"https_proxy",
		"HTTP_PROXY",
		"HTTPS_PROXY",
	}
	for _, key := range keys {
		httpProxyEnv += fmt.Sprintf(` %s="%s"`, key, config.Conf.HTTPProxy)
	}
	return httpProxyEnv
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

// Major return the major version of the given semantic version
func Major(version string) string {
	if version == "" {
		return ""
	}
	ss := strings.SplitN(version, ":", 2)
	ver := ""
	if len(ss) == 1 {
		ver = ss[0]
	} else {
		ver = ss[1]
	}
	return ver[0:strings.Index(ver, ".")]
}

// GetHTTPClient return http.Client
func GetHTTPClient(proxy string) (*http.Client, error) {
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}, nil
	}
	return &http.Client{}, nil
}
