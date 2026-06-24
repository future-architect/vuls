package cwe

// CWE has CWE information
type CWE struct {
	CWEID               string `json:"cweID"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	ExtendedDescription string `json:"extendedDescription"`
	Lang                string `json:"-"`
}

// CweTopTwentyfiveURLs has CWE Top25 links
var CweTopTwentyfiveURLs = map[string]string{
	"2019": "https://cwe.mitre.org/top25/archive/2019/2019_cwe_top25.html",
	"2020": "https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html",
	"2021": "https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html",
	"2022": "https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html",
	"2023": "https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html",
	"2024": "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html",
	"2025": "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
}

// SansTopTwentyfiveURLs has CWE/SANS Top25 links
var SansTopTwentyfiveURLs = map[string]string{
	"2009": "https://cwe.mitre.org/top25/archive/2009/2009_cwe_sans_top25.html",
	"2010": "https://cwe.mitre.org/top25/archive/2010/2010_cwe_sans_top25.html",
	"2011": "https://cwe.mitre.org/top25/archive/2011/2011_cwe_sans_top25.html",
}

// OwaspTopTenURLsEn has GitHub links
var OwaspTopTenURLsEn = map[string]map[string]string{
	"2017": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa1-injection.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa2-broken-authentication.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa3-sensitive-data-disclosure.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa4-xxe.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa5-broken-access-control.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa6-security-misconfiguration.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa7-xss.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa8-insecure-deserialization.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa9-known-vulns.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2017/en/0xaa-logging-detection-response.md",
	},
	"2021": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A01_2021-Broken_Access_Control.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A03_2021-Injection.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A04_2021-Insecure_Design.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A05_2021-Security_Misconfiguration.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A06_2021-Vulnerable_and_Outdated_Components.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A07_2021-Identification_and_Authentication_Failures.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A08_2021-Software_and_Data_Integrity_Failures.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A09_2021-Security_Logging_and_Monitoring_Failures.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2021/docs/A10_2021-Server-Side_Request_Forgery_(SSRF).md",
	},
}

// OwaspTopTenURLsJa has GitHub links
var OwaspTopTenURLsJa = map[string]map[string]string{
	"2017": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa1-injection.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa2-broken-authentication.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa3-sensitive-data-disclosure.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa4-xxe.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa5-broken-access-control.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa6-security-misconfiguration.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa7-xss.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa8-insecure-deserialization.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa9-known-vulns.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2017/ja/0xaa-logging-detection-response.md",
	},
	"2021": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A01_2021-Broken_Access_Control.ja.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.ja.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A03_2021-Injection.ja.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A04_2021-Insecure_Design.ja.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A05_2021-Security_Misconfiguration.ja.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A06_2021-Vulnerable_and_Outdated_Components.ja.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A07_2021-Identification_and_Authentication_Failures.ja.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A08_2021-Software_and_Data_Integrity_Failures.ja.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A09_2021-Security_Logging_and_Monitoring_Failures.ja.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2021/docs/A10_2021-Server-Side_Request_Forgery_(SSRF).ja.md",
	},
}
