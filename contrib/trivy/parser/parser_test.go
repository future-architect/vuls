package parser

import (
	"testing"

	"github.com/d4l3k/messagediff"
	"github.com/future-architect/vuls/models"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		vulnJSON   []byte
		scanResult *models.ScanResult
		expected   *models.ScanResult
	}{
		"golang:1.12-alpine": {
			vulnJSON: []byte(`[
  {
    "Target": "golang:1.12-alpine (alpine 3.11.3)",
    "Type": "alpine",
    "Vulnerabilities": [
      {
        "VulnerabilityID": "CVE-2020-1967",
        "PkgName": "openssl",
        "InstalledVersion": "1.1.1d-r3",
        "FixedVersion": "1.1.1g-r0",
        "Layer": {
          "Digest": "sha256:c9b1b535fdd91a9855fb7f82348177e5f019329a58c53c47272962dd60f71fc9",
          "DiffID": "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"
        },
        "SeveritySource": "nvd",
        "Title": "openssl: Segmentation fault in SSL_check_chain causes denial of service",
        "Description": "Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the \"signature_algorithms_cert\" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).",
        "Severity": "MEDIUM",
        "References": [
          "http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html",
          "http://seclists.org/fulldisclosure/2020/May/5",
          "http://www.openwall.com/lists/oss-security/2020/04/22/2",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1967",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1",
          "https://github.com/irsl/CVE-2020-1967",
          "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440",
          "https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E",
          "https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E",
          "https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/",
          "https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc",
          "https://security.gentoo.org/glsa/202004-10",
          "https://security.netapp.com/advisory/ntap-20200424-0003/",
          "https://www.debian.org/security/2020/dsa-4661",
          "https://www.openssl.org/news/secadv/20200421.txt",
          "https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL",
          "https://www.tenable.com/security/tns-2020-03"
        ]
      }
    ]
  }
]`),
			scanResult: &models.ScanResult{
				JSONVersion: 1,
				ServerUUID:  "uuid",
				ScannedCves: models.VulnInfos{},
			},
			expected: &models.ScanResult{
				JSONVersion: 1,
				ServerUUID:  "uuid",
				ServerName:  "golang:1.12-alpine (alpine 3.11.3)",
				Family:      "alpine",
				ScannedBy:   "trivy",
				ScannedVia:  "trivy",
				ScannedCves: models.VulnInfos{
					"CVE-2020-1967": {
						CveID: "CVE-2020-1967",
						Confidences: models.Confidences{
							models.Confidence{Score: 100,
								DetectionMethod: "TrivyMatch",
								SortOrder:       0,
							},
						},
						AffectedPackages: models.PackageFixStatuses{
							models.PackageFixStatus{
								Name:        "openssl",
								NotFixedYet: false,
								FixState:    "affected",
								FixedIn:     "1.1.1g-r0",
							}},
						CveContents:     models.CveContents{},
						LibraryFixedIns: models.LibraryFixedIns{},
						VulnType:        "",
					},
				},
				Packages: models.Packages{
					"openssl": models.Package{
						Name:    "openssl",
						Version: "1.1.1d-r3",
						Release: "",
					},
				},
			},
		},
	}

	for testcase, v := range cases {
		actual, err := Parse(v.vulnJSON, v.scanResult)
		if err != nil {
			t.Errorf("%s", err)
		}

		diff, equal := messagediff.PrettyDiff(
			v.expected,
			actual,
			messagediff.IgnoreStructField("ScannedAt"),
		)
		if !equal {
			t.Errorf("test: %s, diff %s", testcase, diff)
		}
	}
}
