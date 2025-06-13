//go:build !scanner

package models_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
	cvedict "github.com/vulsio/go-cve-dictionary/models"
)

func TestConvertPaloaltoToModel(t *testing.T) {
	type args struct {
		cveID     string
		paloaltos []cvedict.Paloalto
	}
	tests := []struct {
		name string
		args args
		want []models.CveContent
	}{
		{
			name: "PAN-CVE-2023-44487",
			args: args{
				cveID: "CVE-2023-44487",
				paloaltos: []cvedict.Paloalto{{
					AdvisoryID: "PAN-CVE-2023-44487",
					CveID:      "CVE-2023-44487",
					Title:      "Impact of Rapid Reset and HTTP/2 DoS Vulnerabilities (CVE-2023-44487, CVE-2023-35945)",
					Descriptions: []cvedict.PaloaltoDescription{
						{Description: "The Palo Alto Networks Product Security Assurance team is evaluating the recently disclosed denial-of-service (DoS) vulnerabilities in the HTTP/2 protocol including Rapid Reset (CVE-2023-44487) and CVE-2023-35945.\n\nIf HTTP/2 inspection is enabled in PAN-OS, an ongoing distributed denial-of-service (DDoS) attack in inspected traffic will contribute towards the session capacity limit of the firewall. This can result in the intermittent availability of new firewall sessions and is consistent in impact with other volumetric DDoS attacks. Availability of new firewall sessions will recover naturally once the DDoS attack stops. Customers who have enabled Threat prevention ID 40152 (Applications and Threats content update 8765) blocks this attack from happening in inspected HTTP/2 traffic.\n\nPAN-OS firewalls that do not perform HTTP/2 inspection are not impacted in any way.\nPAN-OS firewalls that do not perform decryption are not impacted by the DDoS attack in encrypted network traffic.\nPAN-OS firewall web interface, Captive Portal, GlobalProtect portals, and GlobalProtect gateways are not impacted by these vulnerabilities.\n\nWhile Prisma Cloud Compute includes vulnerable versions of nghttp2 and golang packages, Prisma Cloud Compute software does not have any HTTP/2 web server endpoints and is not impacted by these vulnerabilities."},
					},
					ProblemTypes: []cvedict.PaloaltoProblemType{
						{CweID: "CWE-400"},
					},
					CVSSv3: []cvedict.PaloaltoCVSS3{
						{
							Cvss3: cvedict.Cvss3{
								VectorString: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
								BaseScore:    0,
								BaseSeverity: "NONE",
							},
						},
						{
							Cvss3: cvedict.Cvss3{
								VectorString: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
								BaseScore:    0,
								BaseSeverity: "NONE",
							},
						},
					},
					CVSSv40: []cvedict.PaloaltoCVSS40{{
						Cvss40: cvedict.Cvss40{
							VectorString: "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
							BaseScore:    0,
							BaseSeverity: "NONE",
						},
					}},
					References: []cvedict.PaloaltoReference{{
						Reference: cvedict.Reference{
							Link: "https://security.paloaltonetworks.com/CVE-2023-44487",
							Tags: "x_refsource_CONFIRM",
						},
					}},
					DatePublic: func() *time.Time {
						t := time.Date(2023, 10, 11, 16, 0, 0, 0, time.UTC)
						return &t
					}(),
				}},
			},
			want: []models.CveContent{{
				Type:           models.Paloalto,
				CveID:          "CVE-2023-44487",
				Title:          "Impact of Rapid Reset and HTTP/2 DoS Vulnerabilities (CVE-2023-44487, CVE-2023-35945)",
				Summary:        "The Palo Alto Networks Product Security Assurance team is evaluating the recently disclosed denial-of-service (DoS) vulnerabilities in the HTTP/2 protocol including Rapid Reset (CVE-2023-44487) and CVE-2023-35945.\n\nIf HTTP/2 inspection is enabled in PAN-OS, an ongoing distributed denial-of-service (DDoS) attack in inspected traffic will contribute towards the session capacity limit of the firewall. This can result in the intermittent availability of new firewall sessions and is consistent in impact with other volumetric DDoS attacks. Availability of new firewall sessions will recover naturally once the DDoS attack stops. Customers who have enabled Threat prevention ID 40152 (Applications and Threats content update 8765) blocks this attack from happening in inspected HTTP/2 traffic.\n\nPAN-OS firewalls that do not perform HTTP/2 inspection are not impacted in any way.\nPAN-OS firewalls that do not perform decryption are not impacted by the DDoS attack in encrypted network traffic.\nPAN-OS firewall web interface, Captive Portal, GlobalProtect portals, and GlobalProtect gateways are not impacted by these vulnerabilities.\n\nWhile Prisma Cloud Compute includes vulnerable versions of nghttp2 and golang packages, Prisma Cloud Compute software does not have any HTTP/2 web server endpoints and is not impacted by these vulnerabilities.",
				Cvss3Score:     0,
				Cvss3Vector:    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
				Cvss3Severity:  "NONE",
				Cvss40Score:    0,
				Cvss40Vector:   "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
				Cvss40Severity: "NONE",
				SourceLink:     "https://security.paloaltonetworks.com/CVE-2023-44487",
				References: []models.Reference{
					{Link: "https://security.paloaltonetworks.com/CVE-2023-44487", Tags: []string{"x_refsource_CONFIRM"}},
				},
				CweIDs:       []string{"CWE-400"},
				Published:    time.Date(2023, 10, 11, 16, 0, 0, 0, time.UTC),
				LastModified: time.Date(2023, 10, 11, 16, 0, 0, 0, time.UTC),
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := models.ConvertPaloaltoToModel(tt.args.cveID, tt.args.paloaltos); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertPaloaltoToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertCiscoToModel(t *testing.T) {
	type args struct {
		cveID  string
		ciscos []cvedict.Cisco
	}
	tests := []struct {
		name string
		args args
		want []models.CveContent
	}{
		{
			name: "cisco-sa-snmp-bypass-HHUVujdn",
			args: args{
				cveID: "CVE-2025-20221",
				ciscos: []cvedict.Cisco{{
					AdvisoryID: "cisco-sa-snmp-bypass-HHUVujdn",
					Title:      "Cisco IOS XE SD-WAN Software Packet Filtering Bypass Vulnerability",
					Summary:    "\r\n\u003cp\u003eA vulnerability in the packet filtering features of Cisco IOS XE SD-WAN Software could allow an unauthenticated, remote attacker to bypass Layer 3 and Layer 4 traffic filters.\u0026nbsp;\u003c/p\u003e\r\n\u003cp\u003eThis vulnerability is due to improper traffic filtering conditions on an affected device. An attacker could exploit this vulnerability by sending a crafted packet to the affected device. A successful exploit could allow the attacker to bypass the Layer 3 and Layer 4 traffic filters and inject a crafted packet into the network.\u003c/p\u003e\r\n\r\n\u003cp\u003eCisco has released software updates that address this vulnerability. There are workarounds that address this vulnerability.\u003c/p\u003e\r\n\u003cp\u003eThis advisory is available at the following link:\u003cbr\u003e\u003ca href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn\" rel=\"nofollow\"\u003ehttps://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn\u003c/a\u003e\u003c/p\u003e\r\n\r\n\u003cp\u003eThis advisory is part of the May 2025 release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication. For a complete list of the advisories and links to them, see \u003ca href=\"https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75279\"\u003eCisco Event Response: May 2025 Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication\u003c/a\u003e.\u003c/p\u003e\r\n",
					SIR:        "Medium",
					CveID:      "CVE-2025-20221",
					BugIDs:     []cvedict.CiscoBugID{},
					CweIDs:     []cvedict.CiscoCweID{{CweID: "CWE-200"}},
					References: []cvedict.CiscoReference{
						{
							Reference: cvedict.Reference{
								Link: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn",
							},
						},
						{
							Reference: cvedict.Reference{
								Link: "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn/csaf/cisco-sa-snmp-bypass-HHUVujdn.json",
							},
						},
						{
							Reference: cvedict.Reference{
								Link: "https://sec.cloudapps.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn/cvrf/cisco-sa-snmp-bypass-HHUVujdn_cvrf.xml",
							},
						},
					},
					FirstPublished: time.Date(2025, 5, 7, 16, 0, 0, 0, time.UTC),
					LastUpdated:    time.Date(2025, 5, 7, 16, 0, 0, 0, time.UTC),
				}},
			},
			want: []models.CveContent{{
				Type:       models.Cisco,
				CveID:      "CVE-2025-20221",
				Title:      "Cisco IOS XE SD-WAN Software Packet Filtering Bypass Vulnerability",
				Summary:    "\r\n\u003cp\u003eA vulnerability in the packet filtering features of Cisco IOS XE SD-WAN Software could allow an unauthenticated, remote attacker to bypass Layer 3 and Layer 4 traffic filters.\u0026nbsp;\u003c/p\u003e\r\n\u003cp\u003eThis vulnerability is due to improper traffic filtering conditions on an affected device. An attacker could exploit this vulnerability by sending a crafted packet to the affected device. A successful exploit could allow the attacker to bypass the Layer 3 and Layer 4 traffic filters and inject a crafted packet into the network.\u003c/p\u003e\r\n\r\n\u003cp\u003eCisco has released software updates that address this vulnerability. There are workarounds that address this vulnerability.\u003c/p\u003e\r\n\u003cp\u003eThis advisory is available at the following link:\u003cbr\u003e\u003ca href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn\" rel=\"nofollow\"\u003ehttps://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn\u003c/a\u003e\u003c/p\u003e\r\n\r\n\u003cp\u003eThis advisory is part of the May 2025 release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication. For a complete list of the advisories and links to them, see \u003ca href=\"https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75279\"\u003eCisco Event Response: May 2025 Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication\u003c/a\u003e.\u003c/p\u003e\r\n",
				SourceLink: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn",
				References: []models.Reference{
					{Link: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn"},
					{Link: "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn/csaf/cisco-sa-snmp-bypass-HHUVujdn.json"},
					{Link: "https://sec.cloudapps.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/cisco-sa-snmp-bypass-HHUVujdn/cvrf/cisco-sa-snmp-bypass-HHUVujdn_cvrf.xml"},
				},
				CweIDs:       []string{"CWE-200"},
				Published:    time.Date(2025, 5, 7, 16, 0, 0, 0, time.UTC),
				LastModified: time.Date(2025, 5, 7, 16, 0, 0, 0, time.UTC),
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := models.ConvertCiscoToModel(tt.args.cveID, tt.args.ciscos); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertCiscoToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}
