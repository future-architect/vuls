//go:build !scanner

package models_test

import (
	"cmp"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
	cvedict "github.com/vulsio/go-cve-dictionary/models"
)

func TestConvertEuvdToModel(t *testing.T) {
	type args struct {
		cveID string
		euvds []cvedict.Euvd
	}
	tests := []struct {
		name string
		args args
		want []models.CveContent
	}{
		{
			name: "CVE-2025-49575",
			args: args{
				cveID: "CVE-2025-49575",
				euvds: []cvedict.Euvd{
					{
						EuvdID:        "EUVD-2025-18144",
						EnisaUUID:     "e15c6dcd-bca6-37ab-b0e0-e1cd92a91c98",
						Description:   "Citizen skin vulnerable to stored XSS through multiple system messages",
						DatePublished: time.Date(2025, time.June, 11, 19, 59, 54, 0, time.UTC),
						DateUpdated:   time.Date(2025, time.June, 13, 03, 43, 58, 0, time.UTC),
						References: []cvedict.EuvdReference{
							{
								Reference: cvedict.Reference{
									Link: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87",
									Name: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87",
								},
							},
							{
								Reference: cvedict.Reference{
									Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575",
									Name: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575",
								},
							},
						},
						Aliases: []cvedict.EuvdAlias{
							{
								Alias: "GHSA-4c2h-67qq-vm87",
							},
							{
								Alias: "CVE-2025-49575",
							},
						},
					},
					{
						EuvdID:           "EUVD-2025-18208",
						EnisaUUID:        "c8b99a1b-5107-3825-a99f-30d856d6c47e",
						Description:      "Citizen skin vulnerable to stored XSS through multiple system messages",
						DatePublished:    time.Date(2025, time.June, 11, 19, 59, 54, 0, time.UTC),
						DateUpdated:      time.Date(2025, time.June, 13, 03, 43, 58, 0, time.UTC),
						BaseScore:        6.5,
						BaseScoreVersion: "3.1",
						BaseScoreVector:  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
						References: []cvedict.EuvdReference{
							{
								Reference: cvedict.Reference{
									Link: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87",
									Name: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87",
								},
							},
							{
								Reference: cvedict.Reference{
									Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575",
									Name: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575",
								},
							},
						},
						Aliases: []cvedict.EuvdAlias{
							{
								Alias: "CVE-2025-49575",
							},
						},
						Assigner: "GitHub_M",
						EPSS:     0.02,
					},
				},
			},
			want: []models.CveContent{
				{
					Type:       models.Euvd,
					CveID:      "CVE-2025-49575",
					Title:      "EUVD-2025-18144",
					Summary:    "Citizen skin vulnerable to stored XSS through multiple system messages",
					SourceLink: "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-18144",
					References: []models.Reference{
						{Link: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87"},
						{Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575"},
					},
					Published:    time.Date(2025, time.June, 11, 19, 59, 54, 0, time.UTC),
					LastModified: time.Date(2025, time.June, 13, 03, 43, 58, 0, time.UTC),
				},
				{
					Type:          models.Euvd,
					CveID:         "CVE-2025-49575",
					Title:         "EUVD-2025-18208",
					Summary:       "Citizen skin vulnerable to stored XSS through multiple system messages",
					Cvss3Score:    6.5,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
					Cvss3Severity: "MEDIUM",
					SourceLink:    "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-18208",
					References: []models.Reference{
						{Link: "https://github.com/StarCitizenTools/mediawiki-skins-Citizen/security/advisories/GHSA-4c2h-67qq-vm87"},
						{Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-49575"},
					},
					Published:    time.Date(2025, time.June, 11, 19, 59, 54, 0, time.UTC),
					LastModified: time.Date(2025, time.June, 13, 03, 43, 58, 0, time.UTC),
				},
			},
		},
		{
			name: "CVE-2025-34028",
			args: args{
				cveID: "CVE-2025-34028",
				euvds: []cvedict.Euvd{
					{
						EuvdID:           "EUVD-2025-12275",
						EnisaUUID:        "631cd45a-4015-314b-b4b4-099d07280668",
						Description:      "The Commvault Command Center Innovation Release allows an unauthenticated actor to upload ZIP files that represent install packages that, when expanded by the target server, are vulnerable to path traversal vulnerability that can result in Remote Code Execution via malicious JSP.\n\n\n\n\n\nThis issue affects Command Center Innovation Release: 11.38.0 to 11.38.20. The vulnerability is fixed in 11.38.20 with SP38-CU20-433 and SP38-CU20-436 and also fixed in 11.38.25 with SP38-CU25-434 and SP38-CU25-438.",
						DatePublished:    time.Date(2025, time.April, 22, 16, 32, 23, 0, time.UTC),
						DateUpdated:      time.Date(2025, time.November, 29, 02, 06, 36, 0, time.UTC),
						BaseScore:        9.3,
						BaseScoreVersion: "4.0",
						BaseScoreVector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H",
						References: []cvedict.EuvdReference{
							{
								Reference: cvedict.Reference{
									Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-34028",
									Name: "https://nvd.nist.gov/vuln/detail/CVE-2025-34028",
								},
							},
							{
								Reference: cvedict.Reference{
									Link: "https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html",
									Name: "https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html",
								},
							},
						},
						Aliases: []cvedict.EuvdAlias{
							{
								Alias: "CVE-2025-34028",
							},
							{
								Alias: "GHSA-6q9c-pjw5-5rjm",
							},
						},
						Assigner:       "VulnCheck",
						EPSS:           45.93,
						ExploitedSince: func() *time.Time { t := time.Date(2025, time.May, 02, 12, 00, 00, 0, time.UTC); return &t }(),
					},
				},
			},
			want: []models.CveContent{
				{
					Type:           models.Euvd,
					CveID:          "CVE-2025-34028",
					Title:          "EUVD-2025-12275",
					Summary:        "The Commvault Command Center Innovation Release allows an unauthenticated actor to upload ZIP files that represent install packages that, when expanded by the target server, are vulnerable to path traversal vulnerability that can result in Remote Code Execution via malicious JSP.\n\n\n\n\n\nThis issue affects Command Center Innovation Release: 11.38.0 to 11.38.20. The vulnerability is fixed in 11.38.20 with SP38-CU20-433 and SP38-CU20-436 and also fixed in 11.38.25 with SP38-CU25-434 and SP38-CU25-438.",
					Cvss40Score:    9.3,
					Cvss40Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H",
					Cvss40Severity: "CRITICAL",
					SourceLink:     "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-12275",
					References: []models.Reference{
						{Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-34028"},
						{Link: "https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html"},
					},
					Published:    time.Date(2025, time.April, 22, 16, 32, 23, 0, time.UTC),
					LastModified: time.Date(2025, time.November, 29, 02, 06, 36, 0, time.UTC),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := models.ConvertEuvdToModel(tt.args.cveID, tt.args.euvds); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertEuvdToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestConvertVulncheckToModel(t *testing.T) {
	type args struct {
		cveID      string
		vulnchecks []cvedict.Vulncheck
	}
	tests := []struct {
		name string
		args args
		want []models.CveContent
	}{
		{
			name: "CVE-2025-0108",
			args: args{
				cveID: "CVE-2025-0108",
				vulnchecks: []cvedict.Vulncheck{{
					CveID: "CVE-2025-0108",
					Descriptions: []cvedict.VulncheckDescription{
						{
							Lang:  "en",
							Value: "An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.\n\nYou can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .\n\nThis issue does not affect Cloud NGFW or Prisma Access software.",
						},
						{
							Lang:  "es",
							Value: "Una omisión de autenticación en el software PAN-OS de Palo Alto Networks permite que un atacante no autenticado con acceso a la red a la interfaz web de administración omita la autenticación que de otro modo requeriría la interfaz web de administración de PAN-OS e invoque ciertos scripts PHP. Si bien la invocación de estos scripts PHP no permite la ejecución remota de código, puede afectar negativamente la integridad y la confidencialidad de PAN-OS. Puede reducir en gran medida el riesgo de este problema al restringir el acceso a la interfaz web de administración solo a direcciones IP internas confiables de acuerdo con nuestras pautas de implementación de mejores prácticas recomendadas https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 . Este problema no afecta al software Cloud NGFW ni a Prisma Access.",
						},
					},
					Cvss2: []cvedict.VulncheckCvss2Extra{},
					Cvss3: []cvedict.VulncheckCvss3{{
						Source: "nvd@nist.gov",
						Type:   "Primary",
						Cvss3: cvedict.Cvss3{
							VectorString:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
							BaseScore:           9.1,
							BaseSeverity:        "CRITICAL",
							ExploitabilityScore: 3.9,
							ImpactScore:         5.0,
						},
					}},
					Cvss40: []cvedict.VulncheckCvss40{{
						Source: "psirt@paloaltonetworks.com",
						Type:   "Secondary",
						Cvss40: cvedict.Cvss40{
							VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:N/R:U/V:C/RE:M/U:Red",
							BaseScore:    8.8,
							BaseSeverity: "HIGH",
						},
					}},
					Cwes: []cvedict.VulncheckCwe{
						{
							Source: "psirt@paloaltonetworks.com",
							Type:   "Secondary",
							CweID:  "CWE-306",
						},
						{
							Source: "nvd@nist.gov",
							Type:   "Primary",
							CweID:  "CWE-306",
						},
					},
					References: []cvedict.VulncheckReference{
						{
							Reference: cvedict.Reference{
								Link:   "https://security.paloaltonetworks.com/CVE-2025-0108",
								Source: "psirt@paloaltonetworks.com",
								Tags:   "Exploit,Vendor Advisory",
								Name:   "https://security.paloaltonetworks.com/CVE-2025-0108",
							},
						},
					},
					PublishedDate:    time.Date(2025, 02, 12, 21, 15, 16, int(190*time.Millisecond), time.UTC),
					LastModifiedDate: time.Date(2025, 06, 27, 20, 39, 59, int(717*time.Millisecond), time.UTC),
				}},
			},
			want: []models.CveContent{
				{
					Type:          models.Vulncheck,
					CveID:         "CVE-2025-0108",
					Summary:       "An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.\n\nYou can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .\n\nThis issue does not affect Cloud NGFW or Prisma Access software.",
					Cvss3Score:    9.1,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Cvss3Severity: "CRITICAL",
					SourceLink:    "https://console.vulncheck.com/cve/CVE-2025-0108",
					References: []models.Reference{
						{
							Link:   "https://security.paloaltonetworks.com/CVE-2025-0108",
							Source: "psirt@paloaltonetworks.com",
							Tags:   []string{"Exploit", "Vendor Advisory"},
						},
					},
					CweIDs:       []string{"CWE-306"},
					Published:    time.Date(2025, 02, 12, 21, 15, 16, int(190*time.Millisecond), time.UTC),
					LastModified: time.Date(2025, 06, 27, 20, 39, 59, int(717*time.Millisecond), time.UTC),
					Optional:     map[string]string{"source": "nvd@nist.gov"},
				},
				{
					Type:           models.Vulncheck,
					CveID:          "CVE-2025-0108",
					Summary:        "An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.\n\nYou can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .\n\nThis issue does not affect Cloud NGFW or Prisma Access software.",
					Cvss40Score:    8.8,
					Cvss40Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:N/R:U/V:C/RE:M/U:Red",
					Cvss40Severity: "HIGH",
					SourceLink:     "https://console.vulncheck.com/cve/CVE-2025-0108",
					References: []models.Reference{
						{
							Link:   "https://security.paloaltonetworks.com/CVE-2025-0108",
							Source: "psirt@paloaltonetworks.com",
							Tags:   []string{"Exploit", "Vendor Advisory"},
						},
					},
					CweIDs:       []string{"CWE-306"},
					Published:    time.Date(2025, 02, 12, 21, 15, 16, int(190*time.Millisecond), time.UTC),
					LastModified: time.Date(2025, 06, 27, 20, 39, 59, int(717*time.Millisecond), time.UTC),
					Optional:     map[string]string{"source": "psirt@paloaltonetworks.com"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := models.ConvertVulncheckToModel(tt.args.cveID, tt.args.vulnchecks)

			slices.SortFunc(got, func(i, j models.CveContent) int {
				switch {
				case i.Optional["source"] == "nvd@nist.gov" && j.Optional["source"] != "nvd@nist.gov":
					return -1
				case i.Optional["source"] != "nvd@nist.gov" && j.Optional["source"] == "nvd@nist.gov":
					return +1
				default:
					return cmp.Or(
						cmp.Compare(i.Cvss2Score, j.Cvss2Score),
						cmp.Compare(i.Cvss3Score, j.Cvss3Score),
						cmp.Compare(i.Cvss40Score, j.Cvss40Score),
					)
				}
			})

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertVulncheckToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
