//go:build !scanner

package oval

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

func TestSUSE_convertToModel(t *testing.T) {
	tests := []struct {
		name string
		args *ovalmodels.Definition
		want *models.CveContent
	}{
		{
			name: "2023-11-15",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID:  "CVE-2021-4024",
							Cvss3:  "4.8/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://www.suse.com/security/cve/CVE-2021-4024/",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:         "CVE-2021-4024",
				Title:         "CVE-2021-4024",
				Summary:       "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Cvss3Score:    4.8,
				Cvss3Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
				Cvss3Severity: "moderate",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "href ends with .html",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID: "CVE-2021-4024",
							Href:  "https://www.suse.com/security/cve/CVE-2021-4024.html",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:   "CVE-2021-4024",
				Title:   "CVE-2021-4024",
				Summary: "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "mix SUSE and NVD",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID:  "CVE-2021-4024",
							Cvss3:  "6.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://nvd.nist.gov/vuln/detail/CVE-2021-4024",
						},
						{
							CveID:  "CVE-2021-4024",
							Cvss3:  "4.8/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://www.suse.com/security/cve/CVE-2021-4024.html",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:         "CVE-2021-4024",
				Title:         "CVE-2021-4024",
				Summary:       "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Cvss3Score:    4.8,
				Cvss3Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
				Cvss3Severity: "moderate",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "mix SUSE and NVD(by old goval-dictionary)",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID:  "CVE-2021-4024 at NVD",
							Cvss3:  "6.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://nvd.nist.gov/vuln/detail/CVE-2021-4024",
						},
						{
							CveID:  "CVE-2021-4024 at SUSE",
							Cvss3:  "4.8/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://www.suse.com/security/cve/CVE-2021-4024/",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:         "CVE-2021-4024",
				Title:         "CVE-2021-4024",
				Summary:       "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Cvss3Score:    4.8,
				Cvss3Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
				Cvss3Severity: "moderate",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "NVD only",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID:  "CVE-2021-4024",
							Cvss3:  "6.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://nvd.nist.gov/vuln/detail/CVE-2021-4024",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:   "CVE-2021-4024",
				Title:   "CVE-2021-4024",
				Summary: "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "NVD only(by old goval-dictionary)",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID:  "CVE-2021-4024 at NVD",
							Cvss3:  "6.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
							Impact: "moderate",
							Href:   "https://nvd.nist.gov/vuln/detail/CVE-2021-4024",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:   "CVE-2021-4024",
				Title:   "CVE-2021-4024",
				Summary: "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
		{
			name: "MITRE only",
			args: &ovalmodels.Definition{
				DefinitionID: "oval:org.opensuse.security:def:20214024",
				Title:        "CVE-2021-4024",
				Description:  "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				Advisory: ovalmodels.Advisory{
					Cves: []ovalmodels.Cve{
						{
							CveID: "CVE-2021-4024",
							Href:  "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
						},
					},
				},
				References: []ovalmodels.Reference{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						RefURL: "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
			want: &models.CveContent{
				CveID:   "CVE-2021-4024",
				Title:   "CVE-2021-4024",
				Summary: "\n    A flaw was found in podman. The `podman machine` function (used to create and manage Podman virtual machine containing a Podman process) spawns a `gvproxy` process on the host system. The `gvproxy` API is accessible on port 7777 on all IP addresses on the host. If that port is open on the host's firewall, an attacker can potentially use the `gvproxy` API to forward ports on the host to ports in the VM, making private services on the VM accessible to the network. This issue could be also used to interrupt the host's services by forwarding all ports to the VM.\n    ",
				References: models.References{
					{
						Source: "CVE",
						RefID:  "Mitre CVE-2021-4024",
						Link:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4024",
					},
					{
						Source: "SUSE CVE",
						RefID:  "SUSE CVE-2021-4024",
						Link:   "https://www.suse.com/security/cve/CVE-2021-4024",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (SUSE{}).convertToModel(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SUSE.convertToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}
