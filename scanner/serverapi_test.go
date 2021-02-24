package scanner

import (
	"net/http"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func TestViaHTTP(t *testing.T) {
	r := newRHEL(config.ServerInfo{})
	r.Distro = config.Distro{Family: constant.RedHat}

	var tests = []struct {
		header         map[string]string
		body           string
		packages       models.Packages
		expectedResult models.ScanResult
		wantErr        error
	}{
		{
			header: map[string]string{
				"X-Vuls-OS-Release":     "6.9",
				"X-Vuls-Kernel-Release": "2.6.32-695.20.3.el6.x86_64",
			},
			wantErr: errOSFamilyHeader,
		},
		{
			header: map[string]string{
				"X-Vuls-OS-Family":      "redhat",
				"X-Vuls-Kernel-Release": "2.6.32-695.20.3.el6.x86_64",
			},
			wantErr: errOSReleaseHeader,
		},
		{
			header: map[string]string{
				"X-Vuls-OS-Family":      "debian",
				"X-Vuls-OS-Release":     "8",
				"X-Vuls-Kernel-Release": "2.6.32-695.20.3.el6.x86_64",
			},
			wantErr: errKernelVersionHeader,
		},
		{
			header: map[string]string{
				"X-Vuls-OS-Family":      "centos",
				"X-Vuls-OS-Release":     "6.9",
				"X-Vuls-Kernel-Release": "2.6.32-695.20.3.el6.x86_64",
			},
			body: `openssl	0	1.0.1e	30.el6.11 x86_64
			Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x84_64
			kernel 0 2.6.32 696.20.1.el6 x86_64
			kernel 0 2.6.32 696.20.3.el6 x86_64
			kernel 0 2.6.32 695.20.3.el6 x86_64`,
			expectedResult: models.ScanResult{
				Family:  "centos",
				Release: "6.9",
				RunningKernel: models.Kernel{
					Release: "2.6.32-695.20.3.el6.x86_64",
				},
				Packages: models.Packages{
					"openssl": models.Package{
						Name:    "openssl",
						Version: "1.0.1e",
						Release: "30.el6.11",
					},
					"Percona-Server-shared-56": models.Package{
						Name:    "Percona-Server-shared-56",
						Version: "1:5.6.19",
						Release: "rel67.0.el6",
					},
					"kernel": models.Package{
						Name:    "kernel",
						Version: "2.6.32",
						Release: "695.20.3.el6",
					},
				},
			},
		},
		{
			header: map[string]string{
				"X-Vuls-OS-Family":      "debian",
				"X-Vuls-OS-Release":     "8.10",
				"X-Vuls-Kernel-Release": "3.16.0-4-amd64",
				"X-Vuls-Kernel-Version": "3.16.51-2",
			},
			body: "",
			expectedResult: models.ScanResult{
				Family:  "debian",
				Release: "8.10",
				RunningKernel: models.Kernel{
					Release: "3.16.0-4-amd64",
					Version: "3.16.51-2",
				},
			},
		},
	}

	for _, tt := range tests {
		header := http.Header{}
		for k, v := range tt.header {
			header.Set(k, v)
		}

		result, err := ViaHTTP(header, tt.body, false)
		if err != tt.wantErr {
			t.Errorf("error: expected %s, actual: %s", tt.wantErr, err)
		}

		if result.Family != tt.expectedResult.Family {
			t.Errorf("os family: expected %s, actual %s", tt.expectedResult.Family, result.Family)
		}
		if result.Release != tt.expectedResult.Release {
			t.Errorf("os release: expected %s, actual %s", tt.expectedResult.Release, result.Release)
		}
		if result.RunningKernel.Release != tt.expectedResult.RunningKernel.Release {
			t.Errorf("kernel release: expected %s, actual %s",
				tt.expectedResult.RunningKernel.Release, result.RunningKernel.Release)
		}
		if result.RunningKernel.Version != tt.expectedResult.RunningKernel.Version {
			t.Errorf("kernel version: expected %s, actual %s",
				tt.expectedResult.RunningKernel.Version, result.RunningKernel.Version)
		}

		for name, expectedPack := range tt.expectedResult.Packages {
			pack := result.Packages[name]
			if pack.Name != expectedPack.Name {
				t.Errorf("name: expected %s, actual %s", expectedPack.Name, pack.Name)
			}
			if pack.Version != expectedPack.Version {
				t.Errorf("version: expected %s, actual %s", expectedPack.Version, pack.Version)
			}
			if pack.Release != expectedPack.Release {
				t.Errorf("release: expected %s, actual %s", expectedPack.Release, pack.Release)
			}
		}
	}
}
