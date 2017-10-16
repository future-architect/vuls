/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

func TestIsRunningKernelSUSE(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: config.SUSEEnterpriseServer}

	kernel := models.Kernel{
		Release: "4.4.74-92.35-default",
		Version: "",
	}

	var tests = []struct {
		pack     models.Package
		family   string
		kernel   models.Kernel
		expected bool
	}{
		{
			pack: models.Package{
				Name:    "kernel-default",
				Version: "4.4.74",
				Release: "92.35.1",
				Arch:    "x86_64",
			},
			family:   config.SUSEEnterpriseServer,
			kernel:   kernel,
			expected: true,
		},
		{
			pack: models.Package{
				Name:    "kernel-default",
				Version: "4.4.59",
				Release: "92.20.2",
				Arch:    "x86_64",
			},
			family:   config.SUSEEnterpriseServer,
			kernel:   kernel,
			expected: false,
		},
	}

	for i, tt := range tests {
		_, actual := isRunningKernel(tt.pack, tt.family, tt.kernel)
		if tt.expected != actual {
			t.Errorf("[%d] expected %t, actual %t", i, tt.expected, actual)
		}
	}
}

func TestIsRunningKernelRedHatLikeLinux(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: config.Amazon}

	kernel := models.Kernel{
		Release: "4.9.43-17.38.amzn1.x86_64",
		Version: "",
	}

	var tests = []struct {
		pack     models.Package
		family   string
		kernel   models.Kernel
		expected bool
	}{
		{
			pack: models.Package{
				Name:    "kernel",
				Version: "4.9.43",
				Release: "17.38.amzn1",
				Arch:    "x86_64",
			},
			family:   config.Amazon,
			kernel:   kernel,
			expected: true,
		},
		{
			pack: models.Package{
				Name:    "kernel",
				Version: "4.9.38",
				Release: "16.35.amzn1",
				Arch:    "x86_64",
			},
			family:   config.Amazon,
			kernel:   kernel,
			expected: false,
		},
	}

	for i, tt := range tests {
		_, actual := isRunningKernel(tt.pack, tt.family, tt.kernel)
		if tt.expected != actual {
			t.Errorf("[%d] expected %t, actual %t", i, tt.expected, actual)
		}
	}
}
