package scanner

import (
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func TestIsRunningKernelSUSE(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: constant.SUSEEnterpriseServer}

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
			family:   constant.SUSEEnterpriseServer,
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
			family:   constant.SUSEEnterpriseServer,
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
	r := newAmazon(config.ServerInfo{})
	r.Distro = config.Distro{Family: constant.Amazon}

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
			family:   constant.Amazon,
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
			family:   constant.Amazon,
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
