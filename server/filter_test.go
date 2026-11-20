package server

import (
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// TestVulsHandler_filterScanResult_IgnoreCves reproduces
// https://github.com/future-architect/vuls/issues/1267: server mode
// (VulsHandler.ServeHTTP, via filterScanResult) must apply the same
// ignoreCves/ignorePkgsRegexp policy as scan/report mode
// (detector.DetectVulnInfos), instead of silently returning ignored CVEs.
func TestVulsHandler_filterScanResult_IgnoreCves(t *testing.T) {
	orig := config.Conf.Servers
	defer func() { config.Conf.Servers = orig }()

	config.Conf.Servers = map[string]config.ServerInfo{
		"testsrv": {IgnoreCves: []string{"CVE-2021-1111"}},
	}

	r := models.ScanResult{
		ServerName: "testsrv",
		ScannedCves: models.VulnInfos{
			"CVE-2021-1111": models.VulnInfo{CveID: "CVE-2021-1111"},
			"CVE-2021-2222": models.VulnInfo{CveID: "CVE-2021-2222"},
		},
	}

	h := VulsHandler{}
	h.filterScanResult(&r)

	if _, ok := r.ScannedCves["CVE-2021-1111"]; ok {
		t.Errorf("ignoreCves=[CVE-2021-1111] is configured for server %q, but server mode did not filter it out; ScannedCves=%v", r.ServerName, r.ScannedCves)
	}
	if _, ok := r.ScannedCves["CVE-2021-2222"]; !ok {
		t.Errorf("CVE-2021-2222 is not in ignoreCves and should have been kept; ScannedCves=%v", r.ScannedCves)
	}
}

// TestVulsHandler_filterScanResult_IgnorePkgsRegexp is the same reproduction
// for the ignorePkgsRegexp half of the same config block.
func TestVulsHandler_filterScanResult_IgnorePkgsRegexp(t *testing.T) {
	orig := config.Conf.Servers
	defer func() { config.Conf.Servers = orig }()

	config.Conf.Servers = map[string]config.ServerInfo{
		"testsrv": {IgnorePkgsRegexp: []string{"^libfoo"}},
	}

	r := models.ScanResult{
		ServerName: "testsrv",
		ScannedCves: models.VulnInfos{
			"CVE-2021-3333": models.VulnInfo{
				CveID: "CVE-2021-3333",
				AffectedPackages: models.PackageFixStatuses{
					{Name: "libfoo-dev"},
				},
			},
			"CVE-2021-4444": models.VulnInfo{
				CveID: "CVE-2021-4444",
				AffectedPackages: models.PackageFixStatuses{
					{Name: "bash"},
				},
			},
		},
	}

	h := VulsHandler{}
	h.filterScanResult(&r)

	if _, ok := r.ScannedCves["CVE-2021-3333"]; ok {
		t.Errorf("ignorePkgsRegexp=[^libfoo] is configured for server %q, but server mode did not filter out the libfoo-dev finding; ScannedCves=%v", r.ServerName, r.ScannedCves)
	}
	if _, ok := r.ScannedCves["CVE-2021-4444"]; !ok {
		t.Errorf("CVE-2021-4444 (bash) does not match ignorePkgsRegexp and should have been kept; ScannedCves=%v", r.ScannedCves)
	}
}
