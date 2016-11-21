package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
	"reflect"
	"testing"
)

func TestPackageCveInfosSetGet(t *testing.T) {
	var test = struct {
		in  []string
		out []string
	}{
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
			"CVE1",
			"CVE1",
			"CVE2",
			"CVE3",
		},
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
		},
	}

	//  var ps packageCveInfos
	var ps CvePacksList
	for _, cid := range test.in {
		ps = ps.set(cid, CvePacksInfo{CveID: cid})
	}

	if len(test.out) != len(ps) {
		t.Errorf("length: expected %d, actual %d", len(test.out), len(ps))
	}

	for i, expectedCid := range test.out {
		if expectedCid != ps[i].CveID {
			t.Errorf("expected %s, actual %s", expectedCid, ps[i].CveID)
		}
	}
	for _, cid := range test.in {
		p, _ := ps.FindByCveID(cid)
		if p.CveID != cid {
			t.Errorf("expected %s, actual %s", cid, p.CveID)
		}
	}
}

func TestGetScanResults(t *testing.T) {
	// setup servers
	c := config.ServerInfo{
		ServerName: "ubuntu",
	}
	deb1 := newDebian(c)
	deb2 := newDebian(c)

	cpis1 := []CvePacksInfo{
		{
			CveID:     "CVE1",
			CveDetail: cve.CveDetail{CveID: "CVE1"},
			Packs: []models.PackageInfo{
				{Name: "mysql-client-5.5"},
				{Name: "mysql-server-5.5"},
				{Name: "mysql-common-5.5"},
			},
		},
		{
			CveID:     "CVE2",
			CveDetail: cve.CveDetail{CveID: "CVE2"},
			Packs: []models.PackageInfo{
				{Name: "mysql-common-5.5"},
				{Name: "mysql-server-5.5"},
				{Name: "mysql-client-5.5"},
			},
		},
	}
	cpis2 := []CvePacksInfo{
		{
			CveID:     "CVE3",
			CveDetail: cve.CveDetail{CveID: "CVE3"},
			Packs: []models.PackageInfo{
				{Name: "libcurl3"},
				{Name: "curl"},
			},
		},
		{
			CveID:     "CVE4",
			CveDetail: cve.CveDetail{CveID: "CVE4"},
			Packs: []models.PackageInfo{
				{Name: "bind9"},
				{Name: "libdns100"},
			},
		},
	}
	deb1.setUnsecurePackages(cpis1)
	servers = append(servers, deb1)

	deb2.setUnsecurePackages(cpis2)
	servers = append(servers, deb2)

	// prepare expected data
	expectedUnKnownPackages := []map[string][]models.PackageInfo{
		{
			"CVE1": {
				{Name: "mysql-client-5.5"},
				{Name: "mysql-common-5.5"},
				{Name: "mysql-server-5.5"},
			},
		},
		{
			"CVE2": {
				{Name: "mysql-client-5.5"},
				{Name: "mysql-common-5.5"},
				{Name: "mysql-server-5.5"},
			},
		},
		{
			"CVE3": {
				{Name: "curl"},
				{Name: "libcurl3"},
			},
		},
		{
			"CVE4": {
				{Name: "bind9"},
				{Name: "libdns100"},
			},
		},
	}

	// check scanResults
	scanResults, _ := GetScanResults()
	if len(scanResults) != 2 {
		t.Errorf("length of scanResults should be 2")
	}
	for i, result := range scanResults {
		if result.ServerName != "ubuntu" {
			t.Errorf("expected ubuntu, actual %s", result.ServerName)
		}

		unKnownCves := result.UnknownCves
		if len(unKnownCves) != 2 {
			t.Errorf("length of unKnownCves should be 2")
		}
		for j, unKnownCve := range unKnownCves {
			expected := expectedUnKnownPackages[i*2+j][unKnownCve.CveDetail.CveID]
			if !reflect.DeepEqual(expected, unKnownCve.Packages) {
				t.Errorf("expected %v, actual %v", expected, unKnownCve.Packages)
			}
		}
	}
}
