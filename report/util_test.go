package report

import (
	"reflect"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestIsCveInfoUpdated(t *testing.T) {
	f := "2006-01-02"
	old, _ := time.Parse(f, "2015-12-15")
	new, _ := time.Parse(f, "2015-12-16")

	type In struct {
		cveID string
		cur   models.ScanResult
		prev  models.ScanResult
	}
	var tests = []struct {
		in       In
		expected bool
	}{
		// NVD compare non-initialized times
		{
			in: In{
				cveID: "CVE-2017-0001",
				cur: models.ScanResult{
					ScannedCves: models.VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0001",
									LastModified: time.Time{},
								},
							),
						},
					},
				},
				prev: models.ScanResult{
					ScannedCves: models.VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0001",
									LastModified: time.Time{},
								},
							),
						},
					},
				},
			},
			expected: false,
		},
		// JVN not updated
		{
			in: In{
				cveID: "CVE-2017-0002",
				cur: models.ScanResult{
					ScannedCves: models.VulnInfos{
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0002",
									LastModified: old,
								},
							),
						},
					},
				},
				prev: models.ScanResult{
					ScannedCves: models.VulnInfos{
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0002",
									LastModified: old,
								},
							),
						},
					},
				},
			},
			expected: false,
		},
		// OVAL updated
		{
			in: In{
				cveID: "CVE-2017-0003",
				cur: models.ScanResult{
					Family: "ubuntu",
					ScannedCves: models.VulnInfos{
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0002",
									LastModified: new,
								},
							),
						},
					},
				},
				prev: models.ScanResult{
					Family: "ubuntu",
					ScannedCves: models.VulnInfos{
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0002",
									LastModified: old,
								},
							),
						},
					},
				},
			},
			expected: true,
		},
		// OVAL newly detected
		{
			in: In{
				cveID: "CVE-2017-0004",
				cur: models.ScanResult{
					Family: "redhat",
					ScannedCves: models.VulnInfos{
						"CVE-2017-0004": {
							CveID: "CVE-2017-0004",
							CveContents: models.NewCveContents(
								models.CveContent{
									Type:         models.NVD,
									CveID:        "CVE-2017-0002",
									LastModified: old,
								},
							),
						},
					},
				},
				prev: models.ScanResult{
					Family:      "redhat",
					ScannedCves: models.VulnInfos{},
				},
			},
			expected: true,
		},
	}
	for i, tt := range tests {
		actual := isCveInfoUpdated(tt.in.cveID, tt.in.prev, tt.in.cur)
		if actual != tt.expected {
			t.Errorf("[%d] actual: %t, expected: %t", i, actual, tt.expected)
		}
	}
}

func TestDiff(t *testing.T) {
	atCurrent, _ := time.Parse("2006-01-02", "2014-12-31")
	atPrevious, _ := time.Parse("2006-01-02", "2014-11-31")
	var tests = []struct {
		inCurrent  models.ScanResults
		inPrevious models.ScanResults
		out        models.ScanResult
	}{
		{
			inCurrent: models.ScanResults{
				{
					ScannedAt:  atCurrent,
					ServerName: "u16",
					Family:     "ubuntu",
					Release:    "16.04",
					ScannedCves: models.VulnInfos{
						"CVE-2012-6702": {
							CveID:            "CVE-2012-6702",
							AffectedPackages: models.PackageStatuses{{Name: "libexpat1"}},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
						"CVE-2014-9761": {
							CveID:            "CVE-2014-9761",
							AffectedPackages: models.PackageStatuses{{Name: "libc-bin"}},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
					},
					Packages: models.Packages{},
					Errors:   []string{},
					Optional: [][]interface{}{},
				},
			},
			inPrevious: models.ScanResults{
				{
					ScannedAt:  atPrevious,
					ServerName: "u16",
					Family:     "ubuntu",
					Release:    "16.04",
					ScannedCves: models.VulnInfos{
						"CVE-2012-6702": {
							CveID:            "CVE-2012-6702",
							AffectedPackages: models.PackageStatuses{{Name: "libexpat1"}},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
						"CVE-2014-9761": {
							CveID:            "CVE-2014-9761",
							AffectedPackages: models.PackageStatuses{{Name: "libc-bin"}},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
					},
					Packages: models.Packages{},
					Errors:   []string{},
					Optional: [][]interface{}{},
				},
			},
			out: models.ScanResult{
				ScannedAt:   atCurrent,
				ServerName:  "u16",
				Family:      "ubuntu",
				Release:     "16.04",
				Packages:    models.Packages{},
				ScannedCves: models.VulnInfos{},
				Errors:      []string{},
				Optional:    [][]interface{}{},
			},
		},
		{
			inCurrent: models.ScanResults{
				{
					ScannedAt:  atCurrent,
					ServerName: "u16",
					Family:     "ubuntu",
					Release:    "16.04",
					ScannedCves: models.VulnInfos{
						"CVE-2016-6662": {
							CveID:            "CVE-2016-6662",
							AffectedPackages: models.PackageStatuses{{Name: "mysql-libs"}},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
					},
					Packages: models.Packages{
						"mysql-libs": {
							Name:       "mysql-libs",
							Version:    "5.1.73",
							Release:    "7.el6",
							NewVersion: "5.1.73",
							NewRelease: "8.el6_8",
							Repository: "",
							Changelog: models.Changelog{
								Contents: "",
								Method:   "",
							},
						},
					},
				},
			},
			inPrevious: models.ScanResults{
				{
					ScannedAt:   atPrevious,
					ServerName:  "u16",
					Family:      "ubuntu",
					Release:     "16.04",
					ScannedCves: models.VulnInfos{},
				},
			},
			out: models.ScanResult{
				ScannedAt:  atCurrent,
				ServerName: "u16",
				Family:     "ubuntu",
				Release:    "16.04",
				ScannedCves: models.VulnInfos{
					"CVE-2016-6662": {
						CveID:            "CVE-2016-6662",
						AffectedPackages: models.PackageStatuses{{Name: "mysql-libs"}},
						DistroAdvisories: []models.DistroAdvisory{},
						CpeNames:         []string{},
					},
				},
				Packages: models.Packages{
					"mysql-libs": {
						Name:       "mysql-libs",
						Version:    "5.1.73",
						Release:    "7.el6",
						NewVersion: "5.1.73",
						NewRelease: "8.el6_8",
						Repository: "",
						Changelog: models.Changelog{
							Contents: "",
							Method:   "",
						},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		diff, _ := diff(tt.inCurrent, tt.inPrevious)
		for _, actual := range diff {
			if !reflect.DeepEqual(actual.ScannedCves, tt.out.ScannedCves) {
				h := pp.Sprint(actual.ScannedCves)
				x := pp.Sprint(tt.out.ScannedCves)
				t.Errorf("[%d] cves actual: \n %s \n expected: \n %s", i, h, x)
			}

			for j := range tt.out.Packages {
				if !reflect.DeepEqual(tt.out.Packages[j], actual.Packages[j]) {
					h := pp.Sprint(tt.out.Packages[j])
					x := pp.Sprint(actual.Packages[j])
					t.Errorf("[%d] packages actual: \n %s \n expected: \n %s", i, x, h)
				}
			}
		}
	}
}
