package models

import (
	"reflect"
	"testing"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/k0kubun/pp"
)

func TestFilterByCvssOver(t *testing.T) {
	type in struct {
		over float64
		rs   ScanResult
	}
	var tests = []struct {
		in  in
		out ScanResult
	}{
		{
			in: in{
				over: 7.0,
				rs: ScanResult{
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							CveContents: NewCveContents(
								CveContent{
									Type:         NvdXML,
									CveID:        "CVE-2017-0001",
									Cvss2Score:   7.1,
									LastModified: time.Time{},
								},
							),
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
							CveContents: NewCveContents(
								CveContent{
									Type:         NvdXML,
									CveID:        "CVE-2017-0002",
									Cvss2Score:   6.9,
									LastModified: time.Time{},
								},
							),
						},
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
							CveContents: NewCveContents(
								CveContent{
									Type:         NvdXML,
									CveID:        "CVE-2017-0003",
									Cvss2Score:   6.9,
									LastModified: time.Time{},
								},
								CveContent{
									Type:         Jvn,
									CveID:        "CVE-2017-0003",
									Cvss2Score:   7.2,
									LastModified: time.Time{},
								},
							),
						},
					},
				},
			},
			out: ScanResult{
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
						CveContents: NewCveContents(
							CveContent{
								Type:         NvdXML,
								CveID:        "CVE-2017-0001",
								Cvss2Score:   7.1,
								LastModified: time.Time{},
							},
						),
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
						CveContents: NewCveContents(
							CveContent{
								Type:         NvdXML,
								CveID:        "CVE-2017-0003",
								Cvss2Score:   6.9,
								LastModified: time.Time{},
							},
							CveContent{
								Type:         Jvn,
								CveID:        "CVE-2017-0003",
								Cvss2Score:   7.2,
								LastModified: time.Time{},
							},
						),
					},
				},
			},
		},
		// OVAL Severity
		{
			in: in{
				over: 7.0,
				rs: ScanResult{
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							CveContents: NewCveContents(
								CveContent{
									Type:          Ubuntu,
									CveID:         "CVE-2017-0001",
									Cvss2Severity: "HIGH",
									LastModified:  time.Time{},
								},
							),
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
							CveContents: NewCveContents(
								CveContent{
									Type:          RedHat,
									CveID:         "CVE-2017-0002",
									Cvss2Severity: "CRITICAL",
									LastModified:  time.Time{},
								},
							),
						},
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
							CveContents: NewCveContents(
								CveContent{
									Type:          Oracle,
									CveID:         "CVE-2017-0003",
									Cvss2Severity: "IMPORTANT",
									LastModified:  time.Time{},
								},
							),
						},
					},
				},
			},
			out: ScanResult{
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
						CveContents: NewCveContents(
							CveContent{
								Type:          Ubuntu,
								CveID:         "CVE-2017-0001",
								Cvss2Severity: "HIGH",
								LastModified:  time.Time{},
							},
						),
					},
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
						CveContents: NewCveContents(
							CveContent{
								Type:          RedHat,
								CveID:         "CVE-2017-0002",
								Cvss2Severity: "CRITICAL",
								LastModified:  time.Time{},
							},
						),
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
						CveContents: NewCveContents(
							CveContent{
								Type:          Oracle,
								CveID:         "CVE-2017-0003",
								Cvss2Severity: "IMPORTANT",
								LastModified:  time.Time{},
							},
						),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.rs.FilterByCvssOver(tt.in.over)
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}
func TestFilterIgnoreCveIDs(t *testing.T) {
	type in struct {
		cves []string
		rs   ScanResult
	}
	var tests = []struct {
		in  in
		out ScanResult
	}{
		{
			in: in{
				cves: []string{"CVE-2017-0002"},
				rs: ScanResult{
					ServerName: "name",
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
						},
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		config.Conf.Servers = map[string]config.ServerInfo{
			"name": {IgnoreCves: tt.in.cves},
		}
		actual := tt.in.rs.FilterIgnoreCves()
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
		for k := range actual.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}

func TestFilterIgnoreCveIDsContainer(t *testing.T) {
	type in struct {
		cves []string
		rs   ScanResult
	}
	var tests = []struct {
		in  in
		out ScanResult
	}{
		{
			in: in{
				cves: []string{"CVE-2017-0002"},
				rs: ScanResult{
					ServerName: "name",
					Container:  Container{Name: "dockerA"},
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
						},
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				Container:  Container{Name: "dockerA"},
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		config.Conf.Servers = map[string]config.ServerInfo{
			"name": {
				Containers: map[string]config.ContainerSetting{
					"dockerA": {
						IgnoreCves: tt.in.cves,
					},
				},
			},
		}
		actual := tt.in.rs.FilterIgnoreCves()
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
		for k := range actual.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}

func TestFilterUnfixed(t *testing.T) {
	var tests = []struct {
		in  ScanResult
		out ScanResult
	}{
		{
			in: ScanResult{
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
						AffectedPackages: PackageFixStatuses{
							{
								Name:        "a",
								NotFixedYet: true,
							},
						},
					},
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
						AffectedPackages: PackageFixStatuses{
							{
								Name:        "b",
								NotFixedYet: false,
							},
						},
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
						AffectedPackages: PackageFixStatuses{
							{
								Name:        "c",
								NotFixedYet: true,
							},
							{
								Name:        "d",
								NotFixedYet: false,
							},
						},
					},
				},
			},
			out: ScanResult{
				ScannedCves: VulnInfos{
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
						AffectedPackages: PackageFixStatuses{
							{
								Name:        "b",
								NotFixedYet: false,
							},
						},
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
						AffectedPackages: PackageFixStatuses{
							{
								Name:        "c",
								NotFixedYet: true,
							},
							{
								Name:        "d",
								NotFixedYet: false,
							},
						},
					},
				},
			},
		},
	}
	for i, tt := range tests {
		config.Conf.IgnoreUnfixed = true
		actual := tt.in.FilterUnfixed()
		if !reflect.DeepEqual(tt.out.ScannedCves, actual.ScannedCves) {
			o := pp.Sprintf("%v", tt.out.ScannedCves)
			a := pp.Sprintf("%v", actual.ScannedCves)
			t.Errorf("[%d] expected: %v\n  actual: %v\n", i, o, a)
		}
	}
}

func TestFilterIgnorePkgs(t *testing.T) {
	type in struct {
		ignorePkgsRegexp []string
		rs               ScanResult
	}
	var tests = []struct {
		in  in
		out ScanResult
	}{
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel"},
				rs: ScanResult{
					ServerName: "name",
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
							},
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				ScannedCves: VulnInfos{
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
					},
				},
			},
		},
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel"},
				rs: ScanResult{
					ServerName: "name",
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
								{Name: "vim"},
							},
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
						AffectedPackages: PackageFixStatuses{
							{Name: "kernel"},
							{Name: "vim"},
						},
					},
				},
			},
		},
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel", "^vim", "^bind"},
				rs: ScanResult{
					ServerName: "name",
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
								{Name: "vim"},
							},
						},
					},
				},
			},
			out: ScanResult{
				ServerName:  "name",
				ScannedCves: VulnInfos{},
			},
		},
	}
	for _, tt := range tests {
		config.Conf.Servers = map[string]config.ServerInfo{
			"name": {IgnorePkgsRegexp: tt.in.ignorePkgsRegexp},
		}
		actual := tt.in.rs.FilterIgnorePkgs()
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
		for k := range actual.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}

func TestFilterIgnorePkgsContainer(t *testing.T) {
	type in struct {
		ignorePkgsRegexp []string
		rs               ScanResult
	}
	var tests = []struct {
		in  in
		out ScanResult
	}{
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel"},
				rs: ScanResult{
					ServerName: "name",
					Container:  Container{Name: "dockerA"},
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
							},
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				Container:  Container{Name: "dockerA"},
				ScannedCves: VulnInfos{
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
					},
				},
			},
		},
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel"},
				rs: ScanResult{
					ServerName: "name",
					Container:  Container{Name: "dockerA"},
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
								{Name: "vim"},
							},
						},
					},
				},
			},
			out: ScanResult{
				ServerName: "name",
				Container:  Container{Name: "dockerA"},
				ScannedCves: VulnInfos{
					"CVE-2017-0001": {
						CveID: "CVE-2017-0001",
						AffectedPackages: PackageFixStatuses{
							{Name: "kernel"},
							{Name: "vim"},
						},
					},
				},
			},
		},
		{
			in: in{
				ignorePkgsRegexp: []string{"^kernel", "^vim", "^bind"},
				rs: ScanResult{
					ServerName: "name",
					Container:  Container{Name: "dockerA"},
					ScannedCves: VulnInfos{
						"CVE-2017-0001": {
							CveID: "CVE-2017-0001",
							AffectedPackages: PackageFixStatuses{
								{Name: "kernel"},
								{Name: "vim"},
							},
						},
					},
				},
			},
			out: ScanResult{
				ServerName:  "name",
				Container:   Container{Name: "dockerA"},
				ScannedCves: VulnInfos{},
			},
		},
	}
	for _, tt := range tests {
		config.Conf.Servers = map[string]config.ServerInfo{
			"name": {
				Containers: map[string]config.ContainerSetting{
					"dockerA": {
						IgnorePkgsRegexp: tt.in.ignorePkgsRegexp,
					},
				},
			},
		}
		actual := tt.in.rs.FilterIgnorePkgs()
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
		for k := range actual.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}

func TestIsDisplayUpdatableNum(t *testing.T) {
	var tests = []struct {
		mode     []byte
		family   string
		expected bool
	}{
		{
			mode:     []byte{config.Offline},
			expected: false,
		},
		{
			mode:     []byte{config.FastRoot},
			expected: true,
		},
		{
			mode:     []byte{config.Deep},
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.RedHat,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Oracle,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Debian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Ubuntu,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Raspbian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.CentOS,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Amazon,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.FreeBSD,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.OpenSUSE,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   config.Alpine,
			expected: true,
		},
	}

	for i, tt := range tests {
		mode := config.ScanMode{}
		for _, m := range tt.mode {
			mode.Set(m)
		}
		config.Conf.Servers = map[string]config.ServerInfo{
			"name": {Mode: mode},
		}
		r := ScanResult{
			ServerName: "name",
			Family:     tt.family,
		}
		act := r.isDisplayUpdatableNum()
		if tt.expected != act {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.expected, act)
		}
	}
}
