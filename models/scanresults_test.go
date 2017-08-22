/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package models

import (
	"reflect"
	"testing"
	"time"

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
									Type:         NVD,
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
									Type:         NVD,
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
									Type:         NVD,
									CveID:        "CVE-2017-0003",
									Cvss2Score:   6.9,
									LastModified: time.Time{},
								},
								CveContent{
									Type:         JVN,
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
								Type:         NVD,
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
								Type:         NVD,
								CveID:        "CVE-2017-0003",
								Cvss2Score:   6.9,
								LastModified: time.Time{},
							},
							CveContent{
								Type:         JVN,
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
									Type:         Ubuntu,
									CveID:        "CVE-2017-0001",
									Severity:     "HIGH",
									LastModified: time.Time{},
								},
							),
						},
						"CVE-2017-0002": {
							CveID: "CVE-2017-0002",
							CveContents: NewCveContents(
								CveContent{
									Type:         RedHat,
									CveID:        "CVE-2017-0002",
									Severity:     "CRITICAL",
									LastModified: time.Time{},
								},
							),
						},
						"CVE-2017-0003": {
							CveID: "CVE-2017-0003",
							CveContents: NewCveContents(
								CveContent{
									Type:         Oracle,
									CveID:        "CVE-2017-0003",
									Severity:     "IMPORTANT",
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
								Type:         Ubuntu,
								CveID:        "CVE-2017-0001",
								Severity:     "HIGH",
								LastModified: time.Time{},
							},
						),
					},
					"CVE-2017-0002": {
						CveID: "CVE-2017-0002",
						CveContents: NewCveContents(
							CveContent{
								Type:         RedHat,
								CveID:        "CVE-2017-0002",
								Severity:     "CRITICAL",
								LastModified: time.Time{},
							},
						),
					},
					"CVE-2017-0003": {
						CveID: "CVE-2017-0003",
						CveContents: NewCveContents(
							CveContent{
								Type:         Oracle,
								CveID:        "CVE-2017-0003",
								Severity:     "IMPORTANT",
								LastModified: time.Time{},
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
		actual := tt.in.rs.FilterIgnoreCves(tt.in.cves)
		for k := range tt.out.ScannedCves {
			if !reflect.DeepEqual(tt.out.ScannedCves[k], actual.ScannedCves[k]) {
				o := pp.Sprintf("%v", tt.out.ScannedCves[k])
				a := pp.Sprintf("%v", actual.ScannedCves[k])
				t.Errorf("[%s] expected: %v\n  actual: %v\n", k, o, a)
			}
		}
	}
}
