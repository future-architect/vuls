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
)

func TestToSortedSlice(t *testing.T) {
	var tests = []struct {
		in  VulnInfos
		out []VulnInfo
	}{
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 7.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 8.0,
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 7.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 8.0,
						},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
			},
		},
		// When max scores are the same, sort by CVE-ID
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss3Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
			},
		},
		// When there are no cvss scores, sort by severity
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "High",
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "Low",
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "High",
						},
					},
				},
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "Low",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.ToSortedSlice()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}
