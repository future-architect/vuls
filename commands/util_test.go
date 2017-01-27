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

package commands

import (
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
	"reflect"
)

func TestDiff(t *testing.T) {
	atCurrent, _ := time.Parse("2006-01-02", "2014-12-31")
	atPrevious, _ := time.Parse("2006-01-02", "2014-11-31")
	var tt = struct {
		inCurrent  models.ScanHistory
		inPrevious models.ScanHistory
		out        models.ScanResult
	}{
		models.ScanHistory{
			ScanResults: models.ScanResults{
				{
					ScannedAt:  atCurrent,
					Lang:       "",
					ServerName: "u16",
					Family:     "ubuntu",
					Release:    "16.04",
					Container: models.Container{
						ContainerID: "",
						Name:        "",
						Image:       "",
					},
					Platform: models.Platform{
						Name:       "other",
						InstanceID: "",
					},
					ScannedCves: []models.VulnInfo{
						{
							CveID: "CVE-2012-6702",
							Packages: models.PackageInfoList{
								{
									Name:       "libexpat1",
									Version:    "2.1.0-7",
									Release:    "",
									NewVersion: "2.1.0-7ubuntu0.16.04.2",
									NewRelease: "",
									Repository: "",
								},
							},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
						{
							CveID: "CVE-2014-9761",
							Packages: models.PackageInfoList{
								{
									Name:       "libc-bin",
									Version:    "2.21-0ubuntu5",
									Release:    "",
									NewVersion: "2.23-0ubuntu5",
									NewRelease: "",
									Repository: "",
								},
							},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
					},
					KnownCves:   []models.CveInfo{},
					UnknownCves: []models.CveInfo{},
					IgnoredCves: []models.CveInfo{},

					Packages: models.PackageInfoList{},

					Errors:   []string{},
					Optional: [][]interface{}{},
				},
			},
		},
		models.ScanHistory{
			ScanResults: models.ScanResults{
				{
					ScannedAt:  atPrevious,
					Lang:       "",
					ServerName: "u16",
					Family:     "ubuntu",
					Release:    "16.04",
					Container: models.Container{
						ContainerID: "",
						Name:        "",
						Image:       "",
					},
					Platform: models.Platform{
						Name:       "other",
						InstanceID: "",
					},
					ScannedCves: []models.VulnInfo{
						{
							CveID: "CVE-2012-6702",
							Packages: models.PackageInfoList{
								{
									Name:       "libexpat1",
									Version:    "2.1.0-7",
									Release:    "",
									NewVersion: "2.1.0-7ubuntu0.16.04.2",
									NewRelease: "",
									Repository: "",
								},
							},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
						{
							CveID: "CVE-2014-9761",
							Packages: models.PackageInfoList{
								{
									Name:       "libc-bin",
									Version:    "2.21-0ubuntu5",
									Release:    "",
									NewVersion: "2.23-0ubuntu5",
									NewRelease: "",
									Repository: "",
								},
							},
							DistroAdvisories: []models.DistroAdvisory{},
							CpeNames:         []string{},
						},
					},
					KnownCves:   []models.CveInfo{},
					UnknownCves: []models.CveInfo{},
					IgnoredCves: []models.CveInfo{},

					Packages: models.PackageInfoList{},

					Errors:   []string{},
					Optional: [][]interface{}{},
				},
			},
		},
		models.ScanResult{
			ScannedAt:  atCurrent,
			Lang:       "",
			ServerName: "u16",
			Family:     "ubuntu",
			Release:    "16.04",
			Container: models.Container{
				ContainerID: "",
				Name:        "",
				Image:       "",
			},
			Platform: models.Platform{
				Name:       "other",
				InstanceID: "",
			},
			ScannedCves: []models.VulnInfo{},
			KnownCves:   []models.CveInfo{},
			UnknownCves: []models.CveInfo{},
			IgnoredCves: []models.CveInfo{},

			Packages: models.PackageInfoList{},

			Errors:   []string{},
			Optional: [][]interface{}{},
		},
	}

	var s models.ScanHistory
	s, _ = diff(tt.inCurrent, tt.inPrevious)
	for _, actual := range s.ScanResults {
		if !reflect.DeepEqual(actual, tt.out) {
			h := pp.Sprint(actual)
			x := pp.Sprint(tt.out)
			t.Errorf("diff result : \n %s \n output result : \n %s", h, x)
		}
	}
}
