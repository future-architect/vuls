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
	"fmt"
	"sort"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/jinzhu/gorm"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
)

// ScanHistory is the history of Scanning.
type ScanHistory struct {
	gorm.Model
	ScanResults ScanResults
	ScannedAt   time.Time
}

// ScanResults is slice of ScanResult.
type ScanResults []ScanResult

// Len implement Sort Interface
func (s ScanResults) Len() int {
	return len(s)
}

// Swap implement Sort Interface
func (s ScanResults) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less implement Sort Interface
func (s ScanResults) Less(i, j int) bool {
	if s[i].ServerName == s[j].ServerName {
		return s[i].Container.ContainerID < s[i].Container.ContainerID
	}
	return s[i].ServerName < s[j].ServerName
}

// FilterByCvssOver is filter function.
func (s ScanResults) FilterByCvssOver() (filtered ScanResults) {
	for _, result := range s {
		cveInfos := []CveInfo{}
		for _, cveInfo := range result.KnownCves {
			if config.Conf.CvssScoreOver < cveInfo.CveDetail.CvssScore(config.Conf.Lang) {
				cveInfos = append(cveInfos, cveInfo)
			}
		}
		result.KnownCves = cveInfos
		filtered = append(filtered, result)
	}
	return
}

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	gorm.Model    `json:"-"`
	ScanHistoryID uint `json:"-"`

	ServerName string // TOML Section key
	//  Hostname    string
	Family  string
	Release string

	Container Container

	Platform Platform

	//  Fqdn        string
	//  NWLinks     []NWLink
	KnownCves   []CveInfo
	UnknownCves []CveInfo

	Optional [][]interface{} `gorm:"-"`
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	hostinfo := ""
	if r.Container.ContainerID == "" {
		hostinfo = fmt.Sprintf(
			"%s (%s%s)",
			r.ServerName,
			r.Family,
			r.Release,
		)
	} else {
		hostinfo = fmt.Sprintf(
			"%s / %s (%s%s) on %s",
			r.Container.Name,
			r.Container.ContainerID,
			r.Family,
			r.Release,
			r.ServerName,
		)
	}
	return hostinfo
}

// ServerInfoTui returns server infromation for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	hostinfo := ""
	if r.Container.ContainerID == "" {
		hostinfo = fmt.Sprintf(
			"%s (%s%s)",
			r.ServerName,
			r.Family,
			r.Release,
		)
	} else {
		hostinfo = fmt.Sprintf(
			"|-- %s (%s%s)",
			r.Container.Name,
			r.Family,
			r.Release,
			//  r.Container.ContainerID,
		)
	}
	return hostinfo
}

// CveSummary summarize the number of CVEs group by CVSSv2 Severity
func (r ScanResult) CveSummary() string {
	var high, middle, low, unknown int
	cves := append(r.KnownCves, r.UnknownCves...)
	for _, cveInfo := range cves {
		score := cveInfo.CveDetail.CvssScore(config.Conf.Lang)
		switch {
		case 7.0 < score:
			high++
		case 4.0 < score:
			middle++
		case 0 < score:
			low++
		default:
			unknown++
		}
	}

	if config.Conf.IgnoreUnscoredCves {
		return fmt.Sprintf("Total: %d (High:%d Middle:%d Low:%d)",
			high+middle+low, high, middle, low)
	}
	return fmt.Sprintf("Total: %d (High:%d Middle:%d Low:%d ?:%d)",
		high+middle+low+unknown, high, middle, low, unknown)
}

// NWLink has network link information.
type NWLink struct {
	gorm.Model   `json:"-"`
	ScanResultID uint `json:"-"`

	IPAddress string
	Netmask   string
	DevName   string
	LinkState string
}

// CveInfos is for sorting
type CveInfos []CveInfo

func (c CveInfos) Len() int {
	return len(c)
}

func (c CveInfos) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c CveInfos) Less(i, j int) bool {
	lang := config.Conf.Lang
	if c[i].CveDetail.CvssScore(lang) == c[j].CveDetail.CvssScore(lang) {
		return c[i].CveDetail.CveID < c[j].CveDetail.CveID
	}
	return c[i].CveDetail.CvssScore(lang) > c[j].CveDetail.CvssScore(lang)
}

// CveInfo has Cve Information.
type CveInfo struct {
	gorm.Model   `json:"-"`
	ScanResultID uint `json:"-"`

	CveDetail        cve.CveDetail
	Packages         []PackageInfo
	DistroAdvisories []DistroAdvisory
	CpeNames         []CpeName
}

// CpeName has CPE name
type CpeName struct {
	gorm.Model `json:"-"`
	CveInfoID  uint `json:"-"`

	Name string
}

// PackageInfoList is slice of PackageInfo
type PackageInfoList []PackageInfo

// Exists returns true if exists the name
func (ps PackageInfoList) Exists(name string) bool {
	for _, p := range ps {
		if p.Name == name {
			return true
		}
	}
	return false
}

// UniqByName be uniq by name.
func (ps PackageInfoList) UniqByName() (distincted PackageInfoList) {
	set := make(map[string]PackageInfo)
	for _, p := range ps {
		set[p.Name] = p
	}
	//sort by key
	keys := []string{}
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		distincted = append(distincted, set[key])
	}
	return
}

// FindByName search PackageInfo by name
func (ps PackageInfoList) FindByName(name string) (result PackageInfo, found bool) {
	for _, p := range ps {
		if p.Name == name {
			return p, true
		}
	}
	return PackageInfo{}, false
}

// Find search PackageInfo by name-version-release
//  func (ps PackageInfoList) find(nameVersionRelease string) (PackageInfo, bool) {
//      for _, p := range ps {
//          joined := p.Name
//          if 0 < len(p.Version) {
//              joined = fmt.Sprintf("%s-%s", joined, p.Version)
//          }
//          if 0 < len(p.Release) {
//              joined = fmt.Sprintf("%s-%s", joined, p.Release)
//          }
//          if joined == nameVersionRelease {
//              return p, true
//          }
//      }
//      return PackageInfo{}, false
//  }

// PackageInfo has installed packages.
type PackageInfo struct {
	gorm.Model `json:"-"`
	CveInfoID  uint `json:"-"`

	Name    string
	Version string
	Release string

	NewVersion string
	NewRelease string
}

// ToStringCurrentVersion returns package name-version-release
func (p PackageInfo) ToStringCurrentVersion() string {
	str := p.Name
	if 0 < len(p.Version) {
		str = fmt.Sprintf("%s-%s", str, p.Version)
	}
	if 0 < len(p.Release) {
		str = fmt.Sprintf("%s-%s", str, p.Release)
	}
	return str
}

// ToStringNewVersion returns package name-version-release
func (p PackageInfo) ToStringNewVersion() string {
	str := p.Name
	if 0 < len(p.NewVersion) {
		str = fmt.Sprintf("%s-%s", str, p.NewVersion)
	}
	if 0 < len(p.NewRelease) {
		str = fmt.Sprintf("%s-%s", str, p.NewRelease)
	}
	return str
}

// DistroAdvisory has Amazon Linux, RHEL, FreeBSD Security Advisory information.
type DistroAdvisory struct {
	gorm.Model `json:"-"`
	CveInfoID  uint `json:"-"`

	AdvisoryID string
	Severity   string
	Issued     time.Time
	Updated    time.Time
}

// Container has Container information
type Container struct {
	gorm.Model   `json:"-"`
	ScanResultID uint `json:"-"`

	ContainerID string
	Name        string
}

// Platform has platform information
type Platform struct {
	gorm.Model   `json:"-"`
	ScanResultID uint `json:"-"`

	Name       string // aws or azure or gcp or other...
	InstanceID string
}
