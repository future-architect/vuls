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
	"github.com/future-architect/vuls/cveapi"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
	goval "github.com/kotakanbe/goval-dictionary/models"
)

// ScanHistory is the history of Scanning.
type ScanHistory struct {
	ScanResults ScanResults
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

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	ScannedAt time.Time

	Lang       string
	ServerName string // TOML Section key
	Family     string
	Release    string
	Container  Container
	Platform   Platform

	// Scanned Vulns via SSH + CPE Vulns
	ScannedCves []VulnInfo

	KnownCves   CveInfos
	UnknownCves CveInfos
	IgnoredCves CveInfos

	Packages PackageInfoList

	Errors   []string
	Optional [][]interface{}
}

// FillCveDetail fetches CVE detailed information from
// CVE Database, and then set to fields.
func (r ScanResult) FillCveDetail() (*ScanResult, error) {
	set := map[string]VulnInfo{}
	var cveIDs []string
	for _, v := range r.ScannedCves {
		set[v.CveID] = v
		cveIDs = append(cveIDs, v.CveID)
	}

	ds, err := cveapi.CveClient.FetchCveDetails(cveIDs)
	if err != nil {
		return nil, err
	}

	r.IgnoredCves = CveInfos{}
	for _, d := range ds {
		cinfo := CveInfo{
			CveDetail: d,
			VulnInfo:  set[d.CveID],
		}
		cinfo.NilSliceToEmpty()

		// ignored
		found := false
		for _, icve := range config.Conf.Servers[r.ServerName].IgnoreCves {
			if icve == d.CveID {
				r.IgnoredCves.Insert(cinfo)
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Update known if KnownCves already have cinfo
		if c, ok := r.KnownCves.Get(cinfo.CveID); ok {
			c.CveDetail = d
			r.KnownCves.Update(c)
			continue
		}

		// Update unknown if UnknownCves already have cinfo
		if c, ok := r.UnknownCves.Get(cinfo.CveID); ok {
			c.CveDetail = d
			r.UnknownCves.Update(c)
			continue
		}

		// unknown
		if d.CvssScore(config.Conf.Lang) <= 0 {
			r.UnknownCves.Insert(cinfo)
			continue
		}

		// known
		r.KnownCves.Insert(cinfo)
	}
	sort.Sort(r.KnownCves)
	sort.Sort(r.UnknownCves)
	sort.Sort(r.IgnoredCves)
	return &r, nil
}

// FilterByCvssOver is filter function.
func (r ScanResult) FilterByCvssOver() ScanResult {
	cveInfos := []CveInfo{}
	// TODO: Set correct default value
	if config.Conf.CvssScoreOver == 0 {
		config.Conf.CvssScoreOver = -1.1
	}

	for _, cveInfo := range r.KnownCves {
		if config.Conf.CvssScoreOver <= cveInfo.CveDetail.CvssScore(config.Conf.Lang) {
			cveInfos = append(cveInfos, cveInfo)
		}
	}
	r.KnownCves = cveInfos
	return r
}

// ReportFileName returns the filename on localhost without extention
func (r ScanResult) ReportFileName() (name string) {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s", r.ServerName)
	}
	return fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
}

// ReportKeyName returns the name of key on S3, Azure-Blob without extention
func (r ScanResult) ReportKeyName() (name string) {
	timestr := r.ScannedAt.Format(time.RFC3339)
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s", timestr, r.ServerName)
	}
	return fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"%s / %s (%s%s) on %s",
		r.Container.Name,
		r.Container.ContainerID,
		r.Family,
		r.Release,
		r.ServerName,
	)
}

// ServerInfoTui returns server infromation for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"|-- %s (%s%s)",
		r.Container.Name,
		r.Family,
		r.Release,
		//  r.Container.ContainerID,
	)
}

// FormatServerName returns server and container name
func (r ScanResult) FormatServerName() string {
	if len(r.Container.ContainerID) == 0 {
		return r.ServerName
	}
	return fmt.Sprintf("%s@%s",
		r.Container.Name, r.ServerName)
}

// CveSummary summarize the number of CVEs group by CVSSv2 Severity
func (r ScanResult) CveSummary() string {
	var high, medium, low, unknown int
	cves := append(r.KnownCves, r.UnknownCves...)
	for _, cveInfo := range cves {
		score := cveInfo.CveDetail.CvssScore(config.Conf.Lang)
		switch {
		case 7.0 <= score:
			high++
		case 4.0 <= score:
			medium++
		case 0 < score:
			low++
		default:
			unknown++
		}
	}

	if config.Conf.IgnoreUnscoredCves {
		return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			high+medium+low, high, medium, low)
	}
	return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
		high+medium+low+unknown, high, medium, low, unknown)
}

// AllCves returns Known and Unknown CVEs
func (r ScanResult) AllCves() []CveInfo {
	return append(r.KnownCves, r.UnknownCves...)
}

// NWLink has network link information.
type NWLink struct {
	IPAddress string
	Netmask   string
	DevName   string
	LinkState string
}

// Confidence is a ranking how confident the CVE-ID was deteted correctly
// Score: 0 - 100
type Confidence struct {
	Score           int
	DetectionMethod string
}

func (c Confidence) String() string {
	return fmt.Sprintf("%d / %s", c.Score, c.DetectionMethod)
}

const (
	// CpeNameMatchStr is a String representation of CpeNameMatch
	CpeNameMatchStr = "CpeNameMatch"

	// YumUpdateSecurityMatchStr is a String representation of YumUpdateSecurityMatch
	YumUpdateSecurityMatchStr = "YumUpdateSecurityMatch"

	// PkgAuditMatchStr is a String representation of PkgAuditMatch
	PkgAuditMatchStr = "PkgAuditMatch"

	// OvalMatchStr is a String representation of OvalMatch
	OvalMatchStr = "OvalMatch"

	// ChangelogExactMatchStr is a String representation of ChangelogExactMatch
	ChangelogExactMatchStr = "ChangelogExactMatch"

	// ChangelogLenientMatchStr is a String representation of ChangelogLenientMatch
	ChangelogLenientMatchStr = "ChangelogLenientMatch"

	// FailedToGetChangelog is a String representation of FailedToGetChangelog
	FailedToGetChangelog = "FailedToGetChangelog"

	// FailedToFindVersionInChangelog is a String representation of FailedToFindVersionInChangelog
	FailedToFindVersionInChangelog = "FailedToFindVersionInChangelog"
)

// CpeNameMatch is a ranking how confident the CVE-ID was deteted correctly
var CpeNameMatch = Confidence{100, CpeNameMatchStr}

// YumUpdateSecurityMatch is a ranking how confident the CVE-ID was deteted correctly
var YumUpdateSecurityMatch = Confidence{100, YumUpdateSecurityMatchStr}

// PkgAuditMatch is a ranking how confident the CVE-ID was deteted correctly
var PkgAuditMatch = Confidence{100, PkgAuditMatchStr}

// OvalMatch is a ranking how confident the CVE-ID was deteted correctly
var OvalMatch = Confidence{100, OvalMatchStr}

// ChangelogExactMatch is a ranking how confident the CVE-ID was deteted correctly
var ChangelogExactMatch = Confidence{95, ChangelogExactMatchStr}

// ChangelogLenientMatch is a ranking how confident the CVE-ID was deteted correctly
var ChangelogLenientMatch = Confidence{50, ChangelogLenientMatchStr}

// VulnInfos is VulnInfo list, getter/setter, sortable methods.
type VulnInfos []VulnInfo

// VulnInfo holds a vulnerability information and unsecure packages
type VulnInfo struct {
	CveID            string
	Confidence       Confidence
	Packages         PackageInfoList
	DistroAdvisories []DistroAdvisory // for Aamazon, RHEL, FreeBSD
	CpeNames         []string
}

// NilSliceToEmpty set nil slice fields to empty slice to avoid null in JSON
func (v *VulnInfo) NilSliceToEmpty() {
	if v.CpeNames == nil {
		v.CpeNames = []string{}
	}
	if v.DistroAdvisories == nil {
		v.DistroAdvisories = []DistroAdvisory{}
	}
	if v.Packages == nil {
		v.Packages = PackageInfoList{}
	}
}

// FindByCveID find by CVEID
func (s VulnInfos) FindByCveID(cveID string) (VulnInfo, bool) {
	for _, p := range s {
		if cveID == p.CveID {
			return p, true
		}
	}
	return VulnInfo{CveID: cveID}, false
}

// immutable
func (s VulnInfos) set(cveID string, v VulnInfo) VulnInfos {
	for i, p := range s {
		if cveID == p.CveID {
			s[i] = v
			return s
		}
	}
	return append(s, v)
}

// Len implement Sort Interface
func (s VulnInfos) Len() int {
	return len(s)
}

// Swap implement Sort Interface
func (s VulnInfos) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less implement Sort Interface
func (s VulnInfos) Less(i, j int) bool {
	return s[i].CveID < s[j].CveID
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
	return c[j].CveDetail.CvssScore(lang) < c[i].CveDetail.CvssScore(lang)
}

// Get cveInfo by cveID
func (c CveInfos) Get(cveID string) (CveInfo, bool) {
	for _, cve := range c {
		if cve.VulnInfo.CveID == cveID {
			return cve, true
		}
	}
	return CveInfo{}, false
}

// Delete by cveID
func (c *CveInfos) Delete(cveID string) {
	cveInfos := *c
	for i, cve := range cveInfos {
		if cve.VulnInfo.CveID == cveID {
			*c = append(cveInfos[:i], cveInfos[i+1:]...)
			break
		}
	}
}

// Insert cveInfo
func (c *CveInfos) Insert(cveInfo CveInfo) {
	*c = append(*c, cveInfo)
}

// Update cveInfo
func (c CveInfos) Update(cveInfo CveInfo) (ok bool) {
	for i, cve := range c {
		if cve.VulnInfo.CveID == cveInfo.VulnInfo.CveID {
			c[i] = cveInfo
			return true
		}
	}
	return false
}

// Upsert cveInfo
func (c *CveInfos) Upsert(cveInfo CveInfo) {
	ok := c.Update(cveInfo)
	if !ok {
		c.Insert(cveInfo)
	}
}

// CveInfo has Cve Information.
type CveInfo struct {
	CveDetail  cve.CveDetail
	OvalDetail goval.Definition
	VulnInfo
}

// NilSliceToEmpty set nil slice fields to empty slice to avoid null in JSON
func (c *CveInfo) NilSliceToEmpty() {
	if c.CveDetail.Nvd.Cpes == nil {
		c.CveDetail.Nvd.Cpes = []cve.Cpe{}
	}
	if c.CveDetail.Jvn.Cpes == nil {
		c.CveDetail.Jvn.Cpes = []cve.Cpe{}
	}
	if c.CveDetail.Nvd.References == nil {
		c.CveDetail.Nvd.References = []cve.Reference{}
	}
	if c.CveDetail.Jvn.References == nil {
		c.CveDetail.Jvn.References = []cve.Reference{}
	}
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

// MergeNewVersion merges candidate version information to the receiver struct
func (ps PackageInfoList) MergeNewVersion(as PackageInfoList) {
	for _, a := range as {
		for i, p := range ps {
			if p.Name == a.Name {
				ps[i].NewVersion = a.NewVersion
				ps[i].NewRelease = a.NewRelease
			}
		}
	}
}

func (ps PackageInfoList) countUpdatablePacks() int {
	count := 0
	set := make(map[string]bool)
	for _, p := range ps {
		if len(p.NewVersion) != 0 && !set[p.Name] {
			count++
			set[p.Name] = true
		}
	}
	return count
}

// FormatUpdatablePacksSummary returns a summary of updatable packages
func (ps PackageInfoList) FormatUpdatablePacksSummary() string {
	return fmt.Sprintf("%d updatable packages",
		ps.countUpdatablePacks())
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

// PackageInfosByName implements sort.Interface for []PackageInfo based on
// the Name field.
type PackageInfosByName []PackageInfo

func (a PackageInfosByName) Len() int           { return len(a) }
func (a PackageInfosByName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a PackageInfosByName) Less(i, j int) bool { return a[i].Name < a[j].Name }

// PackageInfo has installed packages.
type PackageInfo struct {
	Name       string
	Version    string
	Release    string
	NewVersion string
	NewRelease string
	Repository string
	Changelog  Changelog
}

// Changelog has contents of changelog and how to get it.
// Method: modesl.detectionMethodStr
type Changelog struct {
	Contents string
	Method   string
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
	AdvisoryID string
	Severity   string
	Issued     time.Time
	Updated    time.Time
}

// Container has Container information
type Container struct {
	ContainerID string
	Name        string
	Image       string
	Type        string
}

// Platform has platform information
type Platform struct {
	Name       string // aws or azure or gcp or other...
	InstanceID string
}
