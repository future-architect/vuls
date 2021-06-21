package models

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/logging"
)

// ScanResults is a slide of ScanResult
type ScanResults []ScanResult

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	JSONVersion      int               `json:"jsonVersion"`
	Lang             string            `json:"lang"`
	ServerUUID       string            `json:"serverUUID"`
	ServerName       string            `json:"serverName"` // TOML Section key
	Family           string            `json:"family"`
	Release          string            `json:"release"`
	Container        Container         `json:"container"`
	Platform         Platform          `json:"platform"`
	IPv4Addrs        []string          `json:"ipv4Addrs,omitempty"` // only global unicast address (https://golang.org/pkg/net/#IP.IsGlobalUnicast)
	IPv6Addrs        []string          `json:"ipv6Addrs,omitempty"` // only global unicast address (https://golang.org/pkg/net/#IP.IsGlobalUnicast)
	IPSIdentifiers   map[string]string `json:"ipsIdentifiers,omitempty"`
	ScannedAt        time.Time         `json:"scannedAt"`
	ScanMode         string            `json:"scanMode"`
	ScannedVersion   string            `json:"scannedVersion"`
	ScannedRevision  string            `json:"scannedRevision"`
	ScannedBy        string            `json:"scannedBy"`
	ScannedVia       string            `json:"scannedVia"`
	ScannedIPv4Addrs []string          `json:"scannedIpv4Addrs,omitempty"`
	ScannedIPv6Addrs []string          `json:"scannedIpv6Addrs,omitempty"`
	ReportedAt       time.Time         `json:"reportedAt"`
	ReportedVersion  string            `json:"reportedVersion"`
	ReportedRevision string            `json:"reportedRevision"`
	ReportedBy       string            `json:"reportedBy"`
	Errors           []string          `json:"errors"`
	Warnings         []string          `json:"warnings"`

	ScannedCves       VulnInfos              `json:"scannedCves"`
	RunningKernel     Kernel                 `json:"runningKernel"`
	Packages          Packages               `json:"packages"`
	SrcPackages       SrcPackages            `json:",omitempty"`
	EnabledDnfModules []string               `json:"enabledDnfModules,omitempty"` // for dnf modules
	WordPressPackages WordPressPackages      `json:",omitempty"`
	LibraryScanners   LibraryScanners        `json:"libraries,omitempty"`
	CweDict           CweDict                `json:"cweDict,omitempty"`
	Optional          map[string]interface{} `json:",omitempty"`
	Config            struct {
		Scan   config.Config `json:"scan"`
		Report config.Config `json:"report"`
	} `json:"config"`
}

// Container has Container information
type Container struct {
	ContainerID string `json:"containerID"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	Type        string `json:"type"`
	UUID        string `json:"uuid"`
}

// Platform has platform information
type Platform struct {
	Name       string `json:"name"` // aws or azure or gcp or other...
	InstanceID string `json:"instanceID"`
}

// Kernel has the Release, version and whether need restart
type Kernel struct {
	Release        string `json:"release"`
	Version        string `json:"version"`
	RebootRequired bool   `json:"rebootRequired"`
}

// FilterInactiveWordPressLibs is filter function.
func (r *ScanResult) FilterInactiveWordPressLibs(detectInactive bool) {
	if detectInactive {
		return
	}

	filtered := r.ScannedCves.Find(func(v VulnInfo) bool {
		if len(v.WpPackageFixStats) == 0 {
			return true
		}
		// Ignore if all libs in this vulnInfo inactive
		for _, wp := range v.WpPackageFixStats {
			if p, ok := r.WordPressPackages.Find(wp.Name); ok {
				if p.Status != Inactive {
					return true
				}
			} else {
				logging.Log.Warnf("Failed to find the WordPress pkg: %+s", wp.Name)
			}
		}
		return false
	})
	r.ScannedCves = filtered
	return
}

// ReportFileName returns the filename on localhost without extension
func (r ScanResult) ReportFileName() (name string) {
	if r.Container.ContainerID == "" {
		return fmt.Sprintf("%s", r.ServerName)
	}
	return fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
}

// ReportKeyName returns the name of key on S3, Azure-Blob without extension
func (r ScanResult) ReportKeyName() (name string) {
	timestr := r.ScannedAt.Format(time.RFC3339)
	if r.Container.ContainerID == "" {
		return fmt.Sprintf("%s/%s", timestr, r.ServerName)
	}
	return fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	if r.Container.ContainerID == "" {
		return fmt.Sprintf("%s (%s%s)",
			r.FormatServerName(), r.Family, r.Release)
	}
	return fmt.Sprintf(
		"%s (%s%s) on %s",
		r.FormatServerName(),
		r.Family,
		r.Release,
		r.ServerName,
	)
}

// ServerInfoTui returns server information for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	if r.Container.ContainerID == "" {
		line := fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
		if len(r.Warnings) != 0 {
			line = "[Warn] " + line
		}
		if r.RunningKernel.RebootRequired {
			return "[Reboot] " + line
		}
		return line
	}

	fmtstr := "|-- %s (%s%s)"
	if r.RunningKernel.RebootRequired {
		fmtstr = "|-- [Reboot] %s (%s%s)"
	}
	return fmt.Sprintf(fmtstr, r.Container.Name, r.Family, r.Release)
}

// FormatServerName returns server and container name
func (r ScanResult) FormatServerName() (name string) {
	if r.Container.ContainerID == "" {
		name = r.ServerName
	} else {
		name = fmt.Sprintf("%s@%s",
			r.Container.Name, r.ServerName)
	}
	if r.RunningKernel.RebootRequired {
		name = "[Reboot Required] " + name
	}
	return
}

// FormatTextReportHeader returns header of text report
func (r ScanResult) FormatTextReportHeader() string {
	var buf bytes.Buffer
	for i := 0; i < len(r.ServerInfo()); i++ {
		buf.WriteString("=")
	}

	pkgs := r.FormatUpdatablePkgsSummary()
	if 0 < len(r.WordPressPackages) {
		pkgs = fmt.Sprintf("%s, %d WordPress pkgs", pkgs, len(r.WordPressPackages))
	}
	if 0 < len(r.LibraryScanners) {
		pkgs = fmt.Sprintf("%s, %d libs", pkgs, r.LibraryScanners.Total())
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s, %s, %s, %s\n%s\n",
		r.ServerInfo(),
		buf.String(),
		r.ScannedCves.FormatCveSummary(),
		r.ScannedCves.FormatFixedStatus(r.Packages),
		r.FormatExploitCveSummary(),
		r.FormatMetasploitCveSummary(),
		r.FormatAlertSummary(),
		pkgs)
}

// FormatUpdatablePkgsSummary returns a summary of updatable packages
func (r ScanResult) FormatUpdatablePkgsSummary() string {
	mode := r.Config.Scan.Servers[r.ServerName].Mode
	if !r.isDisplayUpdatableNum(mode) {
		return fmt.Sprintf("%d installed", len(r.Packages))
	}

	nUpdatable := 0
	for _, p := range r.Packages {
		if p.NewVersion == "" {
			continue
		}
		if p.Version != p.NewVersion || p.Release != p.NewRelease {
			nUpdatable++
		}
	}
	return fmt.Sprintf("%d installed, %d updatable",
		len(r.Packages),
		nUpdatable)
}

// FormatExploitCveSummary returns a summary of exploit cve
func (r ScanResult) FormatExploitCveSummary() string {
	nExploitCve := 0
	for _, vuln := range r.ScannedCves {
		if 0 < len(vuln.Exploits) {
			nExploitCve++
		}
	}
	return fmt.Sprintf("%d poc", nExploitCve)
}

// FormatMetasploitCveSummary returns a summary of exploit cve
func (r ScanResult) FormatMetasploitCveSummary() string {
	nMetasploitCve := 0
	for _, vuln := range r.ScannedCves {
		if 0 < len(vuln.Metasploits) {
			nMetasploitCve++
		}
	}
	return fmt.Sprintf("%d exploits", nMetasploitCve)
}

// FormatAlertSummary returns a summary of CERT alerts
func (r ScanResult) FormatAlertSummary() string {
	jaCnt := 0
	enCnt := 0
	for _, vuln := range r.ScannedCves {
		if len(vuln.AlertDict.En) > 0 {
			enCnt += len(vuln.AlertDict.En)
		}
		if len(vuln.AlertDict.Ja) > 0 {
			jaCnt += len(vuln.AlertDict.Ja)
		}
	}
	return fmt.Sprintf("en: %d, ja: %d alerts", enCnt, jaCnt)
}

func (r ScanResult) isDisplayUpdatableNum(mode config.ScanMode) bool {
	if r.Family == constant.FreeBSD {
		return false
	}

	if mode.IsOffline() {
		return false
	}
	if mode.IsFastRoot() || mode.IsDeep() {
		return true
	}
	if mode.IsFast() {
		switch r.Family {
		case constant.RedHat,
			constant.Oracle,
			constant.Debian,
			constant.Ubuntu,
			constant.Raspbian:
			return false
		default:
			return true
		}
	}
	return false
}

// IsContainer returns whether this ServerInfo is about container
func (r ScanResult) IsContainer() bool {
	return 0 < len(r.Container.ContainerID)
}

// RemoveRaspbianPackFromResult is for Raspberry Pi and removes the Raspberry Pi dedicated package from ScanResult.
func (r ScanResult) RemoveRaspbianPackFromResult() *ScanResult {
	if r.Family != constant.Raspbian {
		return &r
	}

	packs := make(Packages)
	for _, pack := range r.Packages {
		if !IsRaspbianPackage(pack.Name, pack.Version) {
			packs[pack.Name] = pack
		}
	}
	srcPacks := make(SrcPackages)
	for _, pack := range r.SrcPackages {
		if !IsRaspbianPackage(pack.Name, pack.Version) {
			srcPacks[pack.Name] = pack

		}
	}

	r.Packages = packs
	r.SrcPackages = srcPacks

	return &r
}

// ClearFields clears a given fields of ScanResult
func (r ScanResult) ClearFields(targetTagNames []string) ScanResult {
	if len(targetTagNames) == 0 {
		return r
	}
	target := map[string]bool{}
	for _, n := range targetTagNames {
		target[strings.ToLower(n)] = true
	}
	t := reflect.ValueOf(r).Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		jsonValue := strings.Split(f.Tag.Get("json"), ",")[0]
		if ok := target[strings.ToLower(jsonValue)]; ok {
			vv := reflect.New(f.Type).Elem().Interface()
			reflect.ValueOf(&r).Elem().FieldByName(f.Name).Set(reflect.ValueOf(vv))
		}
	}
	return r
}

// CheckEOL checks the EndOfLife of the OS
func (r *ScanResult) CheckEOL() {
	switch r.Family {
	case constant.ServerTypePseudo, constant.Raspbian:
		return
	}

	eol, found := config.GetEOL(r.Family, r.Release)
	if !found {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("Failed to check EOL. Register the issue to https://github.com/future-architect/vuls/issues with the information in `Family: %s Release: %s`",
				r.Family, r.Release))
		return
	}

	now := time.Now()
	if eol.IsStandardSupportEnded(now) {
		r.Warnings = append(r.Warnings, "Standard OS support is EOL(End-of-Life). Purchase extended support if available or Upgrading your OS is strongly recommended.")
		if eol.ExtendedSupportUntil.IsZero() {
			return
		}
		if !eol.IsExtendedSuppportEnded(now) {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("Extended support available until %s. Check the vendor site.",
					eol.ExtendedSupportUntil.Format("2006-01-02")))
		} else {
			r.Warnings = append(r.Warnings,
				"Extended support is also EOL. There are many Vulnerabilities that are not detected, Upgrading your OS strongly recommended.")
		}
	} else if !eol.StandardSupportUntil.IsZero() &&
		now.AddDate(0, 3, 0).After(eol.StandardSupportUntil) {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("Standard OS support will be end in 3 months. EOL date: %s",
				eol.StandardSupportUntil.Format("2006-01-02")))
	}
}

// SortForJSONOutput sort list elements in the ScanResult to diff in integration-test
func (r *ScanResult) SortForJSONOutput() {
	for k, v := range r.Packages {
		sort.Slice(v.AffectedProcs, func(i, j int) bool {
			return v.AffectedProcs[i].PID < v.AffectedProcs[j].PID
		})
		sort.Slice(v.NeedRestartProcs, func(i, j int) bool {
			return v.NeedRestartProcs[i].PID < v.NeedRestartProcs[j].PID
		})
		r.Packages[k] = v
	}
	for i, v := range r.LibraryScanners {
		sort.Slice(v.Libs, func(i, j int) bool {
			switch strings.Compare(v.Libs[i].Name, v.Libs[j].Name) {
			case -1:
				return true
			case 1:
				return false
			}
			return v.Libs[i].Version < v.Libs[j].Version

		})
		r.LibraryScanners[i] = v
	}

	for k, v := range r.ScannedCves {
		sort.Slice(v.AffectedPackages, func(i, j int) bool {
			return v.AffectedPackages[i].Name < v.AffectedPackages[j].Name
		})
		sort.Slice(v.DistroAdvisories, func(i, j int) bool {
			return v.DistroAdvisories[i].AdvisoryID < v.DistroAdvisories[j].AdvisoryID
		})
		sort.Slice(v.Exploits, func(i, j int) bool {
			return v.Exploits[i].URL < v.Exploits[j].URL
		})
		sort.Slice(v.Metasploits, func(i, j int) bool {
			return v.Metasploits[i].Name < v.Metasploits[j].Name
		})
		sort.Slice(v.Mitigations, func(i, j int) bool {
			return v.Mitigations[i].URL < v.Mitigations[j].URL
		})
		for kk, vv := range v.CveContents {
			sort.Slice(vv.References, func(i, j int) bool {
				return vv.References[i].Link < vv.References[j].Link
			})
			sort.Slice(vv.CweIDs, func(i, j int) bool {
				return vv.CweIDs[i] < vv.CweIDs[j]
			})
			for kkk, vvv := range vv.References {
				// sort v.CveContents[].References[].Tags
				sort.Slice(vvv.Tags, func(i, j int) bool {
					return vvv.Tags[i] < vvv.Tags[j]
				})
				vv.References[kkk] = vvv
			}
			v.CveContents[kk] = vv
		}
		sort.Slice(v.AlertDict.En, func(i, j int) bool {
			return v.AlertDict.En[i].Title < v.AlertDict.En[j].Title
		})
		sort.Slice(v.AlertDict.Ja, func(i, j int) bool {
			return v.AlertDict.Ja[i].Title < v.AlertDict.Ja[j].Title
		})
		r.ScannedCves[k] = v
	}
}

// CweDict is a dictionary for CWE
type CweDict map[string]CweDictEntry

// Get the name, url, top10URL for the specified cweID, lang
func (c CweDict) Get(cweID, lang string) (name, url, top10Rank, top10URL, cweTop25Rank, cweTop25URL, sansTop25Rank, sansTop25URL string) {
	cweNum := strings.TrimPrefix(cweID, "CWE-")
	switch lang {
	case "ja":
		if dict, ok := c[cweNum]; ok && dict.OwaspTopTen2017 != "" {
			top10Rank = dict.OwaspTopTen2017
			top10URL = cwe.OwaspTopTen2017GitHubURLJa[dict.OwaspTopTen2017]
		}
		if dict, ok := c[cweNum]; ok && dict.CweTopTwentyfive2019 != "" {
			cweTop25Rank = dict.CweTopTwentyfive2019
			cweTop25URL = cwe.CweTopTwentyfive2019URL
		}
		if dict, ok := c[cweNum]; ok && dict.SansTopTwentyfive != "" {
			sansTop25Rank = dict.SansTopTwentyfive
			sansTop25URL = cwe.SansTopTwentyfiveURL
		}
		if dict, ok := cwe.CweDictJa[cweNum]; ok {
			name = dict.Name
			url = fmt.Sprintf("http://jvndb.jvn.jp/ja/cwe/%s.html", cweID)
		} else {
			if dict, ok := cwe.CweDictEn[cweNum]; ok {
				name = dict.Name
			}
			url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweID)
		}
	default:
		if dict, ok := c[cweNum]; ok && dict.OwaspTopTen2017 != "" {
			top10Rank = dict.OwaspTopTen2017
			top10URL = cwe.OwaspTopTen2017GitHubURLEn[dict.OwaspTopTen2017]
		}
		if dict, ok := c[cweNum]; ok && dict.CweTopTwentyfive2019 != "" {
			cweTop25Rank = dict.CweTopTwentyfive2019
			cweTop25URL = cwe.CweTopTwentyfive2019URL
		}
		if dict, ok := c[cweNum]; ok && dict.SansTopTwentyfive != "" {
			sansTop25Rank = dict.SansTopTwentyfive
			sansTop25URL = cwe.SansTopTwentyfiveURL
		}
		url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweID)
		if dict, ok := cwe.CweDictEn[cweNum]; ok {
			name = dict.Name
		}
	}
	return
}

// CweDictEntry is a entry of CWE
type CweDictEntry struct {
	En                   *cwe.Cwe `json:"en,omitempty"`
	Ja                   *cwe.Cwe `json:"ja,omitempty"`
	OwaspTopTen2017      string   `json:"owaspTopTen2017"`
	CweTopTwentyfive2019 string   `json:"cweTopTwentyfive2019"`
	SansTopTwentyfive    string   `json:"sansTopTwentyfive"`
}
