package vulnsrc

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/db/types"
)

func ToVulsVulnerability(src Vulnerability) types.Vulnerability {
	return types.Vulnerability{
		ID:          src.ID,
		Advisory:    toVulsAdvisory(src.Advisory),
		Title:       toVulsTitle(src.Title),
		Description: toVulsDescription(src.Description),
		CVSS:        toVulsCVSS(src.CVSS),
		EPSS:        toVulsEPSS(src.EPSS),
		CWE:         toVulsCWE(src.CWE),
		Metasploit:  toVulsMetasploit(src.Metasploit),
		Exploit:     toVulsExploit(src.Exploit),
		KEV:         src.KEV != nil,
		Published:   toVulsPublished(src.Published),
		Modified:    toVulsModified(src.Modified),
		Reference:   toVulsReference(src.References),
	}
}

func toVulsAdvisory(src *Advisories) []string {
	if src == nil {
		return nil
	}

	var advs []string
	if src.MITRE != nil {
		advs = append(advs, "mitre")
	}
	if src.NVD != nil {
		advs = append(advs, "nvd")
	}
	for _, a := range src.JVN {
		advs = append(advs, fmt.Sprintf("jvn:%s", a.ID))
	}
	for v, as := range src.Alma {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("alma:%s:%s", v, a.ID))
		}
	}
	for v, a := range src.Alpine {
		advs = append(advs, fmt.Sprintf("alpine:%s:%s", v, a.ID))
	}
	for v, as := range src.Amazon {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("amazon:%s:%s", v, a.ID))
		}
	}
	for _, a := range src.Arch {
		advs = append(advs, fmt.Sprintf("arch:%s", a.ID))
	}
	for v, as := range src.DebianOVAL {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("debian_oval:%s:%s", v, a.ID))
		}
	}
	for v, a := range src.DebianSecurityTracker {
		advs = append(advs, fmt.Sprintf("debian_security_tracker:%s:%s", v, a.ID))
	}
	for _, a := range src.FreeBSD {
		advs = append(advs, fmt.Sprintf("freebsd:%s", a.ID))
	}
	for v, as := range src.Oracle {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("oracle:%s:%s", v, a.ID))
		}
	}
	for v, as := range src.RedHatOVAL {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("redhat_oval:%s:%s", v, a.ID))
		}
	}
	for v, as := range src.SUSEOVAL {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("suse_oval:%s:%s", v, a.ID))
		}
	}
	if src.SUSECVRF != nil {
		advs = append(advs, "suse_cvrf")
	}
	for v, as := range src.UbuntuOVAL {
		for _, a := range as {
			advs = append(advs, fmt.Sprintf("ubuntu_oval:%s:%s", v, a.ID))
		}
	}
	if src.UbuntuSecurityTracker != nil {
		advs = append(advs, "ubuntu_security_tracker")
	}
	return advs
}

func toVulsTitle(src *Titles) string {
	if src == nil {
		return ""
	}

	if src.NVD != "" {
		return src.NVD
	}
	if src.MITRE != "" {
		return src.MITRE
	}
	return ""
}

func toVulsDescription(src *Descriptions) string {
	if src == nil {
		return ""
	}

	if src.NVD != "" {
		return src.NVD
	}
	if src.MITRE != "" {
		return src.MITRE
	}
	return ""
}

func toVulsCVSS(src *CVSSes) []types.CVSS {
	if src == nil {
		return nil
	}

	var cvsses []types.CVSS
	for _, c := range src.NVD {
		cvsses = append(cvsses, types.CVSS{
			Source:   "nvd",
			Version:  c.Version,
			Vector:   c.Vector,
			Score:    c.Score,
			Severity: c.Severity,
		})
	}
	for id, cs := range src.JVN {
		for _, c := range cs {
			cvsses = append(cvsses, types.CVSS{
				Source:   fmt.Sprintf("jvn:%s", id),
				Version:  c.Version,
				Vector:   c.Vector,
				Score:    c.Score,
				Severity: c.Severity,
			})
		}
	}
	for v, idcs := range src.Alma {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("alma:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for v, idcs := range src.Amazon {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("amazon:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for id, cs := range src.Arch {
		for _, c := range cs {
			cvsses = append(cvsses, types.CVSS{
				Source:   fmt.Sprintf("arch:%s", id),
				Version:  c.Version,
				Vector:   c.Vector,
				Score:    c.Score,
				Severity: c.Severity,
			})
		}
	}
	for v, idcs := range src.Oracle {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("oracle:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for v, idcs := range src.RedHatOVAL {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("redhat_oval:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for v, idcs := range src.SUSEOVAL {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("suse_oval:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for _, c := range src.SUSECVRF {
		cvsses = append(cvsses, types.CVSS{
			Source:   "suse_cvrf",
			Version:  c.Version,
			Vector:   c.Vector,
			Score:    c.Score,
			Severity: c.Severity,
		})
	}
	for v, idcs := range src.UbuntuOVAL {
		for id, cs := range idcs {
			for _, c := range cs {
				cvsses = append(cvsses, types.CVSS{
					Source:   fmt.Sprintf("ubuntu_oval:%s:%s", v, id),
					Version:  c.Version,
					Vector:   c.Vector,
					Score:    c.Score,
					Severity: c.Severity,
				})
			}
		}
	}
	for _, c := range src.UbuntuSecurityTracker {
		cvsses = append(cvsses, types.CVSS{
			Source:   "ubuntu_security_tracker",
			Version:  c.Version,
			Vector:   c.Vector,
			Score:    c.Score,
			Severity: c.Severity,
		})
	}

	return cvsses
}

func toVulsEPSS(src *EPSS) *types.EPSS {
	if src == nil {
		return nil
	}
	return &types.EPSS{EPSS: src.EPSS, Percentile: src.Percentile}
}

func toVulsCWE(src *CWEs) []types.CWE {
	if src == nil {
		return nil
	}

	m := map[string][]string{}
	for _, c := range src.NVD {
		m[c] = append(m[c], "nvd")
	}
	for id, cs := range src.JVN {
		for _, c := range cs {
			m[c] = append(m[c], fmt.Sprintf("jvn:%s", id))
		}
	}
	for v, idcs := range src.RedHatOVAL {
		for id, cs := range idcs {
			for _, c := range cs {
				m[c] = append(m[c], fmt.Sprintf("redhat_oval:%s:%s", v, id))
			}
		}
	}

	var cwes []types.CWE
	for id, srcs := range m {
		cwes = append(cwes, types.CWE{
			Source: srcs,
			ID:     id,
		})
	}
	return cwes
}

func toVulsMetasploit(src []Metasploit) []types.Metasploit {
	ms := make([]types.Metasploit, 0, len(src))
	for _, m := range src {
		ms = append(ms, types.Metasploit{
			Title: m.Title,
			URL:   m.URLs[0],
		})
	}
	return ms
}

func toVulsExploit(src *Exploit) []types.Exploit {
	if src == nil {
		return nil
	}

	m := map[string][]string{}
	for _, e := range src.NVD {
		m[e] = append(m[e], "nvd")
	}
	for _, e := range src.ExploitDB {
		m[e.URL] = append(m[e.URL], "exploit-db")
	}
	for _, e := range src.GitHub {
		m[e.URL] = append(m[e.URL], "github")
	}
	for _, e := range src.InTheWild {
		m[e.URL] = append(m[e.URL], "inthewild")
	}
	if src.Trickest != nil {
		if src.Trickest.PoC != nil {
			for _, e := range src.Trickest.PoC.Reference {
				m[e] = append(m[e], "trickest")
			}
			for _, e := range src.Trickest.PoC.GitHub {
				m[e] = append(m[e], "trickest")
			}
		}
	}

	var es []types.Exploit
	for u, srcs := range m {
		es = append(es, types.Exploit{
			Source: srcs,
			URL:    u,
		})
	}
	return es
}

func toVulsPublished(src *Publisheds) *time.Time {
	if src == nil {
		return nil
	}

	if src.NVD != nil {
		return src.NVD
	}
	if src.MITRE != nil {
		return src.MITRE
	}
	return nil
}

func toVulsModified(src *Modifieds) *time.Time {
	if src == nil {
		return nil
	}

	if src.NVD != nil {
		return src.NVD
	}
	if src.MITRE != nil {
		return src.MITRE
	}
	return nil
}

func toVulsReference(src *References) []string {
	if src == nil {
		return nil
	}

	m := map[string]struct{}{}
	for _, r := range src.MITRE {
		m[r.URL] = struct{}{}
	}
	for _, r := range src.NVD {
		m[r.URL] = struct{}{}
	}
	for _, rs := range src.JVN {
		for _, r := range rs {
			m[r.URL] = struct{}{}
		}
	}
	for _, idrs := range src.Alma {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, idrs := range src.Amazon {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, rs := range src.Arch {
		for _, r := range rs {
			m[r.URL] = struct{}{}
		}
	}
	for _, idrs := range src.DebianOVAL {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, rs := range src.DebianSecurityTracker {
		for _, r := range rs {
			m[r.URL] = struct{}{}
		}
	}
	for _, rs := range src.FreeBSD {
		for _, r := range rs {
			m[r.URL] = struct{}{}
		}
	}
	for _, idrs := range src.Oracle {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, idrs := range src.RedHatOVAL {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, idrs := range src.SUSEOVAL {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, r := range src.SUSECVRF {
		m[r.URL] = struct{}{}
	}
	for _, idrs := range src.UbuntuOVAL {
		for _, rs := range idrs {
			for _, r := range rs {
				m[r.URL] = struct{}{}
			}
		}
	}
	for _, r := range src.UbuntuSecurityTracker {
		m[r.URL] = struct{}{}
	}

	return maps.Keys(m)
}

func ToVulsPackage(src DetectPackage, advType string) (map[string]types.Packages, error) {
	m := map[string]types.Packages{}
	for id, ps := range src.Packages {
		id = fmt.Sprintf("%s:%s", advType, id)
		for _, p := range ps {
			name, err := toVulsPackageName(p.Name, p.ModularityLabel)
			if err != nil {
				return nil, errors.Wrap(err, "to vuls package name")
			}

			base, ok := m[name]
			if !ok {
				base = types.Packages{
					ID:      src.ID,
					Package: map[string]types.Package{},
				}
			}

			vers := make([][]types.Version, 0, len(p.Version))
			for _, vs := range p.Version {
				vss := make([]types.Version, 0, len(vs))
				for _, v := range vs {
					vss = append(vss, types.Version{
						Operator: v.Operator,
						Version:  v.Version,
					})
				}
				vers = append(vers, vss)
			}

			base.Package[id] = types.Package{
				Status:     p.Status,
				Version:    vers,
				Arch:       p.Arch,
				Repository: p.Repository,
				CPE:        p.CPE,
			}

			m[name] = base
		}
	}
	return m, nil
}

func toVulsPackageName(name, modularitylabel string) (string, error) {
	if modularitylabel == "" {
		return name, nil
	}

	ss := strings.Split(modularitylabel, ":")
	if len(ss) < 2 {
		return name, errors.Errorf(`[WARN] unexpected modularitylabel. accepts: "<module name>:<stream>(:<version>:<context>:<arch>)", received: "%s"`, modularitylabel)
	}
	return fmt.Sprintf("%s:%s::%s", ss[0], ss[1], name), nil
}

func ToVulsCPEConfiguration(src DetectCPE, advType string) (map[string]types.CPEConfigurations, error) {
	m := map[string][]types.CPEConfiguration{}
	for id, cs := range src.Configurations {
		id = fmt.Sprintf("%s:%s", advType, id)
		for _, c := range cs {
			rs := make([]types.CPE, 0, len(c.RunningOn))
			for _, r := range c.RunningOn {
				rs = append(rs, toVulnsrcCPEtoVulsCPE(r))
			}

			for _, v := range c.Vulnerable {
				m[id] = append(m[id], types.CPEConfiguration{
					Vulnerable: toVulnsrcCPEtoVulsCPE(v),
					RunningOn:  rs,
				})
			}
		}
	}

	m2 := map[string]types.CPEConfigurations{}
	for id, cs := range m {
		for _, c := range cs {
			pvp, err := toVulsCPEConfigurationName(c.Vulnerable.CPEVersion, c.Vulnerable.CPE)
			if err != nil {
				return nil, errors.Wrap(err, "to vuls cpe configuration name")
			}

			base, ok := m2[pvp]
			if !ok {
				base = types.CPEConfigurations{
					ID:            src.ID,
					Configuration: map[string][]types.CPEConfiguration{},
				}
			}
			base.Configuration[id] = append(base.Configuration[id], c)

			m2[pvp] = base
		}
	}

	return m2, nil
}

func toVulsCPEConfigurationName(version string, cpe string) (string, error) {
	var (
		wfn common.WellFormedName
		err error
	)
	switch version {
	case "2.3":
		wfn, err = naming.UnbindFS(cpe)
	default:
		wfn, err = naming.UnbindURI(cpe)
	}
	if err != nil {
		return "", errors.Wrapf(err, "unbind %s", cpe)
	}
	return fmt.Sprintf("%s:%s:%s", wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)), nil
}

func toVulnsrcCPEtoVulsCPE(s CPE) types.CPE {
	d := types.CPE{
		CPEVersion: s.CPEVersion,
		CPE:        s.CPE,
	}
	for _, v := range s.Version {
		d.Version = append(d.Version, types.Version{
			Operator: v.Operator,
			Version:  v.Version,
		})
	}
	return d
}

func ToVulsRepositoryToCPE(src RepositoryToCPE) types.RepositoryToCPE {
	return types.RepositoryToCPE(src)
}

func ToVulsSupercedences(src []Supercedence) types.Supercedence {
	ss := types.Supercedence{}
	for _, s := range src {
		ss[s.KBID] = s.Supersededby.KBIDs
	}
	return ss
}
