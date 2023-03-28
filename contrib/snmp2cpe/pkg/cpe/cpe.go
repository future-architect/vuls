package cpe

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/util"
)

// Convert ...
func Convert(result snmp.Result) []string {
	var cpes []string

	switch detectVendor(result) {
	case "Cisco":
		var p, v string
		lhs, _, _ := strings.Cut(result.SysDescr0, " RELEASE SOFTWARE")
		for _, s := range strings.Split(lhs, ",") {
			s = strings.TrimSpace(s)
			switch {
			case strings.Contains(s, "Cisco NX-OS"):
				p = "nx-os"
			case strings.Contains(s, "Cisco IOS Software"), strings.Contains(s, "Cisco Internetwork Operating System Software IOS"):
				p = "ios"
				if strings.Contains(lhs, "IOSXE") || strings.Contains(lhs, "IOS-XE") {
					p = "ios_xe"
				}
			case strings.HasPrefix(s, "Version "):
				v = strings.ToLower(strings.TrimPrefix(s, "Version "))
			}
		}
		if p != "" && v != "" {
			cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:cisco:%s:%s:*:*:*:*:*:*:*", p, v))
		}

		if t, ok := result.EntPhysicalTables[1]; ok {
			if t.EntPhysicalName != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:cisco:%s:-:*:*:*:*:*:*:*", strings.ToLower(t.EntPhysicalName)))
			}
			if p != "" && t.EntPhysicalSoftwareRev != "" {
				s, _, _ := strings.Cut(t.EntPhysicalSoftwareRev, " RELEASE SOFTWARE")
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:cisco:%s:%s:*:*:*:*:*:*:*", p, strings.ToLower(strings.TrimSuffix(s, ","))))
			}
		}
	case "Juniper Networks":
		if strings.HasPrefix(result.SysDescr0, "Juniper Networks, Inc.") {
			for _, s := range strings.Split(strings.TrimPrefix(result.SysDescr0, "Juniper Networks, Inc. "), ",") {
				s = strings.TrimSpace(s)
				switch {
				case strings.HasPrefix(s, "qfx"), strings.HasPrefix(s, "ex"), strings.HasPrefix(s, "mx"), strings.HasPrefix(s, "ptx"), strings.HasPrefix(s, "acx"), strings.HasPrefix(s, "bti"), strings.HasPrefix(s, "srx"):
					cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:juniper:%s:-:*:*:*:*:*:*:*", strings.Fields(s)[0]))
				case strings.HasPrefix(s, "kernel JUNOS "):
					cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:juniper:junos:%s:*:*:*:*:*:*:*", strings.ToLower(strings.Fields(strings.TrimPrefix(s, "kernel JUNOS "))[0])))
				}
			}

			if t, ok := result.EntPhysicalTables[1]; ok {
				if t.EntPhysicalSoftwareRev != "" {
					cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:juniper:junos:%s:*:*:*:*:*:*:*", strings.ToLower(t.EntPhysicalSoftwareRev)))
				}
			}
		} else {
			h, v, ok := strings.Cut(result.SysDescr0, " version ")
			if ok {
				cpes = append(cpes,
					fmt.Sprintf("cpe:2.3:h:juniper:%s:-:*:*:*:*:*:*:*", strings.ToLower(h)),
					fmt.Sprintf("cpe:2.3:o:juniper:screenos:%s:*:*:*:*:*:*:*", strings.ToLower(strings.Fields(v)[0])),
				)
			}
		}
	case "Arista Networks":
		v, h, ok := strings.Cut(result.SysDescr0, " running on an ")
		if ok {
			if strings.HasPrefix(v, "Arista Networks EOS version ") {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:arista:eos:%s:*:*:*:*:*:*:*", strings.ToLower(strings.TrimPrefix(v, "Arista Networks EOS version "))))
			}
			cpes = append(cpes, fmt.Sprintf("cpe:/h:arista:%s:-:*:*:*:*:*:*:*", strings.ToLower(strings.TrimPrefix(h, "Arista Networks "))))
		}
		if t, ok := result.EntPhysicalTables[1]; ok {
			if t.EntPhysicalSoftwareRev != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:arista:eos:%s:*:*:*:*:*:*:*", strings.ToLower(t.EntPhysicalSoftwareRev)))
			}
		}
	case "Fortinet":
		if t, ok := result.EntPhysicalTables[1]; ok {
			if strings.HasPrefix(t.EntPhysicalName, "FGT_") {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:fortinet:fortigate-%s:-:*:*:*:*:*:*:*", strings.ToLower(strings.TrimPrefix(t.EntPhysicalName, "FGT_"))))
			}
			for _, s := range strings.Fields(t.EntPhysicalSoftwareRev) {
				switch {
				case strings.HasPrefix(s, "FortiGate-"):
					cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:fortinet:%s:-:*:*:*:*:*:*:*", strings.ToLower(s)))
				case strings.HasPrefix(s, "v") && strings.Contains(s, "build"):
					if v, _, found := strings.Cut(strings.TrimPrefix(s, "v"), ",build"); found {
						if _, err := version.NewVersion(v); err == nil {
							cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:fortinet:fortios:%s:*:*:*:*:*:*:*", v))
						}
					}
				}
			}
		}
	case "YAMAHA":
		var h, v string
		for _, s := range strings.Fields(result.SysDescr0) {
			switch {
			case strings.HasPrefix(s, "RTX"), strings.HasPrefix(s, "NVR"), strings.HasPrefix(s, "RTV"), strings.HasPrefix(s, "RT"),
				strings.HasPrefix(s, "SRT"), strings.HasPrefix(s, "FWX"), strings.HasPrefix(s, "YSL-V810"):
				h = strings.ToLower(s)
			case strings.HasPrefix(s, "Rev."):
				if _, err := version.NewVersion(strings.TrimPrefix(s, "Rev.")); err == nil {
					v = strings.TrimPrefix(s, "Rev.")
				}
			}
		}
		if h != "" {
			cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:yamaha:%s:-:*:*:*:*:*:*:*", h))
			if v != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:yamaha:%s:%s:*:*:*:*:*:*:*", h, v))
			}
		}
	case "NEC":
		var h, v string
		for _, s := range strings.Split(result.SysDescr0, ",") {
			s = strings.TrimSpace(s)
			switch {
			case strings.HasPrefix(s, "IX Series "):
				h = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(s, "IX Series "), " (magellan-sec) Software"))
			case strings.HasPrefix(s, "Version "):
				if _, err := version.NewVersion(strings.TrimSpace(strings.TrimPrefix(s, "Version "))); err == nil {
					v = strings.TrimSpace(strings.TrimPrefix(s, "Version "))
				}
			}
		}
		if h != "" {
			cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:nec:%s:-:*:*:*:*:*:*:*", h))
			if v != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:nec:%s:%s:*:*:*:*:*:*:*", h, v))
			}
		}
	case "Palo Alto Networks":
		if t, ok := result.EntPhysicalTables[1]; ok {
			if t.EntPhysicalName != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:h:paloaltonetworks:%s:-:*:*:*:*:*:*:*", strings.ToLower(t.EntPhysicalName)))
			}
			if t.EntPhysicalSoftwareRev != "" {
				cpes = append(cpes, fmt.Sprintf("cpe:2.3:o:paloaltonetworks:pan-os:%s:*:*:*:*:*:*:*", t.EntPhysicalSoftwareRev))
			}
		}
	default:
		return []string{}
	}

	return util.Unique(cpes)
}

func detectVendor(r snmp.Result) string {
	if t, ok := r.EntPhysicalTables[1]; ok {
		switch t.EntPhysicalMfgName {
		case "Cisco":
			return "Cisco"
		case "Juniper Networks":
			return "Juniper Networks"
		case "Arista Networks":
			return "Arista Networks"
		case "Fortinet":
			return "Fortinet"
		case "YAMAHA":
			return "YAMAHA"
		case "NEC":
			return "NEC"
		case "Palo Alto Networks":
			return "Palo Alto Networks"
		}
	}

	switch {
	case strings.Contains(r.SysDescr0, "Cisco"):
		return "Cisco"
	case strings.Contains(r.SysDescr0, "Juniper Networks"),
		strings.Contains(r.SysDescr0, "SSG5"), strings.Contains(r.SysDescr0, "SSG20"), strings.Contains(r.SysDescr0, "SSG140"),
		strings.Contains(r.SysDescr0, "SSG320"), strings.Contains(r.SysDescr0, "SSG350"), strings.Contains(r.SysDescr0, "SSG520"),
		strings.Contains(r.SysDescr0, "SSG550"):
		return "Juniper Networks"
	case strings.Contains(r.SysDescr0, "Arista Networks"):
		return "Arista Networks"
	case strings.Contains(r.SysDescr0, "Fortinet"), strings.Contains(r.SysDescr0, "FortiGate"):
		return "Fortinet"
	case strings.Contains(r.SysDescr0, "YAMAHA"),
		strings.Contains(r.SysDescr0, "RTX810"), strings.Contains(r.SysDescr0, "RTX830"),
		strings.Contains(r.SysDescr0, "RTX1000"), strings.Contains(r.SysDescr0, "RTX1100"),
		strings.Contains(r.SysDescr0, "RTX1200"), strings.Contains(r.SysDescr0, "RTX1210"), strings.Contains(r.SysDescr0, "RTX1220"),
		strings.Contains(r.SysDescr0, "RTX1300"), strings.Contains(r.SysDescr0, "RTX1500"), strings.Contains(r.SysDescr0, "RTX2000"),
		strings.Contains(r.SysDescr0, "RTX3000"), strings.Contains(r.SysDescr0, "RTX3500"), strings.Contains(r.SysDescr0, "RTX5000"),
		strings.Contains(r.SysDescr0, "NVR500"), strings.Contains(r.SysDescr0, "NVR510"), strings.Contains(r.SysDescr0, "NVR700W"),
		strings.Contains(r.SysDescr0, "RTV01"), strings.Contains(r.SysDescr0, "RTV700"),
		strings.Contains(r.SysDescr0, "RT105i"), strings.Contains(r.SysDescr0, "RT105p"), strings.Contains(r.SysDescr0, "RT105e"),
		strings.Contains(r.SysDescr0, "RT107e"), strings.Contains(r.SysDescr0, "RT250i"), strings.Contains(r.SysDescr0, "RT300i"),
		strings.Contains(r.SysDescr0, "SRT100"),
		strings.Contains(r.SysDescr0, "FWX100"),
		strings.Contains(r.SysDescr0, "YSL-V810"):
		return "YAMAHA"
	case strings.Contains(r.SysDescr0, "NEC"):
		return "NEC"
	case strings.Contains(r.SysDescr0, "Palo Alto Networks"):
		return "Palo Alto Networks"
	default:
		return ""
	}
}
