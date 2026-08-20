package cpe

import (
	"testing"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// FuzzConvert drives random snmp.Result values through Convert. Strings are
// fed for SysDescr0, EntPhysicalMfgName, EntPhysicalName and
// EntPhysicalSoftwareRev. Invariant: never panic.
func FuzzConvert(f *testing.F) {
	seeds := []struct{ desc, mfg, name, rev string }{
		{"Cisco IOS Software, Version 12.4", "Cisco", "C2960", "12.4"},
		{"Cisco NX-OS, Version 7.0", "Cisco", "Nexus", "7.0"},
		{"Juniper Networks, Inc. mx240, kernel JUNOS 15.1F6", "Juniper Networks", "MX240", "15.1F6"},
		{"Arista Networks EOS version 4.20.7M running on an Arista Networks DCS-7050S", "Arista Networks", "DCS-7050S", "4.20.7M"},
		{"FortiGate-60E v5.6.4,build1575", "Fortinet", "FGT_60E", "FortiGate-60E v5.6.4,build1575"},
		{"YAMAHA RTX1210 Rev.14.01.42", "YAMAHA", "RTX1210", "14.01.42"},
		{"NEC IX Series IX2215 (magellan-sec) Software, Version 10.10.10", "NEC", "IX2215", "10.10.10"},
		{"Palo Alto Networks PA-220", "Palo Alto Networks", "PA-220", "10.0.0"},
		{"", "", "", ""},
		{"Cisco", "", "", ""},
		{"Cisco IOS Software, Version", "", "", ""},
		{"Juniper Networks, Inc. ", "", "", ""},
		{"Arista Networks EOS version  running on an ", "", "", ""},
		{"Arista Networks EOS version x running on an ", "", "", ""},
		{"FortiGate version", "", "", ""},
		{"YAMAHA RTX", "", "", ""},
		{"NEC", "", "", ""},
		{"foo version ", "Juniper Networks", "", ""},
		{"abc kernel JUNOS ", "Juniper Networks", "", ""},
		{"Juniper Networks, Inc. qfx", "Juniper Networks", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.desc, s.mfg, s.name, s.rev)
	}

	f.Fuzz(func(_ *testing.T, desc, mfg, ename, rev string) {
		r := snmp.Result{
			SysDescr0: desc,
			EntPhysicalTables: map[int]snmp.EntPhysicalTable{
				1: {
					EntPhysicalMfgName:     mfg,
					EntPhysicalName:        ename,
					EntPhysicalSoftwareRev: rev,
				},
			},
		}
		_ = Convert(r)
	})
}
