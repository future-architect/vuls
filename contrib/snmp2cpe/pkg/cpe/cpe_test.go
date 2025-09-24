package cpe_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cpe"
	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		name string
		args snmp.Result
		want []string
	}{
		{
			name: "Cisco NX-OS Version 7.1(4)N1(1)",
			args: snmp.Result{
				SysDescr0: "Cisco NX-OS(tm) n6000, Software (n6000-uk9), Version 7.1(4)N1(1), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Device Manager Version 6.0(2)N1(1),Compiled 9/2/2016 10:00:00",
			},
			want: []string{"cpe:2.3:o:cisco:nx-os:7.1(4)n1(1):*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS Version 15.1(4)M3",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software, 2800 Software (C2800NM-ADVENTERPRISEK9-M), Version 15.1(4)M3, RELEASE SOFTWARE (fc1)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2011 by Cisco Systems, Inc.
		Compiled Tue 06-Dec-11 16:21 by prod_rel_team`,
			},
			want: []string{"cpe:2.3:o:cisco:ios:15.1(4)m3:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS Version 15.1(4)M4",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software, C181X Software (C181X-ADVENTERPRISEK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2012 by Cisco Systems, Inc.
		Compiled Tue 20-Mar-12 23:34 by prod_rel_team`,
			},
			want: []string{"cpe:2.3:o:cisco:ios:15.1(4)m4:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS Version 15.5(3)M on Cisco 892J-K9-V02",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software, C890 Software (C890-UNIVERSALK9-M), Version 15.5(3)M, RELEASE SOFTWARE (fc1)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2015 by Cisco Systems, Inc.
		Compiled Thu 23-Jul-15 03:08 by prod_rel_team`,
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Cisco",
					EntPhysicalName:        "892",
					EntPhysicalSoftwareRev: "15.5(3)M, RELEASE SOFTWARE (fc1)",
				}},
			},
			want: []string{"cpe:2.3:h:cisco:892:-:*:*:*:*:*:*:*", "cpe:2.3:o:cisco:ios:15.5(3)m:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS Version 15.4(3)M5 on Cisco C892FSP-K9-V02",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.4(3)M5, RELEASE SOFTWARE (fc1)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2016 by Cisco Systems, Inc.
		Compiled Tue 09-Feb-16 06:15 by prod_rel_team`,
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Cisco",
					EntPhysicalName:        "C892FSP-K9",
					EntPhysicalSoftwareRev: "15.4(3)M5, RELEASE SOFTWARE (fc1)",
				}},
			},
			want: []string{"cpe:2.3:h:cisco:c892fsp-k9:-:*:*:*:*:*:*:*", "cpe:2.3:o:cisco:ios:15.4(3)m5:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS Version 12.2(17d)SXB11",
			args: snmp.Result{
				SysDescr0: `Cisco Internetwork Operating System Software IOS (tm) s72033_rp Software (s72033_rp-JK9SV-M), Version 12.2(17d)SXB11, RELEASE SOFTWARE (fc1)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2005 by cisco Systems, Inc.`,
			},
			want: []string{"cpe:2.3:o:cisco:ios:12.2(17d)sxb11:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS-XE Version 16.12.4",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 16.12.4, RELEASE SOFTWARE (fc5)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2020 by Cisco Systems, Inc.
		Compiled Thu 09-Jul-20 19:31 by m`,
			},
			want: []string{"cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS-XE Version 03.06.07.E",
			args: snmp.Result{
				SysDescr0: `Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500es8-UNIVERSALK9-M), Version 03.06.07.E RELEASE SOFTWARE (fc3)
		Technical Support: http://www.cisco.com/techsupport
		Copyright (c) 1986-2017 by Cisco Systems, Inc.
		Compiled Wed`,
			},
			want: []string{"cpe:2.3:o:cisco:ios_xe:03.06.07.e:*:*:*:*:*:*:*"},
		},
		{
			name: "Cisco IOS-XE Version 03.06.06E on c38xx Stack",
			args: snmp.Result{
				SysDescr0: "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.06.06E RELEASE SOFTWARE (fc1)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2016 by Cisco Systems, Inc.\r\nCompiled Sat 17-Dec-",
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalName: "c38xx Stack",
				}},
			},
			want: []string{"cpe:2.3:h:cisco:c38xx_stack:-:*:*:*:*:*:*:*", "cpe:2.3:o:cisco:ios_xe:03.06.06e:*:*:*:*:*:*:*"},
		},
		{
			name: "Juniper SSG-5-SH-BT",
			args: snmp.Result{
				SysDescr0: "SSG5-ISDN version 6.3.0r14.0 (SN: 0000000000000001, Firewall+VPN)",
			},
			want: []string{"cpe:2.3:h:juniper:ssg5-isdn:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:screenos:6.3.0r14.0:*:*:*:*:*:*:*"},
		},
		{
			name: "JUNOS 20.4R3-S4.8 on Juniper MX240",
			args: snmp.Result{
				SysDescr0: "Juniper Networks, Inc. mx240 internet router, kernel JUNOS 20.4R3-S4.8, Build date: 2022-08-16 20:42:11 UTC Copyright (c) 1996-2022 Juniper Networks, Inc.",
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Juniper Networks",
					EntPhysicalName:        "CHAS-BP3-MX240-S",
					EntPhysicalSoftwareRev: "20.4R3-S4.8",
				}},
			},
			want: []string{"cpe:2.3:h:juniper:mx240:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:20.4r3-s4.8:*:*:*:*:*:*:*"},
		},
		{
			name: "JUNOS 12.1X46-D65.4 on Juniper SRX220H",
			args: snmp.Result{
				SysDescr0: "Juniper Networks, Inc. srx220h internet router, kernel JUNOS 12.1X46-D65.4 #0: 2016-12-30 01:34:30 UTC     builder@quoarth.juniper.net:/volume/build/junos/12.1/service/12.1X46-D65.4/obj-octeon/junos/bsd/kernels/JSRXNLE/kernel Build date: 2016-12-30 02:59",
			},
			want: []string{"cpe:2.3:h:juniper:srx220h:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:12.1x46-d65.4:*:*:*:*:*:*:*"},
		},
		{
			name: "JUNOS 12.3X48-D30.7 on Juniper SRX220H2",
			args: snmp.Result{
				SysDescr0: "Juniper Networks, Inc. srx220h2 internet router, kernel JUNOS 12.3X48-D30.7, Build date: 2016-04-29 00:01:04 UTC Copyright (c) 1996-2016 Juniper Networks, Inc.",
			},
			want: []string{"cpe:2.3:h:juniper:srx220h2:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:12.3x48-d30.7:*:*:*:*:*:*:*"},
		},
		{
			name: "JUNOS 20.4R3-S4.8 on Juniper SRX4600",
			args: snmp.Result{
				SysDescr0: "Juniper Networks, Inc. srx4600 internet router, kernel JUNOS 20.4R3-S4.8, Build date: 2022-08-16 20:42:11 UTC Copyright (c) 1996-2022 Juniper Networks, Inc.",
			},
			want: []string{"cpe:2.3:h:juniper:srx4600:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:20.4r3-s4.8:*:*:*:*:*:*:*"},
		},
		{
			name: "cpe:2.3:o:juniper:junos:20.4:r2-s2.2:*:*:*:*:*:*",
			args: snmp.Result{
				SysDescr0: "Juniper Networks, Inc. ex4300-32f Ethernet Switch, kernel JUNOS 20.4R3-S4.8, Build date: 2022-08-16 21:10:45 UTC Copyright (c) 1996-2022 Juniper Networks, Inc.",
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Juniper Networks",
					EntPhysicalName:        "",
					EntPhysicalSoftwareRev: "20.4R3-S4.8",
				}},
			},
			want: []string{"cpe:2.3:h:juniper:ex4300-32f:-:*:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:20.4r3-s4.8:*:*:*:*:*:*:*"},
		},
		{
			name: "Arista Networks EOS version 4.28.4M on DCS-7050TX-64",
			args: snmp.Result{
				SysDescr0: "Arista Networks EOS version 4.28.4M running on an Arista Networks DCS-7050TX-64",
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Arista Networks",
					EntPhysicalName:        "",
					EntPhysicalSoftwareRev: "4.28.4M",
				}},
			},
			want: []string{"cpe:2.3:h:arista:dcs-7050tx-64:-:*:*:*:*:*:*:*", "cpe:2.3:o:arista:eos:4.28.4m:*:*:*:*:*:*:*"},
		},
		{
			name: "FortiGate-50E",
			args: snmp.Result{
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Fortinet",
					EntPhysicalName:        "FGT_50E",
					EntPhysicalSoftwareRev: "FortiGate-50E v5.4.6,build1165b1165,171018 (GA)",
				}},
			},
			want: []string{"cpe:2.3:h:fortinet:fortigate-50e:-:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortios:5.4.6:*:*:*:*:*:*:*"},
		},
		{
			name: "FortiGate-60F",
			args: snmp.Result{
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Fortinet",
					EntPhysicalName:        "FGT_60F",
					EntPhysicalSoftwareRev: "FortiGate-60F v6.4.11,build2030,221031 (GA.M)",
				}},
			},
			want: []string{"cpe:2.3:h:fortinet:fortigate-60f:-:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortios:6.4.11:*:*:*:*:*:*:*"},
		},
		{
			name: "FortiSwitch-108E",
			args: snmp.Result{
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Fortinet",
					EntPhysicalName:        "FS_108E",
					EntPhysicalSoftwareRev: "FortiSwitch-108E v6.4.6,build0000,000000 (GA)",
				}},
			},
			want: []string{"cpe:2.3:h:fortinet:fortiswitch-108e:-:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiswitch:6.4.6:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiswitch_firmware:6.4.6:*:*:*:*:*:*:*"},
		},
		{
			name: "YAMAHA RTX1000",
			args: snmp.Result{
				SysDescr0: "RTX1000 Rev.8.01.29 (Fri Apr 15 11:50:44 2011)",
			},
			want: []string{"cpe:2.3:h:yamaha:rtx1000:-:*:*:*:*:*:*:*", "cpe:2.3:o:yamaha:rtx1000:8.01.29:*:*:*:*:*:*:*"},
		},
		{
			name: "YAMAHA RTX810",
			args: snmp.Result{
				SysDescr0: "RTX810 Rev.11.01.34 (Tue Nov 26 18:39:12 2019)",
			},
			want: []string{"cpe:2.3:h:yamaha:rtx810:-:*:*:*:*:*:*:*", "cpe:2.3:o:yamaha:rtx810:11.01.34:*:*:*:*:*:*:*"},
		},
		{
			name: "NEC IX2105",
			args: snmp.Result{
				SysDescr0: "NEC Portable Internetwork Core Operating System Software, IX Series IX2105 (magellan-sec) Software, Version 8.8.22, RELEASE SOFTWARE, Compiled Jul 04-Wed-2012 14:18:46 JST #2, IX2105",
			},
			want: []string{"cpe:2.3:h:nec:ix2105:-:*:*:*:*:*:*:*", "cpe:2.3:o:nec:ix2105:8.8.22:*:*:*:*:*:*:*"},
		},
		{
			name: "NEC IX2235",
			args: snmp.Result{
				SysDescr0: "NEC Portable Internetwork Core Operating System Software, IX Series IX2235 (magellan-sec) Software, Version 10.6.21, RELEASE SOFTWARE, Compiled Dec 15-Fri-YYYY HH:MM:SS JST #2, IX2235",
			},
			want: []string{"cpe:2.3:h:nec:ix2235:-:*:*:*:*:*:*:*", "cpe:2.3:o:nec:ix2235:10.6.21:*:*:*:*:*:*:*"},
		},
		{
			name: "Palo Alto Networks PAN-OS 10.0.0 on PA-220",
			args: snmp.Result{
				SysDescr0: "Palo Alto Networks PA-220 series firewall",
				EntPhysicalTables: map[int]snmp.EntPhysicalTable{1: {
					EntPhysicalMfgName:     "Palo Alto Networks",
					EntPhysicalName:        "PA-220",
					EntPhysicalSoftwareRev: "10.0.0",
				}},
			},
			want: []string{"cpe:2.3:h:paloaltonetworks:pa-220:-:*:*:*:*:*:*:*", "cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []cmp.Option{
				cmpopts.SortSlices(func(i, j string) bool {
					return i < j
				}),
			}
			if diff := cmp.Diff(cpe.Convert(tt.args), tt.want, opts...); diff != "" {
				t.Errorf("Convert() value is mismatch (-got +want):%s\n", diff)
			}
		})
	}
}
