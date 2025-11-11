package scanner

import (
	"reflect"
	"slices"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

func Test_parseSystemInfo(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		osInfo  osInfo
		kbs     []string
		wantErr bool
	}{
		{
			name: "Workstation",
			args: `
Host Name:                 DESKTOP
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19044 N/A Build 19044
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00000-00000-00000-AA000
Original Install Date:     2022/04/13, 12:25:41
System Boot Time:          2022/06/06, 16:43:45
System Manufacturer:       HP
System Model:              HP EliteBook 830 G7 Notebook PC
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
						   [01]: Intel64 Family 6 Model 142 Stepping 12 GenuineIntel ~1803 Mhz
BIOS Version:              HP S70 Ver. 01.05.00, 2021/04/26
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     15,709 MB
Available Physical Memory: 12,347 MB
Virtual Memory: Max Size:  18,141 MB
Virtual Memory: Available: 14,375 MB
Virtual Memory: In Use:    3,766 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DESKTOP
Hotfix(s):                 7 Hotfix(s) Installed.
						   [01]: KB5012117
						   [02]: KB4562830
						   [03]: KB5003791
						   [04]: KB5007401
						   [05]: KB5012599
						   [06]: KB5011651
						   [07]: KB5005699
Network Card(s):           1 NIC(s) Installed.
						   [01]: Intel(R) Wi-Fi 6 AX201 160MHz
								 Connection Name: Wi-Fi
								 DHCP Enabled:    Yes
								 DHCP Server:     192.168.0.1
								 IP address(es)
								 [01]: 192.168.0.205
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes
						   Virtualization Enabled In Firmware: Yes
						   Second Level Address Translation: Yes
						   Data Execution Prevention Available: Yes
`,
			osInfo: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			kbs: []string{"5012117", "4562830", "5003791", "5007401", "5012599", "5011651", "5005699"},
		},
		{
			name: "Server",
			args: `
Host Name:                 WIN-RIBN7SM07BK
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00454-10000-00001-AA483
Original Install Date:     10/1/2021, 4:15:34 PM
System Boot Time:          10/22/2021, 8:36:55 AM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
						   [01]: Intel64 Family 6 Model 158 Stepping 9 GenuineIntel ~2808 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.0, 12/17/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 900 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,143 MB
Virtual Memory: In Use:    1,056 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WIN-RIBN7SM07BK
Hotfix(s):                 3 Hotfix(s) Installed.
						   [01]: KB5004330
						   [02]: KB5005039
						   [03]: KB5005552
Network Card(s):           1 NIC(s) Installed.
						   [01]: Microsoft Hyper-V Network Adapter
								 Connection Name: Ethernet
								 DHCP Enabled:    Yes
								 DHCP Server:     192.168.254.254
								 IP address(es)
								 [01]: 192.168.254.172
								 [02]: fe80::b4a1:11cc:2c4:4f57
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
`,
			osInfo: osInfo{
				productName:      "Microsoft Windows Server 2022 Standard",
				version:          "10.0",
				build:            "20348",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			kbs: []string{"5004330", "5005039", "5005552"},
		},
		{
			name: "Domain Controller",
			args: `
Host Name:                 vuls
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          N/A
Registered Organization:   N/A
Product ID:                00430-00000-00000-AA602
Original Install Date:     1/16/2023, 10:04:07 AM
System Boot Time:          3/28/2023, 8:37:14 AM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
						   [01]: Intel64 Family 6 Model 85 Stepping 4 GenuineIntel ~2095 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 5/9/2022
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Coordinated Universal Time
Total Physical Memory:     16,383 MB
Available Physical Memory: 13,170 MB
Virtual Memory: Max Size:  18,431 MB
Virtual Memory: Available: 15,208 MB
Virtual Memory: In Use:    3,223 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    vuls
Logon Server:              \\vuls
Hotfix(s):                 5 Hotfix(s) Installed.
						   [01]: KB5022511
						   [02]: KB5012170
						   [03]: KB5023702
						   [04]: KB5020374
						   [05]: KB5023789
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
`,
			osInfo: osInfo{
				productName:      "Microsoft Windows Server 2019 Datacenter",
				version:          "10.0",
				build:            "17763",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Domain Controller",
			},
			kbs: []string{"5022511", "5012170", "5023702", "5020374", "5023789"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osInfo, kbs, err := parseSystemInfo(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSystemInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if osInfo != tt.osInfo {
				t.Errorf("parseSystemInfo() got = %v, want %v", osInfo, tt.osInfo)
			}
			if !reflect.DeepEqual(kbs, tt.kbs) {
				t.Errorf("parseSystemInfo() got = %v, want %v", kbs, tt.kbs)
			}
		})
	}
}

func Test_parseGetComputerInfo(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    osInfo
		wantErr bool
	}{
		{
			name: "happy",
			args: `
WindowsProductName         : Windows 10 Pro
OsVersion                  : 10.0.19044
WindowsEditionId           : Professional
OsCSDVersion               :
CsSystemType               : x64-based PC
WindowsInstallationType    : Client
`,
			want: osInfo{
				productName:      "Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGetComputerInfo(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGetComputerInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseGetComputerInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseWmiObject(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    osInfo
		wantErr bool
	}{
		{
			name: "happy",
			args: `
Caption            : Microsoft Windows 10 Pro
Version            : 10.0.19044
OperatingSystemSKU : 48
CSDVersion         :





DomainRole : 1
SystemType : x64-based PC`,
			want: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWmiObject(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseWmiObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseWmiObject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseRegistry(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    osInfo
		wantErr bool
	}{
		{
			name: "happy",
			args: `
ProductName               : Windows 10 Pro
CurrentVersion            : 6.3
CurrentMajorVersionNumber : 10
CurrentMinorVersionNumber : 0
CurrentBuildNumber        : 19044
UBR                       : 2364
EditionID                 : Professional
InstallationType          : Client

PROCESSOR_ARCHITECTURE : AMD64
`,
			want: osInfo{
				productName:      "Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "2364",
				edition:          "Professional",
				servicePack:      "",
				arch:             "AMD64",
				installationType: "Client",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRegistry(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRegistry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_detectOSName(t *testing.T) {
	tests := []struct {
		name    string
		args    osInfo
		want    string
		wantErr bool
	}{
		{
			name: "Windows 10 for x64-based Systems",
			args: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "10585",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			want: "Windows 10 for x64-based Systems",
		},
		{
			name: "Windows 10 Version 21H2 for x64-based Systems",
			args: osInfo{
				productName:      "Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "2364",
				edition:          "Professional",
				servicePack:      "",
				arch:             "AMD64",
				installationType: "Client",
			},
			want: "Windows 10 Version 21H2 for x64-based Systems",
		},
		{
			name: "Windows 10 Version 21H2 for x64-based Systems",
			args: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			want: "Windows 10 Version 21H2 for x64-based Systems",
		},
		{
			name: "Windows 10 Version 22H2 for 32-bit Systems",
			args: osInfo{
				productName:      "Windows 10 Pro",
				version:          "10.0",
				build:            "19045",
				revision:         "6093",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x86",
				installationType: "Client",
			},
			want: "Windows 10 Version 22H2 for 32-bit Systems",
		},
		{
			name: "Windows 11 Version 21H2 for x64-based Systems",
			args: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "22000",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			want: "Windows 11 Version 21H2 for x64-based Systems",
		},
		{
			name: "Windows 11 Version 24H2 for x64-based Systems",
			args: osInfo{
				productName:      "Microsoft Windows 11 Pro",
				version:          "10.0",
				build:            "26100",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			want: "Windows 11 Version 24H2 for x64-based Systems",
		},
		{
			name: "Windows 11 latest release",
			args: osInfo{
				productName:      "Microsoft Windows 11 Pro",
				version:          "10.0",
				build:            "30000",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			want: "Windows 11 Version 25H2 for x64-based Systems",
		},
		{
			name: "Windows Server 2019",
			args: osInfo{
				productName:      "Microsoft Windows Server 2019 Datacenter",
				version:          "10.0",
				build:            "17763",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Domain Controller",
			},
			want: "Windows Server 2019",
		},
		{
			name: "Windows Server 2022",
			args: osInfo{
				productName:      "Windows Server",
				version:          "10.0",
				build:            "20348",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			want: "Windows Server 2022",
		},
		{
			name: "Windows Server 2022, 23H2 Edition",
			args: osInfo{
				productName:      "Microsoft Windows Server 2022 Datacenter",
				version:          "10.0",
				build:            "25398",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			want: "Windows Server 2022, 23H2 Edition",
		},
		{
			name: "Windows Server 2025",
			args: osInfo{
				productName:      "Microsoft Windows Server 2025 Datacenter",
				version:          "10.0",
				build:            "26100",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			want: "Windows Server 2025",
		},
		{
			name: "Windows Server latest release",
			args: osInfo{
				productName:      "Microsoft Windows Server 2025 Datacenter",
				version:          "10.0",
				build:            "30000",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			want: "Windows Server 2025",
		},
		{
			name: "err",
			args: osInfo{
				productName:      "Microsoft Windows 10 Pro",
				version:          "10.0",
				build:            "build",
				revision:         "",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectOSName(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectOSName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("detectOSName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_formatKernelVersion(t *testing.T) {
	tests := []struct {
		name string
		args osInfo
		want string
	}{
		{
			name: "major.minor.build.revision",
			args: osInfo{
				version:  "10.0",
				build:    "19045",
				revision: "2130",
			},
			want: "10.0.19045.2130",
		},
		{
			name: "major.minor.build",
			args: osInfo{
				version: "10.0",
				build:   "19045",
			},
			want: "10.0.19045",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatKernelVersion(tt.args); got != tt.want {
				t.Errorf("formatKernelVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInstalledPackages(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    models.Packages
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Name         : Git
Version      : 2.35.1.2
ProviderName : Programs

Name         : Oracle Database 11g Express Edition
Version      : 11.2.0
ProviderName : msi

Name         : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Version      :
ProviderName : msu
`,
			},
			want: models.Packages{
				"Git": {
					Name:    "Git",
					Version: "2.35.1.2",
				},
				"Oracle Database 11g Express Edition": {
					Name:    "Oracle Database 11g Express Edition",
					Version: "11.2.0",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, _, err := o.parseInstalledPackages(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseInstalledPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseInstalledPackages() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseGetHotfix(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
HotFixID : KB5020872

HotFixID : KB4562830
`,
			},
			want:    []string{"5020872", "4562830"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseGetHotfix(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseGetHotfix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseGetHotfix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseGetPackageMSU(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Name         : Git
Version      : 2.35.1.2
ProviderName : Programs

Name         : Oracle Database 11g Express Edition
Version      : 11.2.0
ProviderName : msi

Name         : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Version      :
ProviderName : msu
`,
			},
			want:    []string{"5021233"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseGetPackageMSU(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseGetPackageMSU() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseGetPackageMSU() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseWindowsUpdaterSearch(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `5012170
5021233
5021088
`,
			},
			want:    []string{"5012170", "5021233", "5021088"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseWindowsUpdaterSearch(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseWindowsUpdaterSearch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseWindowsUpdaterSearch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseWindowsUpdateHistory(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Title      : 2022-10 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5020435)
Operation  : 1
ResultCode : 2

Title      : 2022-10 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5020435)
Operation  : 2
ResultCode : 2

Title      : 2022-12 x64 (KB5021088) 向け Windows 10 Version 21H2 用 .NET Framework 3.5、4.8 および 4.8.1 の累積的な更新プログラム
Operation  : 1
ResultCode : 2

Title      : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Operation  : 1
ResultCode : 2
`,
			},
			want:    []string{"5021088", "5021233"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseWindowsUpdateHistory(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseWindowsUpdateHistory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.Sort(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseWindowsUpdateHistory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_windows_detectKBsFromKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		base    base
		want    models.WindowsKB
		wantErr bool
	}{
		{
			name: "10.0.19045.2129",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.19045.2129"}},
			},
			want: models.WindowsKB{
				Applied:   nil,
				Unapplied: []string{"5020953", "5019959", "5020030", "5021233", "5022282", "5019275", "5022834", "5022906", "5023696", "5023773", "5025221", "5025297", "5026361", "5026435", "5027215", "5027293", "5028166", "5028244", "5029244", "5029331", "5030211", "5030300", "5031356", "5031445", "5032189", "5032278", "5033372", "5034122", "5034203", "5034763", "5034843", "5035845", "5035941", "5036892", "5036979", "5037768", "5037849", "5039211", "5039299", "5040427", "5040525", "5041580", "5041582", "5043064", "5043131", "5044273", "5045594", "5046613", "5046714", "5048652", "5049981", "5050081", "5051974", "5052077", "5053606", "5053643", "5055518", "5055612", "5058379", "5061768", "5061979", "5058481", "5060533", "5063159", "5061087", "5062554", "5062649", "5063709", "5066188", "5063842", "5065429", "5066198", "5066791"},
			},
		},
		{
			name: "10.0.19045.2130",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.19045.2130"}},
			},
			want: models.WindowsKB{
				Applied:   nil,
				Unapplied: []string{"5020953", "5019959", "5020030", "5021233", "5022282", "5019275", "5022834", "5022906", "5023696", "5023773", "5025221", "5025297", "5026361", "5026435", "5027215", "5027293", "5028166", "5028244", "5029244", "5029331", "5030211", "5030300", "5031356", "5031445", "5032189", "5032278", "5033372", "5034122", "5034203", "5034763", "5034843", "5035845", "5035941", "5036892", "5036979", "5037768", "5037849", "5039211", "5039299", "5040427", "5040525", "5041580", "5041582", "5043064", "5043131", "5044273", "5045594", "5046613", "5046714", "5048652", "5049981", "5050081", "5051974", "5052077", "5053606", "5053643", "5055518", "5055612", "5058379", "5061768", "5061979", "5058481", "5060533", "5063159", "5061087", "5062554", "5062649", "5063709", "5066188", "5063842", "5065429", "5066198", "5066791"},
			},
		},
		{
			name: "10.0.22621.1105",
			base: base{
				Distro:     config.Distro{Release: "Windows 11 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.22621.1105"}},
			},
			want: models.WindowsKB{
				Applied:   []string{"5019311", "5017389", "5018427", "5019509", "5018496", "5019980", "5020044", "5021255", "5022303"},
				Unapplied: []string{"5022360", "5022845", "5022913", "5023706", "5023778", "5025239", "5025305", "5026372", "5026446", "5027231", "5027303", "5028185", "5028254", "5029263", "5029351", "5030219", "5030310", "5031354", "5031455", "5032190", "5032288", "5033375", "5034123", "5034204", "5034765", "5034848", "5035853", "5035942", "5036893", "5036980", "5037771", "5037853", "5039212", "5039302", "5040442", "5040527", "5041585", "5041587", "5043076", "5043145", "5044285", "5044380", "5046633", "5046732", "5048685", "5050021", "5050092", "5051989", "5052094", "5053602", "5053657", "5055528", "5058919", "5055629", "5058405", "5058502", "5062170", "5060999", "5060826", "5062552", "5063875", "5066189", "5065431", "5066793"},
			},
		},
		{
			name: "10.0.20348.1547",
			base: base{
				Distro:     config.Distro{Release: "Windows Server 2022"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.20348.1547"}},
			},
			want: models.WindowsKB{
				Applied:   []string{"5005104", "5005575", "5005619", "5006699", "5006745", "5007205", "5007254", "5008223", "5010197", "5009555", "5010796", "5009608", "5010354", "5010421", "5011497", "5011558", "5012604", "5012637", "5013944", "5015013", "5014021", "5014678", "5014665", "5015827", "5015879", "5016627", "5016693", "5017316", "5017381", "5018421", "5020436", "5018485", "5019081", "5021656", "5020032", "5021249", "5022553", "5022291", "5022842"},
				Unapplied: []string{"5023705", "5025230", "5026370", "5027225", "5028171", "5029250", "5030216", "5031364", "5032198", "5033118", "5034129", "5034770", "5035857", "5037422", "5036909", "5037782", "5039227", "5041054", "5040437", "5041160", "5042881", "5044281", "5046616", "5048654", "5049983", "5051979", "5053603", "5055526", "5058920", "5059092", "5058385", "5061906", "5060526", "5062572", "5063880", "5065432", "5066782", "5070884"},
			},
		},
		{
			name: "10.0.20348.9999",
			base: base{
				Distro:     config.Distro{Release: "Windows Server 2022"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.20348.9999"}},
			},
			want: models.WindowsKB{
				Applied:   []string{"5005104", "5005575", "5005619", "5006699", "5006745", "5007205", "5007254", "5008223", "5010197", "5009555", "5010796", "5009608", "5010354", "5010421", "5011497", "5011558", "5012604", "5012637", "5013944", "5015013", "5014021", "5014678", "5014665", "5015827", "5015879", "5016627", "5016693", "5017316", "5017381", "5018421", "5020436", "5018485", "5019081", "5021656", "5020032", "5021249", "5022553", "5022291", "5022842", "5023705", "5025230", "5026370", "5027225", "5028171", "5029250", "5030216", "5031364", "5032198", "5033118", "5034129", "5034770", "5035857", "5037422", "5036909", "5037782", "5039227", "5041054", "5040437", "5041160", "5042881", "5044281", "5046616", "5048654", "5049983", "5051979", "5053603", "5055526", "5058920", "5059092", "5058385", "5061906", "5060526", "5062572", "5063880", "5065432", "5066782", "5070884"},
				Unapplied: nil,
			},
		},
		{
			name: "err",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{
				base: tt.base,
			}
			got, err := DetectKBsFromKernelVersion(o.getDistro().Release, o.Kernel.Version)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.detectKBsFromKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.detectKBsFromKernelVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_windows_parseIP(t *testing.T) {
	tests := []struct {
		name      string
		args      string
		ipv4Addrs []string
		ipv6Addrs []string
	}{
		{
			name: "en",
			args: `

Windows IP Configuration


Ethernet adapter イーサネット 4:

   Connection-specific DNS Suffix  . : vuls.local
   Link-local IPv6 Address . . . . . : fe80::19b6:ae27:d1fe:2041%33
   Link-local IPv6 Address . . . . . : fe80::7080:8828:5cc8:c0ba%33
   IPv4 Address. . . . . . . . . . . : 10.145.8.50
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : ::

Ethernet adapter イーサネット 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f49d:2c16:4270:759d%9
   IPv4 Address. . . . . . . . . . . : 192.168.56.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Wireless LAN adapter ローカル エリア接続* 1:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter ローカル エリア接続* 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.0.205
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.0.1

Ethernet adapter Bluetooth ネットワーク接続:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
`,
			ipv4Addrs: []string{"10.145.8.50", "192.168.56.1", "192.168.0.205"},
			ipv6Addrs: []string{"fe80::19b6:ae27:d1fe:2041", "fe80::7080:8828:5cc8:c0ba", "fe80::f49d:2c16:4270:759d"},
		},
		{
			name: "ja",
			args: `

Windows IP 構成


イーサネット アダプター イーサネット 4:

   接続固有の DNS サフィックス . . . . .: future.co.jp
   リンクローカル IPv6 アドレス. . . . .: fe80::19b6:ae27:d1fe:2041%33
   リンクローカル IPv6 アドレス. . . . .: fe80::7080:8828:5cc8:c0ba%33
   IPv4 アドレス . . . . . . . . . . . .: 10.145.8.50
   サブネット マスク . . . . . . . . . .: 255.255.0.0
   デフォルト ゲートウェイ . . . . . . .: ::

イーサネット アダプター イーサネット 2:

   接続固有の DNS サフィックス . . . . .:
   リンクローカル IPv6 アドレス. . . . .: fe80::f49d:2c16:4270:759d%9
   IPv4 アドレス . . . . . . . . . . . .: 192.168.56.1
   サブネット マスク . . . . . . . . . .: 255.255.255.0
   デフォルト ゲートウェイ . . . . . . .:

Wireless LAN adapter ローカル エリア接続* 1:

   メディアの状態. . . . . . . . . . . .: メディアは接続されていません
   接続固有の DNS サフィックス . . . . .:

Wireless LAN adapter ローカル エリア接続* 2:

   メディアの状態. . . . . . . . . . . .: メディアは接続されていません
   接続固有の DNS サフィックス . . . . .:

Wireless LAN adapter Wi-Fi:

   接続固有の DNS サフィックス . . . . .:
   IPv4 アドレス . . . . . . . . . . . .: 192.168.0.205
   サブネット マスク . . . . . . . . . .: 255.255.255.0
   デフォルト ゲートウェイ . . . . . . .: 192.168.0.1

イーサネット アダプター Bluetooth ネットワーク接続:

   メディアの状態. . . . . . . . . . . .: メディアは接続されていません
   接続固有の DNS サフィックス . . . . .:
`,
			ipv4Addrs: []string{"10.145.8.50", "192.168.56.1", "192.168.0.205"},
			ipv6Addrs: []string{"fe80::19b6:ae27:d1fe:2041", "fe80::7080:8828:5cc8:c0ba", "fe80::f49d:2c16:4270:759d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIPv4s, gotIPv6s := (&windows{}).parseIP(tt.args)
			if !reflect.DeepEqual(gotIPv4s, tt.ipv4Addrs) {
				t.Errorf("windows.parseIP() got = %v, want %v", gotIPv4s, tt.ipv4Addrs)
			}
			if !reflect.DeepEqual(gotIPv6s, tt.ipv6Addrs) {
				t.Errorf("windows.parseIP() got = %v, want %v", gotIPv6s, tt.ipv6Addrs)
			}
		})
	}
}
