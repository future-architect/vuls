package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"golang.org/x/exp/slices"
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
			name: "happy",
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
	type args struct {
		stdout string
		arch   string
	}
	tests := []struct {
		name    string
		args    args
		want    osInfo
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
ProductName               : Windows 10 Pro
CurrentVersion            : 6.3
CurrentMajorVersionNumber : 10
CurrentMinorVersionNumber : 0
CurrentBuildNumber        : 19044
UBR                       : 2364
EditionID                 : Professional
InstallationType          : Client`,
				arch: "AMD64",
			},
			want: osInfo{
				productName:      "Windows 10 Pro",
				version:          "10.0",
				build:            "19044",
				revision:         "2364",
				edition:          "Professional",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Client",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRegistry(tt.args.stdout, tt.args.arch)
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
			name: "Windows Server 2022",
			args: osInfo{
				productName:      "Windows Server",
				version:          "10.0",
				build:            "30000",
				revision:         "",
				edition:          "",
				servicePack:      "",
				arch:             "x64-based",
				installationType: "Server",
			},
			want: "Windows Server 2022",
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

func Test_windows_detectKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		base    base
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "major.minor.build, applied on 10",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.19045"}},
			},
			args: []string{"5020030", "5019275"},
			want: "10.0.19045.2546",
		},
		{
			name: "major.minor.build, zero applied on 10",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.19045"}},
			},
			args: []string{},
			want: "10.0.19045",
		},
		{
			name: "major.minor.build.revision",
			base: base{
				Distro:     config.Distro{Release: "Windows 10 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.19045.2130"}},
			},
			want: "10.0.19045.2130",
		},
		{
			name: "major.minor.build, applied on 11",
			base: base{
				Distro:     config.Distro{Release: "Windows 11 Version 22H2 for x64-based Systems"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.22621"}},
			},
			args: []string{"5017389", "5022303"},
			want: "10.0.22621.1105",
		},
		{
			name: "major.minor.build, applied on server 2022",
			base: base{
				Distro:     config.Distro{Release: "Windows Server 2022"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.20348"}},
			},
			args: []string{"5022842"},
			want: "10.0.20348.1547",
		},
		{
			name: "major.minor",
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
			got, err := o.detectKernelVersion(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.detectKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("windows.detectKernelVersion() = %v, want %v", got, tt.want)
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
				Unapplied: []string{"5020953", "5019959", "5020030", "5021233", "5022282", "5019275", "5022834", "5022906"},
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
				Unapplied: []string{"5020953", "5019959", "5020030", "5021233", "5022282", "5019275", "5022834", "5022906"},
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
				Unapplied: []string{"5022360", "5022845"},
			},
		},
		{
			name: "10.0.20348.1547",
			base: base{
				Distro:     config.Distro{Release: "Windows Server 2022"},
				osPackages: osPackages{Kernel: models.Kernel{Version: "10.0.20348.1547"}},
			},
			want: models.WindowsKB{
				Applied:   []string{"5005575", "5005619", "5006699", "5006745", "5007205", "5007254", "5008223", "5010197", "5009555", "5010796", "5009608", "5010354", "5010421", "5011497", "5011558", "5012604", "5012637", "5013944", "5015013", "5014021", "5014678", "5014665", "5015827", "5015879", "5016627", "5016693", "5017316", "5017381", "5018421", "5020436", "5018485", "5019081", "5021656", "5020032", "5021249", "5022553", "5022291", "5022842"},
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
			got, err := o.detectKBsFromKernelVersion()
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
