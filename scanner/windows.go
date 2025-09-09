package scanner

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ufilepath "github.com/future-architect/vuls/scanner/utils/filepath/windows"
)

// inherit OsTypeInterface
type windows struct {
	base
	shell string
}

type osInfo struct {
	productName      string
	version          string
	build            string
	revision         string
	edition          string
	servicePack      string
	arch             string
	installationType string
}

func newWindows(c config.ServerInfo) *windows {
	d := &windows{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
		shell: "unknown",
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func detectWindows(c config.ServerInfo) (bool, osTypeInterface) {
	tmp := c
	tmp.Distro.Family = constant.Windows
	w := newWindows(tmp)
	w.shell = func() string {
		if r := w.exec("echo $env:OS", noSudo); r.isSuccess() {
			switch strings.TrimSpace(r.Stdout) {
			case "$env:OS":
				return "cmd.exe"
			case "Windows_NT":
				return "powershell"
			default:
				if rr := w.exec("Get-ChildItem env:OS", noSudo); rr.isSuccess() {
					return "powershell"
				}
				return "unknown"
			}
		}
		return "unknown"
	}()

	if r := w.exec(w.translateCmd(`Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" | Format-List -Property ProductName, CurrentVersion, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentBuildNumber, UBR, CSDVersion, EditionID, InstallationType; Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" | Format-List -Property PROCESSOR_ARCHITECTURE`), noSudo); r.isSuccess() {
		osInfo, err := parseRegistry(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse Registry. err: %w", err)})
			return true, w
		}

		logging.Log.Debugf("osInfo(Registry): %+v", osInfo)
		release, err := detectOSName(osInfo)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to detect os name. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
		w.Kernel = models.Kernel{Version: formatKernelVersion(osInfo)}
		return true, w
	}

	if r := w.exec(w.translateCmd(`$ProgressPreference = "SilentlyContinue"; Get-ComputerInfo -Property WindowsProductName, OsVersion, WindowsEditionId, OsCSDVersion, CsSystemType, WindowsInstallationType`), noSudo); r.isSuccess() {
		osInfo, err := parseGetComputerInfo(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse Get-ComputerInfo. err: %w", err)})
			return true, w
		}

		logging.Log.Debugf("osInfo(Get-ComputerInfo): %+v", osInfo)
		release, err := detectOSName(osInfo)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to detect os name. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
		w.Kernel = models.Kernel{Version: formatKernelVersion(osInfo)}
		return true, w
	}

	if r := w.exec(w.translateCmd("Get-WmiObject Win32_OperatingSystem | Format-List -Property Caption, Version, OperatingSystemSKU, CSDVersion; Get-WmiObject Win32_ComputerSystem | Format-List -Property SystemType, DomainRole"), noSudo); r.isSuccess() {
		osInfo, err := parseWmiObject(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse Get-WmiObject. err: %w", err)})
			return true, w
		}

		logging.Log.Debugf("osInfo(Get-WmiObject): %+v", osInfo)
		release, err := detectOSName(osInfo)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to detect os name. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
		w.Kernel = models.Kernel{Version: formatKernelVersion(osInfo)}
		return true, w
	}

	if r := w.exec("systeminfo.exe", noSudo); r.isSuccess() {
		osInfo, _, err := parseSystemInfo(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse systeminfo.exe. err: %w", err)})
			return true, w
		}

		logging.Log.Debugf("osInfo(systeminfo.exe): %+v", osInfo)
		release, err := detectOSName(osInfo)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to detect os name. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
		w.Kernel = models.Kernel{Version: formatKernelVersion(osInfo)}
		return true, w
	}

	return false, nil
}

func (w *windows) translateCmd(cmd string) string {
	switch w.shell {
	case "cmd.exe":
		return fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive "%s"`, strings.ReplaceAll(cmd, `"`, `\"`))
	case "powershell":
		return cmd
	default: // not tested with bash etc
		return fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive "%s"`, strings.ReplaceAll(cmd, `"`, `\"`))
	}
}

func parseSystemInfo(stdout string) (osInfo, []string, error) {
	var (
		o   osInfo
		kbs []string
	)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "OS 名:"):
			line = strings.NewReplacer("OS 名:", "OS Name:").Replace(line)
		case strings.HasPrefix(line, "OS バージョン:"):
			line = strings.NewReplacer("OS バージョン:", "OS Version:", "ビルド", "Build").Replace(line)
		case strings.HasPrefix(line, "システムの種類:"):
			line = strings.NewReplacer("システムの種類:", "System Type:").Replace(line)
		case strings.HasPrefix(line, "OS 構成:"):
			line = strings.NewReplacer("OS 構成:", "OS Configuration:", "サーバー", "Server", "ワークステーション", "Workstation").Replace(line)
		case strings.HasPrefix(line, "ホットフィックス:"):
			line = strings.NewReplacer("ホットフィックス:", "Hotfix(s):", "ホットフィックスがインストールされています。", "Hotfix(s) Installed.").Replace(line)
		default:
		}

		switch {
		case strings.HasPrefix(line, "OS Name:"):
			o.productName = strings.TrimSpace(strings.TrimPrefix(line, "OS Name:"))
		case strings.HasPrefix(line, "OS Version:"):
			s := strings.TrimSpace(strings.TrimPrefix(line, "OS Version:"))
			lhs, build, _ := strings.Cut(s, " Build ")
			vb, sp, _ := strings.Cut(lhs, " ")
			o.version = strings.TrimSuffix(vb, fmt.Sprintf(".%s", build))
			o.build = build
			if sp != "N/A" {
				o.servicePack = sp
			}
		case strings.HasPrefix(line, "System Type:"):
			o.arch = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "System Type:"), "PC"))
		case strings.HasPrefix(line, "OS Configuration:"):
			switch {
			case strings.Contains(line, "Server"):
				o.installationType = "Server"
			case strings.Contains(line, "Workstation"):
				o.installationType = "Client"
			case strings.Contains(line, "Domain Controller"):
				o.installationType = "Domain Controller"
			default:
				return osInfo{}, nil, xerrors.Errorf("Failed to detect installation type. line: %s", line)
			}
		case strings.HasPrefix(line, "Hotfix(s):"):
			nKB, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "Hotfix(s):"), "Hotfix(s) Installed.")))
			if err != nil {
				return osInfo{}, nil, xerrors.Errorf("Failed to detect number of installed hotfix from %s", line)
			}
			for i := 0; i < nKB; i++ {
				scanner.Scan()
				line := scanner.Text()
				_, rhs, found := strings.Cut(line, ":")
				if !found {
					continue
				}
				s := strings.TrimSpace(rhs)
				if strings.HasPrefix(s, "KB") {
					kbs = append(kbs, strings.TrimPrefix(s, "KB"))
				}
			}
		default:
		}
	}
	return o, kbs, nil
}

func parseGetComputerInfo(stdout string) (osInfo, error) {
	var o osInfo
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "WindowsProductName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect ProductName. expected: "WindowsProductName : <ProductName>", line: "%s"`, line)
			}
			o.productName = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "OsVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect OsVersion. expected: "OsVersion : <Version>", line: "%s"`, line)
			}
			ss := strings.Split(strings.TrimSpace(rhs), ".")
			o.version = strings.Join(ss[0:len(ss)-1], ".")
			o.build = ss[len(ss)-1]
		case strings.HasPrefix(line, "WindowsEditionId"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect WindowsEditionId. expected: "WindowsEditionId : <EditionId>", line: "%s"`, line)
			}
			o.edition = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "OsCSDVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect OsCSDVersion. expected: "OsCSDVersion : <CSDVersion>", line: "%s"`, line)
			}
			o.servicePack = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CsSystemType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CsSystemType. expected: "CsSystemType : <SystemType>", line: "%s"`, line)
			}
			o.arch = strings.TrimSpace(strings.TrimSuffix(rhs, "PC"))
		case strings.HasPrefix(line, "WindowsInstallationType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect WindowsInstallationType. expected: "WindowsInstallationType : <InstallationType>", line: "%s"`, line)
			}
			o.installationType = strings.TrimSpace(rhs)
		default:
		}
	}
	return o, nil
}

func parseWmiObject(stdout string) (osInfo, error) {
	var o osInfo
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "Caption"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect Caption. expected: "Caption : <Caption>", line: "%s"`, line)
			}
			o.productName = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Version"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect Version. expected: "Version : <Version>", line: "%s"`, line)
			}
			ss := strings.Split(strings.TrimSpace(rhs), ".")
			o.version = strings.Join(ss[0:len(ss)-1], ".")
			o.build = ss[len(ss)-1]
		case strings.HasPrefix(line, "OperatingSystemSKU"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect OperatingSystemSKU. expected: "OperatingSystemSKU : <OperatingSystemSKU>", line: "%s"`, line)
			}
			switch n := strings.TrimSpace(rhs); n {
			case "0":
				o.edition = "Undefined"
			case "1":
				o.edition = "Ultimate"
				o.installationType = "Client"
			case "2":
				o.edition = "Home Basic"
				o.installationType = "Client"
			case "3":
				o.edition = "Home Premium"
				o.installationType = "Client"
			case "4":
				o.edition = "Enterprise"
				o.installationType = "Client"
			case "6":
				o.edition = "Business"
				o.installationType = "Client"
			case "7":
				o.edition = "Windows Server Standard Edition (Desktop Experience installation)"
				o.installationType = "Server"
			case "8":
				o.edition = "Windows Server Datacenter Edition (Desktop Experience installation)"
				o.installationType = "Server"
			case "9":
				o.edition = "Small Business Server"
				o.installationType = "Server"
			case "10":
				o.edition = "Enterprise Server"
				o.installationType = "Server"
			case "11":
				o.edition = "Starter"
			case "12":
				o.edition = "Datacenter Server Core"
				o.installationType = "Server Core"
			case "13":
				o.edition = "Standard Server Core"
				o.installationType = "Server Core"
			case "14":
				o.edition = "Enterprise Server Core"
				o.installationType = "Server Core"
			case "17":
				o.edition = "Web Server"
				o.installationType = "Server"
			case "19":
				o.edition = "Home Server"
				o.installationType = "Server"
			case "20":
				o.edition = "Storage Express Server"
				o.installationType = "Server"
			case "21":
				o.edition = "Windows Storage Server Standard"
				o.installationType = "Server"
			case "22":
				o.edition = "Windows Storage Server Workgroup"
				o.installationType = "Server"
			case "23":
				o.edition = "Storage Enterprise Server"
				o.installationType = "Server"
			case "24":
				o.edition = "Server For Small Business"
				o.installationType = "Server"
			case "25":
				o.edition = "Small Business Server Premium"
				o.installationType = "Server"
			case "27":
				o.edition = "Enterprise"
				o.installationType = "Client"
			case "28":
				o.edition = "Ultimate"
				o.installationType = "Client"
			case "29":
				o.edition = "Windows Server Web Server Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "36":
				o.edition = "Windows Server Standard Edition without Hyper-V"
				o.installationType = "Server"
			case "37":
				o.edition = "Windows Server Datacenter Edition without Hyper-V (full installation)"
				o.installationType = "Server"
			case "38":
				o.edition = "Windows Server Enterprise Edition without Hyper-V (full installation)"
				o.installationType = "Server"
			case "39":
				o.edition = "Windows Server Datacenter Edition without Hyper-V (Server Core installation)"
				o.installationType = "Server Core"
			case "40":
				o.edition = "Windows Server Standard Edition without Hyper-V (Server Core installation)"
				o.installationType = "Server Core"
			case "41":
				o.edition = "Windows Server Enterprise Edition without Hyper-V (Server Core installation)"
				o.installationType = "Server Core"
			case "42":
				o.edition = "Microsoft Hyper-V Server"
				o.installationType = "Server"
			case "43":
				o.edition = "Storage Server Express Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "44":
				o.edition = "Storage Server Standard Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "45":
				o.edition = "Storage Server Workgroup Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "46":
				o.edition = "Storage Server Enterprise Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "48":
				o.edition = "Professional"
				o.installationType = "Client"
			case "50":
				o.edition = "Windows Server Essentials (Desktop Experience installation)"
				o.installationType = "Server"
			case "63":
				o.edition = "Small Business Server Premium (Server Core installation)"
				o.installationType = "Server Core"
			case "64":
				o.edition = "Windows Compute Cluster Server without Hyper-V"
				o.installationType = "Server"
			case "97":
				o.edition = "Windows RT"
				o.installationType = "Client"
			case "101":
				o.edition = "Home"
				o.installationType = "Client"
			case "103":
				o.edition = "Media Center"
				o.installationType = "Client"
			case "104":
				o.edition = "Mobile"
				o.installationType = "Client"
			case "123":
				o.edition = "Windows IoT (Internet of Things) Core"
				o.installationType = "Client"
			case "143":
				o.edition = "Windows Server Datacenter Edition (Nano Server installation)"
				o.installationType = "Server"
			case "144":
				o.edition = "Windows Server Standard Edition (Nano Server installation)"
				o.installationType = "Server"
			case "147":
				o.edition = "Windows Server Datacenter Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "148":
				o.edition = "Windows Server Standard Edition (Server Core installation)"
				o.installationType = "Server Core"
			case "175":
				o.edition = "Windows Enterprise for Virtual Desktops (Azure Virtual Desktop)"
				o.installationType = "Client"
			default:
			}

		case strings.HasPrefix(line, "CSDVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CSDVersion. expected: "CSDVersion : <CSDVersion>", line: "%s"`, line)
			}
			o.servicePack = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "SystemType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect SystemType. expected: "SystemType : <SystemType>", line: "%s"`, line)
			}
			o.arch = strings.TrimSpace(strings.TrimSuffix(rhs, "PC"))
		case strings.HasPrefix(line, "DomainRole"):
			if o.installationType != "" {
				break
			}

			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect DomainRole. expected: "DomainRole : <DomainRole>", line: "%s"`, line)
			}
			switch domainRole := strings.TrimSpace(rhs); domainRole { // https://learn.microsoft.com/en-us/windows/win32/api/dsrole/ne-dsrole-dsrole_machine_role
			case "0", "1":
				o.installationType = "Client"
			case "2", "3":
				o.installationType = "Server"
			case "4", "5":
				o.installationType = "Domain Controller"
			default:
				return osInfo{}, xerrors.Errorf("Failed to detect Installation Type from DomainRole. err: %s is invalid DomainRole", domainRole)
			}
		default:
		}
	}
	return o, nil
}

func parseRegistry(stdout string) (osInfo, error) {
	var (
		o     osInfo
		major string
		minor string
	)

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "ProductName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect ProductName. expected: "ProductName : <ProductName>", line: "%s"`, line)
			}
			o.productName = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CurrentVersion. expected: "CurrentVersion : <Version>", line: "%s"`, line)
			}
			o.version = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentMajorVersionNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CurrentMajorVersionNumber. expected: "CurrentMajorVersionNumber : <Version>", line: "%s"`, line)
			}
			major = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentMinorVersionNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CurrentMinorVersionNumber. expected: "CurrentMinorVersionNumber : <Version>", line: "%s"`, line)
			}
			minor = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentBuildNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CurrentBuildNumber. expected: "CurrentBuildNumber : <Build>", line: "%s"`, line)
			}
			o.build = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "UBR"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect UBR. expected: "UBR : <Revision>", line: "%s"`, line)
			}
			o.revision = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "EditionID"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect EditionID. expected: "EditionID : <EditionID>", line: "%s"`, line)
			}
			o.edition = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CSDVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect CSDVersion. expected: "CSDVersion : <CSDVersion>", line: "%s"`, line)
			}
			o.servicePack = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "InstallationType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect InstallationType. expected: "InstallationType : <InstallationType>", line: "%s"`, line)
			}
			o.installationType = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "PROCESSOR_ARCHITECTURE"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return osInfo{}, xerrors.Errorf(`Failed to detect PROCESSOR_ARCHITECTURE. expected: "PROCESSOR_ARCHITECTURE : <PROCESSOR_ARCHITECTURE>", line: "%s"`, line)
			}
			o.arch = strings.TrimSpace(rhs)
		default:
		}
	}
	if major != "" && minor != "" {
		o.version = fmt.Sprintf("%s.%s", major, minor)
	}

	return o, nil
}

func detectOSName(osInfo osInfo) (string, error) {
	osName, err := detectOSNameFromOSInfo(osInfo)
	if err != nil {
		return "", xerrors.Errorf("Failed to detect OS Name from OSInfo: %+v, err: %w", osInfo, err)
	}
	return osName, nil
}

func detectOSNameFromOSInfo(osInfo osInfo) (string, error) {
	switch osInfo.version {
	case "5.0":
		switch osInfo.installationType {
		case "Client":
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 %s", osInfo.servicePack), nil
			}
			return "Microsoft Windows 2000", nil
		case "Server", "Domain Controller":
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 Server %s", osInfo.servicePack), nil
			}
			return "Microsoft Windows 2000 Server", nil
		}
	case "5.1":
		switch osInfo.installationType {
		case "Client":
			var n string
			switch osInfo.edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}

			switch arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		}
	case "5.2":
		switch osInfo.installationType {
		case "Client":
			var n string
			switch osInfo.edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			switch arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server", "Domain Controller":
			n := "Microsoft Windows Server 2003"
			if strings.Contains(osInfo.productName, "R2") {
				n = "Microsoft Windows Server 2003 R2"
			}
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			switch arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			case "Itanium-based":
				if osInfo.edition == "Enterprise" {
					n = fmt.Sprintf("%s, Enterprise Edition for Itanium-based Systems", n)
				} else {
					n = fmt.Sprintf("%s for Itanium-based Systems", n)
				}
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		}
	case "6.0":
		switch osInfo.installationType {
		case "Client":
			var n string
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			switch arch {
			case "x64-based":
				n = "Windows Vista x64 Editions"
			default:
				n = "Windows Vista"
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server", "Domain Controller":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s (Server Core installation)", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.1":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows 7 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows 7 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s (Server Core installation)", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.2":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			return fmt.Sprintf("Windows 8 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			return "Windows Server 2012", nil
		case "Server Core":
			return "Windows Server 2012 (Server Core installation)", nil
		}
	case "6.3":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			return fmt.Sprintf("Windows 8.1 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			return "Windows Server 2012 R2", nil
		case "Server Core":
			return "Windows Server 2012 R2 (Server Core installation)", nil
		}
	case "10.0":
		switch osInfo.installationType {
		case "Client":
			if strings.Contains(osInfo.productName, "Windows 11") {
				arch, err := formatArch(osInfo.arch)
				if err != nil {
					return "", xerrors.Errorf("Failed to format architecture: %w", err)
				}
				name, err := formatNamebyBuild("11", osInfo.build)
				if err != nil {
					return "", xerrors.Errorf("Failed to format name by build: %w", err)
				}
				return fmt.Sprintf("%s for %s Systems", name, arch), nil
			}

			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", xerrors.Errorf("Failed to format architecture: %w", err)
			}
			name, err := formatNamebyBuild("10", osInfo.build)
			if err != nil {
				return "", xerrors.Errorf("Failed to format name by build: %w", err)
			}
			return fmt.Sprintf("%s for %s Systems", name, arch), nil
		case "Server", "Nano Server", "Domain Controller":
			return formatNamebyBuild("Server", osInfo.build)
		case "Server Core":
			name, err := formatNamebyBuild("Server", osInfo.build)
			if err != nil {
				return "", xerrors.Errorf("Failed to format name by build: %w", err)
			}
			return fmt.Sprintf("%s (Server Core installation)", name), nil
		}
	}
	return "", xerrors.New("OS Name not found")
}

func formatArch(arch string) (string, error) {
	switch arch {
	case "AMD64", "x64-based":
		return "x64-based", nil
	case "ARM64", "ARM64-based":
		return "ARM64-based", nil
	case "IA64", "Itanium-based":
		return "Itanium-based", nil
	case "x86", "X86-based":
		return "32-bit", nil
	default:
		return "", xerrors.Errorf("CPU Architecture not found. expected: %q, actual: %q", []string{"AMD64", "x64-based", "ARM64", "ARM64-based", "IA64", "Itanium-based", "x86", "X86-based"}, arch)
	}
}

type buildNumber struct {
	build string
	name  string
}

var (
	winBuilds = map[string][]buildNumber{
		"10": {
			{
				build: "10240",
				name:  "Windows 10", // not "Windows 10 Version 1507"
			},
			{
				build: "10586",
				name:  "Windows 10 Version 1511",
			},
			{
				build: "14393",
				name:  "Windows 10 Version 1607",
			},
			{
				build: "15063",
				name:  "Windows 10 Version 1703",
			},
			{
				build: "16299",
				name:  "Windows 10 Version 1709",
			},
			{
				build: "17134",
				name:  "Windows 10 Version 1803",
			},
			{
				build: "17763",
				name:  "Windows 10 Version 1809",
			},
			{
				build: "18362",
				name:  "Windows 10 Version 1903",
			},
			{
				build: "18363",
				name:  "Windows 10 Version 1909",
			},
			{
				build: "19041",
				name:  "Windows 10 Version 2004",
			},
			{
				build: "19042",
				name:  "Windows 10 Version 20H2",
			},
			{
				build: "19043",
				name:  "Windows 10 Version 21H1",
			},
			{
				build: "19044",
				name:  "Windows 10 Version 21H2",
			},
			{
				build: "19045",
				name:  "Windows 10 Version 22H2",
			},
			// It seems that there are cases where the Product Name is Windows 10 even though it is Windows 11
			// ref: https://docs.microsoft.com/en-us/answers/questions/586548/in-the-official-version-of-windows-11-why-the-key.html
			{
				build: "22000",
				name:  "Windows 11 Version 21H2",
			},
			{
				build: "22621",
				name:  "Windows 11 Version 22H2",
			},
			{
				build: "22631",
				name:  "Windows 11 Version 23H2",
			},
			{
				build: "26100",
				name:  "Windows 11 Version 24H2",
			},
		},
		"11": {
			{
				build: "22000",
				name:  "Windows 11 Version 21H2",
			},
			{
				build: "22621",
				name:  "Windows 11 Version 22H2",
			},
			{
				build: "22631",
				name:  "Windows 11 Version 23H2",
			},
			{
				build: "26100",
				name:  "Windows 11 Version 24H2",
			},
		},
		"Server": {
			{
				build: "14393",
				name:  "Windows Server 2016",
			},
			{
				build: "16299",
				name:  "Windows Server, Version 1709",
			},
			{
				build: "17134",
				name:  "Windows Server, Version 1803",
			},
			{
				build: "17763",
				name:  "Windows Server, Version 1809",
			},
			{
				build: "17763",
				name:  "Windows Server 2019",
			},
			{
				build: "18362",
				name:  "Windows Server, Version 1903",
			},
			{
				build: "18363",
				name:  "Windows Server, Version 1909",
			},
			{
				build: "19041",
				name:  "Windows Server, Version 2004",
			},
			{
				build: "19042",
				name:  "Windows Server, Version 20H2",
			},
			{
				build: "20348",
				name:  "Windows Server 2022",
			},
			{
				build: "25398",
				name:  "Windows Server 2022, 23H2 Edition", // https://support.microsoft.com/en-us/topic/windows-server-version-23h2-update-history-68c851ff-825a-4dbc-857b-51c5aa0ab248
			},
			{
				build: "26100",
				name:  "Windows Server 2025",
			},
		},
	}
)

func formatNamebyBuild(osType string, mybuild string) (string, error) {
	builds, ok := winBuilds[osType]
	if !ok {
		return "", xerrors.New("OS Type not found")
	}

	nMybuild, err := strconv.Atoi(mybuild)
	if err != nil {
		return "", xerrors.Errorf("Failed to parse build number. err: %w", err)
	}

	v := builds[0].name
	for _, b := range builds {
		nBuild, err := strconv.Atoi(b.build)
		if err != nil {
			return "", xerrors.Errorf("Failed to parse build number. err: %w", err)
		}
		if nMybuild < nBuild {
			break
		}
		v = b.name
	}
	return v, nil
}

func formatKernelVersion(osInfo osInfo) string {
	v := fmt.Sprintf("%s.%s", osInfo.version, osInfo.build)
	if osInfo.revision != "" {
		v = fmt.Sprintf("%s.%s", v, osInfo.revision)
	}
	return v
}

func (w *windows) checkScanMode() error {
	return nil
}

func (w *windows) checkIfSudoNoPasswd() error {
	return nil
}

func (w *windows) checkDeps() error {
	return nil
}

func (w *windows) preCure() error {
	if err := w.detectIPAddr(); err != nil {
		w.log.Warnf("Failed to detect IP addresses: %s", err)
		w.warns = append(w.warns, err)
	}
	return nil
}

func (w *windows) postScan() error {
	return nil
}

func (w *windows) detectIPAddr() error {
	var err error
	w.ServerInfo.IPv4Addrs, w.ServerInfo.IPv6Addrs, err = w.ip()
	return err
}

func (w *windows) ip() ([]string, []string, error) {
	r := w.exec("ipconfig.exe", noSudo)
	if !r.isSuccess() {
		return nil, nil, xerrors.Errorf("Failed to detect IP address: %v", r)
	}
	ipv4Addrs, ipv6Addrs := w.parseIP(r.Stdout)
	return ipv4Addrs, ipv6Addrs, nil
}

func (w *windows) parseIP(stdout string) ([]string, []string) {
	var ipv4Addrs, ipv6Addrs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		lhs, rhs, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(lhs, "IPv4 Address"), strings.Contains(lhs, "Autoconfiguration IPv4 Address"), strings.HasPrefix(lhs, "IPv4 アドレス"), strings.HasPrefix(lhs, "自動構成 IPv4 アドレス"):
			rhs = strings.NewReplacer("(Duplicate)", "", "(Preferred)", "", "(重複)", "", "(優先)", "").Replace(rhs)
			if ip := net.ParseIP(strings.TrimSpace(rhs)); ip != nil {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			}
		case strings.HasPrefix(lhs, "IPv6 Address"), strings.HasPrefix(lhs, "Temporary IPv6 Address"), strings.HasPrefix(lhs, "IPv6 アドレス"), strings.HasPrefix(lhs, "一時 IPv6 アドレス"):
			if ip := net.ParseIP(strings.TrimSpace(rhs)); ip != nil {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		case strings.HasPrefix(lhs, "Link-local IPv6 Address"), strings.HasPrefix(lhs, "リンクローカル IPv6 アドレス"):
			lhs, _, ok := strings.Cut(rhs, "%")
			if !ok {
				break
			}
			if ip := net.ParseIP(strings.TrimSpace(lhs)); ip != nil {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		default:
		}
	}
	return ipv4Addrs, ipv6Addrs
}

func (w *windows) scanPackages() error {
	if r := w.exec(w.translateCmd("Get-Package | Format-List -Property Name, Version, ProviderName"), noSudo); r.isSuccess() {
		installed, _, err := w.parseInstalledPackages(r.Stdout)
		if err != nil {
			return xerrors.Errorf("Failed to parse installed packages. err: %w", err)
		}
		w.Packages = installed
	}

	kbs, err := w.scanKBs()
	if err != nil {
		return xerrors.Errorf("Failed to scan KB. err: %w", err)
	}
	w.windowsKB = kbs

	return nil
}

func (w *windows) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	installed := models.Packages{}

	var name, version string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			name, version = "", ""
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}
			name = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Version"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect Version. expected: "Version : <Version>", line: "%s"`, line)
			}
			version = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ProviderName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect ProviderName. expected: "ProviderName : <ProviderName>", line: "%s"`, line)
			}

			switch strings.TrimSpace(rhs) {
			case "msu":
			default:
				if name != "" {
					installed[name] = models.Package{Name: name, Version: version}
				}
			}
		default:
		}
	}

	return installed, nil, nil
}

func (w *windows) scanKBs() (*models.WindowsKB, error) {
	applied, unapplied := map[string]struct{}{}, map[string]struct{}{}

	if r := w.exec(w.translateCmd("Get-Hotfix | Format-List -Property HotFixID"), noSudo); r.isSuccess() {
		kbs, err := w.parseGetHotfix(r.Stdout)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse Get-Hotifx. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	if r := w.exec(w.translateCmd("Get-Package -ProviderName msu | Format-List -Property Name"), noSudo); r.isSuccess() {
		kbs, err := w.parseGetPackageMSU(r.Stdout)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse Get-Package. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	if err := func() error {
		var searcher string
		switch c := w.getServerInfo(); c.Windows.ServerSelection {
		case 3: // https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline
			searcher = fmt.Sprintf(`$UpdateSession = (New-Object -ComObject Microsoft.Update.Session); $UpdateServiceManager = (New-Object -ComObject Microsoft.Update.ServiceManager); $UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", "%s"); $UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); $UpdateSearcher.ServerSelection = %d; $UpdateSearcher.ServiceID = $UpdateService.ServiceID;`, c.Windows.CabPath, c.Windows.ServerSelection)
		default:
			if c.Mode.IsOffline() {
				return nil
			}
			searcher = fmt.Sprintf("$UpdateSession = (New-Object -ComObject Microsoft.Update.Session); $UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); $UpdateSearcher.ServerSelection = %d;", c.Windows.ServerSelection)
		}
		if r := w.exec(w.translateCmd(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 0 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)), noSudo); r.isSuccess() {
			kbs, err := w.parseWindowsUpdaterSearch(r.Stdout)
			if err != nil {
				return xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
			}
			for _, kb := range kbs {
				applied[kb] = struct{}{}
			}
		}

		if r := w.exec(w.translateCmd(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 0 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)), noSudo); r.isSuccess() {
			kbs, err := w.parseWindowsUpdaterSearch(r.Stdout)
			if err != nil {
				return xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
			}
			for _, kb := range kbs {
				unapplied[kb] = struct{}{}
			}
		}

		if r := w.exec(w.translateCmd(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 1 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)), noSudo); r.isSuccess() {
			kbs, err := w.parseWindowsUpdaterSearch(r.Stdout)
			if err != nil {
				return xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
			}
			for _, kb := range kbs {
				unapplied[kb] = struct{}{}
			}
		}

		if w.getServerInfo().Windows.ServerSelection == 3 {
			if r := w.exec(w.translateCmd(`$UpdateServiceManager = (New-Object -ComObject Microsoft.Update.ServiceManager); $UpdateServiceManager.Services | Where-Object {$_.Name -eq "Offline Sync Service"} | ForEach-Object { $UpdateServiceManager.RemoveService($_.ServiceID) };`), noSudo); !r.isSuccess() {
				return xerrors.Errorf("Failed to remove Windows Update Offline Sync Service: %v", r)
			}
		}

		return nil
	}(); err != nil {
		return nil, xerrors.Errorf("Failed to check Windows Update Serach. err: %w", err)
	}

	if r := w.exec(w.translateCmd("$UpdateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $HistoryCount = $UpdateSearcher.GetTotalHistoryCount(); $UpdateSearcher.QueryHistory(0, $HistoryCount) | Sort-Object -Property Date | Format-List -Property Title, Operation, ResultCode"), noSudo); r.isSuccess() {
		kbs, err := w.parseWindowsUpdateHistory(r.Stdout)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse Windows Update History. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	kbs, err := DetectKBsFromKernelVersion(w.getDistro().Release, w.Kernel.Version)
	if err != nil {
		return nil, xerrors.Errorf("Failed to detect KBs from kernel version. err: %w", err)
	}
	for _, kb := range kbs.Applied {
		applied[kb] = struct{}{}
	}
	for _, kb := range kbs.Unapplied {
		unapplied[kb] = struct{}{}
	}

	return &models.WindowsKB{Applied: slices.Collect(maps.Keys(applied)), Unapplied: slices.Collect(maps.Keys(unapplied))}, nil
}

func (w *windows) parseGetHotfix(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "HotFixID"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect HotFixID. expected: "HotFixID : <KBID>", line: "%s"`, line)
			}
			kbs = append(kbs, strings.TrimPrefix(strings.TrimSpace(rhs), "KB"))
		default:
		}
	}

	return kbs, nil
}

func (w *windows) parseGetPackageMSU(stdout string) ([]string, error) {
	var kbs []string

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}

			for _, m := range kbIDPattern.FindAllStringSubmatch(strings.TrimSpace(rhs), -1) {
				kbs = append(kbs, m[1])
			}
		default:
		}
	}

	return kbs, nil
}

func (w *windows) parseWindowsUpdaterSearch(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			kbs = append(kbs, line)
		}
	}

	return kbs, nil
}

func (w *windows) parseWindowsUpdateHistory(stdout string) ([]string, error) {
	kbs := map[string]struct{}{}

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	var title, operation string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			title, operation = "", ""
		case strings.HasPrefix(line, "Title"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Title. expected: "Title : <Title>", line: "%s"`, line)
			}
			title = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Operation"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Operation. expected: "Operation : <Operation>", line: "%s"`, line)
			}
			operation = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ResultCode"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect ResultCode. expected: "ResultCode : <ResultCode>", line: "%s"`, line)
			}

			// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode
			if strings.TrimSpace(rhs) == "2" {
				for _, m := range kbIDPattern.FindAllStringSubmatch(title, -1) {
					// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-updateoperation
					switch operation {
					case "1":
						kbs[m[1]] = struct{}{}
					case "2":
						delete(kbs, m[1])
					default:
					}
				}
			}
		default:
		}
	}

	return slices.Collect(maps.Keys(kbs)), nil
}

type windowsRelease struct {
	revision string
	kb       string
}

type updateProgram struct {
	rollup       []windowsRelease
	securityOnly []string
}

var windowsReleases = map[string]map[string]updateProgram{
	"Windows 7": {
		// https://support.microsoft.com/en-us/topic/windows-7-sp1-and-windows-server-2008-r2-sp1-update-history-720c2590-fd58-26ba-16cc-6d8f3b547599
		"SP1": {
			rollup: []windowsRelease{
				{revision: "", kb: "3172605"},
				{revision: "", kb: "3179573"},
				{revision: "", kb: "3185278"},
				{revision: "", kb: "3185330"},
				{revision: "", kb: "3192403"},
				{revision: "", kb: "3197868"},
				{revision: "", kb: "3197869"},
				{revision: "", kb: "3207752"},
				{revision: "", kb: "3212646"},
				{revision: "", kb: "4012215"},
				{revision: "", kb: "4012218"},
				{revision: "", kb: "4015549"},
				{revision: "", kb: "4015552"},
				{revision: "", kb: "4019264"},
				{revision: "", kb: "4019265"},
				{revision: "", kb: "4022719"},
				{revision: "", kb: "4022168"},
				{revision: "", kb: "4025341"},
				{revision: "", kb: "4025340"},
				{revision: "", kb: "4034664"},
				{revision: "", kb: "4034670"},
				{revision: "", kb: "4038777"},
				{revision: "", kb: "4038803"},
				{revision: "", kb: "4041681"},
				{revision: "", kb: "4041686"},
				{revision: "", kb: "4048957"},
				{revision: "", kb: "4051034"},
				{revision: "", kb: "4054518"},
				{revision: "", kb: "4056894"},
				{revision: "", kb: "4057400"},
				{revision: "", kb: "4074598"},
				{revision: "", kb: "4075211"},
				{revision: "", kb: "4088875"},
				{revision: "", kb: "4088881"},
				{revision: "", kb: "4093118"},
				{revision: "", kb: "4093113"},
				{revision: "", kb: "4103718"},
				{revision: "", kb: "4103713"},
				{revision: "", kb: "4284826"},
				{revision: "", kb: "4284842"},
				{revision: "", kb: "4338818"},
				{revision: "", kb: "4338821"},
				{revision: "", kb: "4343900"},
				{revision: "", kb: "4343894"},
				{revision: "", kb: "4457144"},
				{revision: "", kb: "4457139"},
				{revision: "", kb: "4462923"},
				{revision: "", kb: "4462927"},
				{revision: "", kb: "4467107"},
				{revision: "", kb: "4467108"},
				{revision: "", kb: "4471318"},
				{revision: "", kb: "4480970"},
				{revision: "", kb: "4480955"},
				{revision: "", kb: "4486563"},
				{revision: "", kb: "4486565"},
				{revision: "", kb: "4489878"},
				{revision: "", kb: "4489892"},
				{revision: "", kb: "4493472"},
				{revision: "", kb: "4493453"},
				{revision: "", kb: "4499164"},
				{revision: "", kb: "4499178"},
				{revision: "", kb: "4503292"},
				{revision: "", kb: "4503277"},
				{revision: "", kb: "4507449"},
				{revision: "", kb: "4507437"},
				{revision: "", kb: "4512506"},
				{revision: "", kb: "4512514"},
				{revision: "", kb: "4516065"},
				{revision: "", kb: "4516048"},
				{revision: "", kb: "4524157"},
				{revision: "", kb: "4519976"},
				{revision: "", kb: "4519972"},
				{revision: "", kb: "4525235"},
				{revision: "", kb: "4525251"},
				{revision: "", kb: "4530734"},
				{revision: "", kb: "4534310"},
				{revision: "", kb: "4539601"},
				{revision: "", kb: "4537820"},
				{revision: "", kb: "4540688"},
				{revision: "", kb: "4550964"},
				{revision: "", kb: "4556836"},
				{revision: "", kb: "4561643"},
				{revision: "", kb: "4565524"},
				{revision: "", kb: "4571729"},
				{revision: "", kb: "4577051"},
				{revision: "", kb: "4580345"},
				{revision: "", kb: "4586827"},
				{revision: "", kb: "4592471"},
				{revision: "", kb: "4598279"},
				{revision: "", kb: "4601347"},
				{revision: "", kb: "5000841"},
				{revision: "", kb: "5001335"},
				{revision: "", kb: "5003233"},
				{revision: "", kb: "5003667"},
				{revision: "", kb: "5004953"},
				{revision: "", kb: "5004289"},
				{revision: "", kb: "5005088"},
				{revision: "", kb: "5005633"},
				{revision: "", kb: "5006743"},
				{revision: "", kb: "5007236"},
				{revision: "", kb: "5008244"},
				{revision: "", kb: "5009610"},
				{revision: "", kb: "5010404"},
				{revision: "", kb: "5011552"},
				{revision: "", kb: "5012626"},
				{revision: "", kb: "5014012"},
				{revision: "", kb: "5014748"},
				{revision: "", kb: "5015861"},
				{revision: "", kb: "5016676"},
				{revision: "", kb: "5017361"},
				{revision: "", kb: "5018454"},
				{revision: "", kb: "5020000"},
				{revision: "", kb: "5021291"},
				{revision: "", kb: "5022338"},
				{revision: "", kb: "5022872"},
				{revision: "", kb: "5023769"},
				{revision: "", kb: "5025279"},
				{revision: "", kb: "5026413"},
				{revision: "", kb: "5027275"},
				{revision: "", kb: "5028240"},
				{revision: "", kb: "5029296"},
				{revision: "", kb: "5030265"},
				{revision: "", kb: "5031408"},
				{revision: "", kb: "5032252"},
				{revision: "", kb: "5033433"},
				{revision: "", kb: "5034169"},
			},
			securityOnly: []string{
				"3192391",
				"3197867",
				"3205394",
				"3212642",
				"4012212",
				"4015546",
				"4019263",
				"4022722",
				"4025337",
				"4034679",
				"4038779",
				"4041678",
				"4048960",
				"4054521",
				"4056897",
				"4074587",
				"4088878",
				"4093108",
				"4103712",
				"4284867",
				"4338823",
				"4343899",
				"4457145",
				"4462915",
				"4467106",
				"4471328",
				"4480960",
				"4486564",
				"4489885",
				"4493448",
				"4499175",
				"4503269",
				"4507456",
				"4512486",
				"4516033",
				"4520003",
				"4525233",
				"4530692",
				"4534314",
				"4537813",
				"4541500",
				"4550965",
				"4556843",
				"4561669",
				"4565539",
				"4571719",
				"4577053",
				"4580387",
				"4586805",
				"4592503",
				"4598289",
				"4601363",
				"5000851",
				"5001392",
				"5003228",
				"5003694",
				"5004951",
				"5004307",
				"5005089",
				"5005615",
				"5006728",
				"5007233",
				"5008282",
				"5009621",
				"5010422",
				"5011529",
				"5012649",
				"5013999",
				"5014742",
				"5015862",
				"5016679",
				"5017373",
				"5018479",
				"5020013",
				"5021288",
				"5022339",
				"5022874",
				"5023759",
				"5025277",
				"5026426",
				"5027256",
				"5028224",
				"5029307",
				"5030261",
				"5031441",
				"5032250",
				"5033424",
				"5034167",
			},
		},
	},
	"Windows 8.1": {
		// https://support.microsoft.com/en-us/topic/windows-8-1-and-windows-server-2012-r2-update-history-47d81dd2-6804-b6ae-4112-20089467c7a6
		"": {
			rollup: []windowsRelease{
				{revision: "", kb: "3172614"},
				{revision: "", kb: "3179574"},
				{revision: "", kb: "3185279"},
				{revision: "", kb: "3185331"},
				{revision: "", kb: "3192404"},
				{revision: "", kb: "3197874"},
				{revision: "", kb: "3197875"},
				{revision: "", kb: "3205401"},
				{revision: "", kb: "4012216"},
				{revision: "", kb: "4012219"},
				{revision: "", kb: "4015550"},
				{revision: "", kb: "4015553"},
				{revision: "", kb: "4019215"},
				{revision: "", kb: "4019217"},
				{revision: "", kb: "4022726"},
				{revision: "", kb: "4022720"},
				{revision: "", kb: "4025336"},
				{revision: "", kb: "4025335"},
				{revision: "", kb: "4034681"},
				{revision: "", kb: "4034663"},
				{revision: "", kb: "4038792"},
				{revision: "", kb: "4038774"},
				{revision: "", kb: "4041693"},
				{revision: "", kb: "4041685"},
				{revision: "", kb: "4048958"},
				{revision: "", kb: "4050946"},
				{revision: "", kb: "4054519"},
				{revision: "", kb: "4056895"},
				{revision: "", kb: "4057401"},
				{revision: "", kb: "4074594"},
				{revision: "", kb: "4075212"},
				{revision: "", kb: "4088876"},
				{revision: "", kb: "4088882"},
				{revision: "", kb: "4093114"},
				{revision: "", kb: "4093121"},
				{revision: "", kb: "4103725"},
				{revision: "", kb: "4103724"},
				{revision: "", kb: "4284815"},
				{revision: "", kb: "4284863"},
				{revision: "", kb: "4338815"},
				{revision: "", kb: "4338831"},
				{revision: "", kb: "4343898"},
				{revision: "", kb: "4343891"},
				{revision: "", kb: "4457129"},
				{revision: "", kb: "4457133"},
				{revision: "", kb: "4462926"},
				{revision: "", kb: "4462921"},
				{revision: "", kb: "4467697"},
				{revision: "", kb: "4467695"},
				{revision: "", kb: "4471320"},
				{revision: "", kb: "4480963"},
				{revision: "", kb: "4480969"},
				{revision: "", kb: "4487000"},
				{revision: "", kb: "4487016"},
				{revision: "", kb: "4489881"},
				{revision: "", kb: "4489893"},
				{revision: "", kb: "4493446"},
				{revision: "", kb: "4493443"},
				{revision: "", kb: "4499151"},
				{revision: "", kb: "4499182"},
				{revision: "", kb: "4503276"},
				{revision: "", kb: "4503283"},
				{revision: "", kb: "4507448"},
				{revision: "", kb: "4507463"},
				{revision: "", kb: "4512488"},
				{revision: "", kb: "4512478"},
				{revision: "", kb: "4516067"},
				{revision: "", kb: "4516041"},
				{revision: "", kb: "4524156"},
				{revision: "", kb: "4520005"},
				{revision: "", kb: "4520012"},
				{revision: "", kb: "4525243"},
				{revision: "", kb: "4525252"},
				{revision: "", kb: "4530702"},
				{revision: "", kb: "4534297"},
				{revision: "", kb: "4534324"},
				{revision: "", kb: "4537821"},
				{revision: "", kb: "4537819"},
				{revision: "", kb: "4541509"},
				{revision: "", kb: "4541334"},
				{revision: "", kb: "4550961"},
				{revision: "", kb: "4550958"},
				{revision: "", kb: "4556846"},
				{revision: "", kb: "4561666"},
				{revision: "", kb: "4565541"},
				{revision: "", kb: "4571703"},
				{revision: "", kb: "4577066"},
				{revision: "", kb: "4580347"},
				{revision: "", kb: "4586845"},
				{revision: "", kb: "4592484"},
				{revision: "", kb: "4598285"},
				{revision: "", kb: "4601384"},
				{revision: "", kb: "5000848"},
				{revision: "", kb: "5001382"},
				{revision: "", kb: "5003209"},
				{revision: "", kb: "5003671"},
				{revision: "", kb: "5004954"},
				{revision: "", kb: "5004298"},
				{revision: "", kb: "5005076"},
				{revision: "", kb: "5005613"},
				{revision: "", kb: "5006714"},
				{revision: "", kb: "5007247"},
				{revision: "", kb: "5008263"},
				{revision: "", kb: "5009624"},
				{revision: "", kb: "5010419"},
				{revision: "", kb: "5011564"},
				{revision: "", kb: "5012670"},
				{revision: "", kb: "5014011"},
				{revision: "", kb: "5014738"},
				{revision: "", kb: "5015874"},
				{revision: "", kb: "5016681"},
				{revision: "", kb: "5017367"},
				{revision: "", kb: "5018474"},
				{revision: "", kb: "5020023"},
				{revision: "", kb: "5021294"},
				{revision: "", kb: "5022352"},
				{revision: "", kb: "5022899"},
				{revision: "", kb: "5023765"},
				{revision: "", kb: "5025285"},
				{revision: "", kb: "5026415"},
				{revision: "", kb: "5027271"},
				{revision: "", kb: "5028228"},
				{revision: "", kb: "5029312"},
				{revision: "", kb: "5030269"},
				{revision: "", kb: "5031419"},
				{revision: "", kb: "5032249"},
				{revision: "", kb: "5033420"},
				{revision: "", kb: "5034171"},
				{revision: "", kb: "5034819"},
				{revision: "", kb: "5035885"},
				{revision: "", kb: "5036960"},
				{revision: "", kb: "5037823"},
				{revision: "", kb: "5039294"},
				{revision: "", kb: "5040456"},
				{revision: "", kb: "5041828"},
				{revision: "", kb: "5043138"},
				{revision: "", kb: "5044343"},
				{revision: "", kb: "5046682"},
				{revision: "", kb: "5048735"},
				{revision: "", kb: "5050048"},
				{revision: "", kb: "5052042"},
				{revision: "", kb: "5053887"},
				{revision: "", kb: "5055557"},
				{revision: "", kb: "5058403"},
				{revision: "", kb: "5061018"},
				{revision: "", kb: "5062597"},
				{revision: "", kb: "5063950"},
				{revision: "", kb: "5065507"},
			},
			securityOnly: []string{
				"3192392",
				"3197873",
				"3205400",
				"4012213",
				"4015547",
				"4019213",
				"4022717",
				"4025333",
				"4034672",
				"4038793",
				"4041687",
				"4048961",
				"4054522",
				"4056898",
				"4074597",
				"4088879",
				"4093115",
				"4103715",
				"4284878",
				"4338824",
				"4343888",
				"4457143",
				"4462941",
				"4467703",
				"4471322",
				"4480964",
				"4487028",
				"4489883",
				"4493467",
				"4499165",
				"4503290",
				"4507457",
				"4512489",
				"4516064",
				"4519990",
				"4525250",
				"4530730",
				"4534309",
				"4537803",
				"4541505",
				"4550970",
				"4556853",
				"4561673",
				"4565540",
				"4571723",
				"4577071",
				"4580358",
				"4586823",
				"4592495",
				"4598275",
				"4601349",
				"5000853",
				"5001393",
				"5003220",
				"5003681",
				"5004958",
				"5004285",
				"5005106",
				"5005627",
				"5006729",
				"5007255",
				"5008285",
				"5009595",
				"5010395",
				"5011560",
				"5012639",
				"5014001",
				"5014746",
				"5015877",
				"5016683",
				"5017365",
				"5018476",
				"5020010",
				"5021296",
				"5022346",
				"5022894",
				"5023764",
				"5025288",
				"5026409",
				"5027282",
				"5028223",
				"5029304",
				"5030287",
				"5031407",
			},
		},
	},
	"Windows 10": {
		// https://learn.microsoft.com/en-us/windows/release-health/release-information
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-93345c32-4ae1-6d1c-f885-6c0b718adf3b
		"10240": {
			rollup: []windowsRelease{
				{revision: "16405", kb: "3074683"},
				{revision: "16413", kb: "3081424"},
				{revision: "16430", kb: "3081436"},
				{revision: "16433", kb: "3081438"},
				{revision: "16445", kb: "3081444"},
				{revision: "16463", kb: "3081448"},
				{revision: "16487", kb: "3081455"},
				{revision: "16520", kb: "3093266"},
				{revision: "16549", kb: "3097617"},
				{revision: "16566", kb: "3105210"},
				{revision: "16590", kb: "3105213"},
				{revision: "16601", kb: "3116869"},
				{revision: "16644", kb: "3124266"},
				{revision: "16683", kb: "3135174"},
				{revision: "16725", kb: "3140745"},
				{revision: "16769", kb: "3147461"},
				{revision: "16771", kb: "3147461"},
				{revision: "16854", kb: "3156387"},
				{revision: "16942", kb: "3163017"},
				{revision: "17024", kb: "3163912"},
				{revision: "17071", kb: "3176492"},
				{revision: "17113", kb: "3185611"},
				{revision: "17113", kb: "3193821"},
				{revision: "17146", kb: "3192440"},
				{revision: "17190", kb: "3198585"},
				{revision: "17202", kb: "3205383"},
				{revision: "17236", kb: "3210720"},
				{revision: "17319", kb: "4012606"},
				{revision: "17320", kb: "4016637"},
				{revision: "17354", kb: "4015221"},
				{revision: "17394", kb: "4019474"},
				{revision: "17443", kb: "4022727"},
				{revision: "17446", kb: "4032695"},
				{revision: "17488", kb: "4025338"},
				{revision: "17533", kb: "4034668"},
				{revision: "17609", kb: "4038781"},
				{revision: "17643", kb: "4042895"},
				{revision: "17673", kb: "4048956"},
				{revision: "17709", kb: "4053581"},
				{revision: "17738", kb: "4056893"},
				{revision: "17741", kb: "4075199"},
				{revision: "17741", kb: "4077735"},
				{revision: "17770", kb: "4074596"},
				{revision: "17797", kb: "4088786"},
				{revision: "17831", kb: "4093111"},
				{revision: "17861", kb: "4103716"},
				{revision: "17889", kb: "4284860"},
				{revision: "17914", kb: "4338829"},
				{revision: "17918", kb: "4345455"},
				{revision: "17946", kb: "4343892"},
				{revision: "17976", kb: "4457132"},
				{revision: "18005", kb: "4462922"},
				{revision: "18036", kb: "4467680"},
				{revision: "18063", kb: "4471323"},
				{revision: "18064", kb: "4483228"},
				{revision: "18094", kb: "4480962"},
				{revision: "18132", kb: "4487018"},
				{revision: "18135", kb: "4491101"},
				{revision: "18158", kb: "4489872"},
				{revision: "18186", kb: "4493475"},
				{revision: "18187", kb: "4498375"},
				{revision: "18215", kb: "4499154"},
				{revision: "18218", kb: "4505051"},
				{revision: "18244", kb: "4503291"},
				{revision: "18275", kb: "4507458"},
				{revision: "18305", kb: "4512497"},
				{revision: "18308", kb: "4517276"},
				{revision: "18333", kb: "4516070"},
				{revision: "18334", kb: "4522009"},
				{revision: "18335", kb: "4524153"},
				{revision: "18368", kb: "4520011"},
				{revision: "18395", kb: "4525232"},
				{revision: "18427", kb: "4530681"},
				{revision: "18453", kb: "4534306"},
				{revision: "18486", kb: "4537776"},
				{revision: "18519", kb: "4540693"},
				{revision: "18545", kb: "4550930"},
				{revision: "18575", kb: "4556826"},
				{revision: "18608", kb: "4561649"},
				{revision: "18609", kb: "4567518"},
				{revision: "18638", kb: "4565513"},
				{revision: "18666", kb: "4571692"},
				{revision: "18696", kb: "4577049"},
				{revision: "18725", kb: "4580327"},
				{revision: "18756", kb: "4586787"},
				{revision: "18782", kb: "4592464"},
				{revision: "18818", kb: "4598231"},
				{revision: "18841", kb: "4601331"},
				{revision: "18842", kb: "4601331"},
				{revision: "18874", kb: "5000807"},
				{revision: "18875", kb: "5001631"},
				{revision: "18906", kb: "5001340"},
				{revision: "18932", kb: "5003172"},
				{revision: "18967", kb: "5003687"},
				{revision: "18969", kb: "5004950"},
				{revision: "19003", kb: "5004249"},
				{revision: "19022", kb: "5005040"},
				{revision: "19060", kb: "5005569"},
				{revision: "19086", kb: "5006675"},
				{revision: "19119", kb: "5007207"},
				{revision: "19145", kb: "5008230"},
				{revision: "19177", kb: "5009585"},
				{revision: "19179", kb: "5010789"},
				{revision: "19204", kb: "5010358"},
				{revision: "19235", kb: "5011491"},
				{revision: "19265", kb: "5012653"},
				{revision: "19297", kb: "5013963"},
				{revision: "19325", kb: "5014710"},
				{revision: "19360", kb: "5015832"},
				{revision: "19387", kb: "5016639"},
				{revision: "19444", kb: "5017327"},
				{revision: "19507", kb: "5018425"},
				{revision: "19509", kb: "5020440"},
				{revision: "19567", kb: "5019970"},
				{revision: "19624", kb: "5021243"},
				{revision: "19685", kb: "5022297"},
				{revision: "19747", kb: "5022858"},
				{revision: "19805", kb: "5023713"},
				{revision: "19869", kb: "5025234"},
				{revision: "19926", kb: "5026382"},
				{revision: "19983", kb: "5027230"},
				{revision: "19986", kb: "5028622"},
				{revision: "20048", kb: "5028186"},
				{revision: "20107", kb: "5029259"},
				{revision: "20162", kb: "5030220"},
				{revision: "20232", kb: "5031377"},
				{revision: "20308", kb: "5032199"},
				{revision: "20345", kb: "5033379"},
				{revision: "20402", kb: "5034134"},
				{revision: "20469", kb: "5034774"},
				{revision: "20526", kb: "5035858"},
				{revision: "20596", kb: "5036925"},
				{revision: "20651", kb: "5037788"},
				{revision: "20680", kb: "5039225"},
				{revision: "20710", kb: "5040448"},
				{revision: "20751", kb: "5041782"},
				{revision: "20766", kb: "5043083"},
				{revision: "20796", kb: "5044286"},
				{revision: "20826", kb: "5046665"},
				{revision: "20857", kb: "5048703"},
				{revision: "20890", kb: "5050013"},
				{revision: "20915", kb: "5052040"},
				{revision: "20947", kb: "5053618"},
				{revision: "20979", kb: "5055547"},
				{revision: "21014", kb: "5058387"},
				{revision: "21034", kb: "5060998"},
				{revision: "21073", kb: "5062561"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-2ad7900f-882c-1dfc-f9d7-82b7ca162010
		"10586": {
			rollup: []windowsRelease{
				{revision: "3", kb: "3105211"},
				{revision: "11", kb: "3118754"},
				{revision: "14", kb: "3120677"},
				{revision: "17", kb: "3116908"},
				{revision: "29", kb: "3116900"},
				{revision: "36", kb: "3124200"},
				{revision: "63", kb: "3124263"},
				{revision: "71", kb: "3124262"},
				{revision: "104", kb: "3135173"},
				{revision: "122", kb: "3140743"},
				{revision: "164", kb: "3140768"},
				{revision: "218", kb: "3147458"},
				{revision: "318", kb: "3156421"},
				{revision: "420", kb: "3163018"},
				{revision: "494", kb: "3172985"},
				{revision: "545", kb: "3176493"},
				{revision: "589", kb: "3185614"},
				{revision: "633", kb: "3192441"},
				{revision: "679", kb: "3198586"},
				{revision: "682", kb: "3198586"},
				{revision: "713", kb: "3205386"},
				{revision: "753", kb: "3210721"},
				{revision: "839", kb: "4013198"},
				{revision: "842", kb: "4016636"},
				{revision: "873", kb: "4015219"},
				{revision: "916", kb: "4019473"},
				{revision: "962", kb: "4022714"},
				{revision: "965", kb: "4032693"},
				{revision: "1007", kb: "4025344"},
				{revision: "1045", kb: "4034660"},
				{revision: "1106", kb: "4038783"},
				{revision: "1176", kb: "4041689"},
				{revision: "1177", kb: "4052232"},
				{revision: "1232", kb: "4048952"},
				{revision: "1295", kb: "4053578"},
				{revision: "1356", kb: "4056888"},
				{revision: "1358", kb: "4075200"},
				{revision: "1417", kb: "4074591"},
				{revision: "1478", kb: "4088779"},
				{revision: "1540", kb: "4093109"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2016-update-history-4acfbc84-a290-1b54-536a-1c0430e9f3fd
		"14393": {
			rollup: []windowsRelease{
				{revision: "10", kb: "3176929"},
				{revision: "51", kb: "3176495"},
				{revision: "82", kb: "3176934"},
				{revision: "105", kb: "3176938"},
				{revision: "187", kb: "3189866"},
				{revision: "187", kb: "3193494"},
				{revision: "189", kb: "3193494"},
				{revision: "222", kb: "3194496"},
				{revision: "321", kb: "3194798"},
				{revision: "351", kb: "3197954"},
				{revision: "447", kb: "3200970"},
				{revision: "448", kb: "3200970"},
				{revision: "479", kb: "3201845"},
				{revision: "571", kb: "3206632"},
				{revision: "576", kb: "3206632"},
				{revision: "693", kb: "3213986"},
				{revision: "729", kb: "4010672"},
				{revision: "953", kb: "4013429"},
				{revision: "969", kb: "4015438"},
				{revision: "970", kb: "4016635"},
				{revision: "1066", kb: "4015217"},
				{revision: "1083", kb: "4015217"},
				{revision: "1198", kb: "4019472"},
				{revision: "1230", kb: "4023680"},
				{revision: "1358", kb: "4022715"},
				{revision: "1378", kb: "4022723"},
				{revision: "1480", kb: "4025339"},
				{revision: "1532", kb: "4025334"},
				{revision: "1537", kb: "4038220"},
				{revision: "1593", kb: "4034658"},
				{revision: "1613", kb: "4034661"},
				{revision: "1670", kb: "4039396"},
				{revision: "1715", kb: "4038782"},
				{revision: "1737", kb: "4038801"},
				{revision: "1770", kb: "4041691"},
				{revision: "1794", kb: "4041688"},
				{revision: "1797", kb: "4052231"},
				{revision: "1884", kb: "4048953"},
				{revision: "1914", kb: "4051033"},
				{revision: "1944", kb: "4053579"},
				{revision: "2007", kb: "4056890"},
				{revision: "2034", kb: "4057142"},
				{revision: "2035", kb: "4057142"},
				{revision: "2068", kb: "4074590"},
				{revision: "2097", kb: "4077525"},
				{revision: "2125", kb: "4088787"},
				{revision: "2126", kb: "4088787"},
				{revision: "2155", kb: "4088889"},
				{revision: "2156", kb: "4096309"},
				{revision: "2189", kb: "4093119"},
				{revision: "2214", kb: "4093120"},
				{revision: "2248", kb: "4103723"},
				{revision: "2273", kb: "4103720"},
				{revision: "2312", kb: "4284880"},
				{revision: "2339", kb: "4284833"},
				{revision: "2363", kb: "4338814"},
				{revision: "2368", kb: "4345418"},
				{revision: "2395", kb: "4338822"},
				{revision: "2396", kb: "4346877"},
				{revision: "2430", kb: "4343887"},
				{revision: "2457", kb: "4343884"},
				{revision: "2485", kb: "4457131"},
				{revision: "2515", kb: "4457127"},
				{revision: "2551", kb: "4462917"},
				{revision: "2580", kb: "4462928"},
				{revision: "2608", kb: "4467691"},
				{revision: "2639", kb: "4467684"},
				{revision: "2641", kb: "4478877"},
				{revision: "2665", kb: "4471321"},
				{revision: "2670", kb: "4483229"},
				{revision: "2724", kb: "4480961"},
				{revision: "2759", kb: "4480977"},
				{revision: "2791", kb: "4487026"},
				{revision: "2828", kb: "4487006"},
				{revision: "2848", kb: "4489882"},
				{revision: "2879", kb: "4489889"},
				{revision: "2906", kb: "4493470"},
				{revision: "2908", kb: "4499418"},
				{revision: "2941", kb: "4493473"},
				{revision: "2969", kb: "4494440"},
				{revision: "2972", kb: "4505052"},
				{revision: "2999", kb: "4499177"},
				{revision: "3025", kb: "4503267"},
				{revision: "3053", kb: "4503294"},
				{revision: "3056", kb: "4509475"},
				{revision: "3085", kb: "4507460"},
				{revision: "3115", kb: "4507459"},
				{revision: "3144", kb: "4512517"},
				{revision: "3181", kb: "4512495"},
				{revision: "3204", kb: "4516044"},
				{revision: "3206", kb: "4522010"},
				{revision: "3242", kb: "4516061"},
				{revision: "3243", kb: "4524152"},
				{revision: "3274", kb: "4519998"},
				{revision: "3300", kb: "4519979"},
				{revision: "3326", kb: "4525236"},
				{revision: "3384", kb: "4530689"},
				{revision: "3443", kb: "4534271"},
				{revision: "3474", kb: "4534307"},
				{revision: "3504", kb: "4537764"},
				{revision: "3542", kb: "4537806"},
				{revision: "3564", kb: "4540670"},
				{revision: "3595", kb: "4541329"},
				{revision: "3630", kb: "4550929"},
				{revision: "3659", kb: "4550947"},
				{revision: "3686", kb: "4556813"},
				{revision: "3750", kb: "4561616"},
				{revision: "3755", kb: "4567517"},
				{revision: "3808", kb: "4565511"},
				{revision: "3866", kb: "4571694"},
				{revision: "3930", kb: "4577015"},
				{revision: "3986", kb: "4580346"},
				{revision: "4046", kb: "4586830"},
				{revision: "4048", kb: "4594441"},
				{revision: "4104", kb: "4593226"},
				{revision: "4169", kb: "4598243"},
				{revision: "4225", kb: "4601318"},
				{revision: "4283", kb: "5000803"},
				{revision: "4288", kb: "5001633"},
				{revision: "4350", kb: "5001347"},
				{revision: "4402", kb: "5003197"},
				{revision: "4467", kb: "5003638"},
				{revision: "4470", kb: "5004948"},
				{revision: "4530", kb: "5004238"},
				{revision: "4532", kb: "5005393"},
				{revision: "4583", kb: "5005043"},
				{revision: "4651", kb: "5005573"},
				{revision: "4704", kb: "5006669"},
				{revision: "4770", kb: "5007192"},
				{revision: "4771", kb: "5008601"},
				{revision: "4825", kb: "5008207"},
				{revision: "4827", kb: "5010195"},
				{revision: "4886", kb: "5009546"},
				{revision: "4889", kb: "5010790"},
				{revision: "4946", kb: "5010359"},
				{revision: "5006", kb: "5011495"},
				{revision: "5066", kb: "5012596"},
				{revision: "5125", kb: "5013952"},
				{revision: "5127", kb: "5015019"},
				{revision: "5192", kb: "5014702"},
				{revision: "5246", kb: "5015808"},
				{revision: "5291", kb: "5016622"},
				{revision: "5356", kb: "5017305"},
				{revision: "5427", kb: "5018411"},
				{revision: "5429", kb: "5020439"},
				{revision: "5501", kb: "5019964"},
				{revision: "5502", kb: "5021654"},
				{revision: "5582", kb: "5021235"},
				{revision: "5648", kb: "5022289"},
				{revision: "5717", kb: "5022838"},
				{revision: "5786", kb: "5023697"},
				{revision: "5850", kb: "5025228"},
				{revision: "5921", kb: "5026363"},
				{revision: "5989", kb: "5027219"},
				{revision: "5996", kb: "5028623"},
				{revision: "6085", kb: "5028169"},
				{revision: "6167", kb: "5029242"},
				{revision: "6252", kb: "5030213"},
				{revision: "6351", kb: "5031362"},
				{revision: "6452", kb: "5032197"},
				{revision: "6529", kb: "5033373"},
				{revision: "6614", kb: "5034119"},
				{revision: "6709", kb: "5034767"},
				{revision: "6796", kb: "5035855"},
				{revision: "6799", kb: "5037423"},
				{revision: "6800", kb: "5037423"},
				{revision: "6897", kb: "5036899"},
				{revision: "6981", kb: "5037763"},
				{revision: "7070", kb: "5039214"},
				{revision: "7159", kb: "5040434"},
				{revision: "7259", kb: "5041773"},
				{revision: "7336", kb: "5043051"},
				{revision: "7428", kb: "5044293"},
				{revision: "7515", kb: "5046612"},
				{revision: "7606", kb: "5048671"},
				{revision: "7699", kb: "5049993"},
				{revision: "7785", kb: "5052006"},
				{revision: "7876", kb: "5053594"},
				{revision: "7969", kb: "5055521"},
				{revision: "7973", kb: "5058921"},
				{revision: "8066", kb: "5058383"},
				{revision: "8148", kb: "5061010"},
				{revision: "8246", kb: "5062560"},
				{revision: "8330", kb: "5063871"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-83aa43c0-82e0-92d8-1580-10642c9ed612
		"15063": {
			rollup: []windowsRelease{
				{revision: "13", kb: "4016251"},
				{revision: "138", kb: "4015583"},
				{revision: "250", kb: "4016240"},
				{revision: "296", kb: "4016871"},
				{revision: "297", kb: "4016871"},
				{revision: "332", kb: "4020102"},
				{revision: "413", kb: "4022725"},
				{revision: "414", kb: "4022725"},
				{revision: "447", kb: "4022716"},
				{revision: "483", kb: "4025342"},
				{revision: "502", kb: "4032188"},
				{revision: "540", kb: "4034674"},
				{revision: "608", kb: "4038788"},
				{revision: "632", kb: "4040724"},
				{revision: "674", kb: "4041676"},
				{revision: "675", kb: "4049370"},
				{revision: "726", kb: "4048954"},
				{revision: "728", kb: "4048954"},
				{revision: "729", kb: "4055254"},
				{revision: "786", kb: "4053580"},
				{revision: "850", kb: "4056891"},
				{revision: "877", kb: "4057144"},
				{revision: "909", kb: "4074592"},
				{revision: "936", kb: "4077528"},
				{revision: "936", kb: "4092077"},
				{revision: "966", kb: "4088782"},
				{revision: "968", kb: "4088782"},
				{revision: "994", kb: "4088891"},
				{revision: "1029", kb: "4093107"},
				{revision: "1058", kb: "4093117"},
				{revision: "1088", kb: "4103731"},
				{revision: "1112", kb: "4103722"},
				{revision: "1155", kb: "4284874"},
				{revision: "1182", kb: "4284830"},
				{revision: "1206", kb: "4338826"},
				{revision: "1209", kb: "4345419"},
				{revision: "1235", kb: "4338827"},
				{revision: "1266", kb: "4343885"},
				{revision: "1292", kb: "4343889"},
				{revision: "1324", kb: "4457138"},
				{revision: "1356", kb: "4457141"},
				{revision: "1358", kb: "4457141"},
				{revision: "1387", kb: "4462937"},
				{revision: "1418", kb: "4462939"},
				{revision: "1446", kb: "4467696"},
				{revision: "1478", kb: "4467699"},
				{revision: "1506", kb: "4471327"},
				{revision: "1508", kb: "4483230"},
				{revision: "1563", kb: "4480973"},
				{revision: "1596", kb: "4480959"},
				{revision: "1631", kb: "4487020"},
				{revision: "1659", kb: "4487011"},
				{revision: "1689", kb: "4489871"},
				{revision: "1716", kb: "4489888"},
				{revision: "1746", kb: "4493474"},
				{revision: "1784", kb: "4493436"},
				{revision: "1785", kb: "4502112"},
				{revision: "1805", kb: "4499181"},
				{revision: "1808", kb: "4505055"},
				{revision: "1839", kb: "4499162"},
				{revision: "1868", kb: "4503279"},
				{revision: "1897", kb: "4503289"},
				{revision: "1898", kb: "4509476"},
				{revision: "1928", kb: "4507450"},
				{revision: "1955", kb: "4507467"},
				{revision: "1988", kb: "4512507"},
				{revision: "2021", kb: "4512474"},
				{revision: "2045", kb: "4516068"},
				{revision: "2046", kb: "4522011"},
				{revision: "2078", kb: "4516059"},
				{revision: "2079", kb: "4524151"},
				{revision: "2108", kb: "4520010"},
				{revision: "2172", kb: "4525245"},
				{revision: "2224", kb: "4530711"},
				{revision: "2254", kb: "4534296"},
				{revision: "2284", kb: "4537765"},
				{revision: "2313", kb: "4540705"},
				{revision: "2346", kb: "4550939"},
				{revision: "2375", kb: "4556804"},
				{revision: "2409", kb: "4561605"},
				{revision: "2411", kb: "4567516"},
				{revision: "2439", kb: "4565499"},
				{revision: "2467", kb: "4571689"},
				{revision: "2500", kb: "4577021"},
				{revision: "2525", kb: "4580370"},
				{revision: "2554", kb: "4586782"},
				{revision: "2584", kb: "4592473"},
				{revision: "2614", kb: "4599208"},
				{revision: "2642", kb: "4601330"},
				{revision: "2679", kb: "5000812"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-update-history-8e779ac1-e840-d3b8-524e-91037bf7645a
		"16299": {
			rollup: []windowsRelease{
				{revision: "19", kb: "4043961"},
				{revision: "64", kb: "4048955"},
				{revision: "98", kb: "4051963"},
				{revision: "125", kb: "4054517"},
				{revision: "192", kb: "4056892"},
				{revision: "194", kb: "4073290"},
				{revision: "201", kb: "4073291"},
				{revision: "214", kb: "4058258"},
				{revision: "248", kb: "4074588"},
				{revision: "251", kb: "4090913"},
				{revision: "309", kb: "4088776"},
				{revision: "334", kb: "4089848"},
				{revision: "371", kb: "4093112"},
				{revision: "402", kb: "4093105"},
				{revision: "431", kb: "4103727"},
				{revision: "461", kb: "4103714"},
				{revision: "492", kb: "4284819"},
				{revision: "522", kb: "4284822"},
				{revision: "547", kb: "4338825"},
				{revision: "551", kb: "4345420"},
				{revision: "579", kb: "4338817"},
				{revision: "611", kb: "4343897"},
				{revision: "637", kb: "4343893"},
				{revision: "665", kb: "4457142"},
				{revision: "666", kb: "4464217"},
				{revision: "699", kb: "4457136"},
				{revision: "726", kb: "4462918"},
				{revision: "755", kb: "4462932"},
				{revision: "785", kb: "4467686"},
				{revision: "820", kb: "4467681"},
				{revision: "846", kb: "4471329"},
				{revision: "847", kb: "4483232"},
				{revision: "904", kb: "4480978"},
				{revision: "936", kb: "4480967"},
				{revision: "967", kb: "4486996"},
				{revision: "1004", kb: "4487021"},
				{revision: "1029", kb: "4489886"},
				{revision: "1059", kb: "4489890"},
				{revision: "1087", kb: "4493441"},
				{revision: "1127", kb: "4493440"},
				{revision: "1146", kb: "4499179"},
				{revision: "1150", kb: "4505062"},
				{revision: "1182", kb: "4499147"},
				{revision: "1217", kb: "4503284"},
				{revision: "1237", kb: "4503281"},
				{revision: "1239", kb: "4509477"},
				{revision: "1268", kb: "4507455"},
				{revision: "1296", kb: "4507465"},
				{revision: "1331", kb: "4512516"},
				{revision: "1365", kb: "4512494"},
				{revision: "1387", kb: "4516066"},
				{revision: "1392", kb: "4522012"},
				{revision: "1420", kb: "4516071"},
				{revision: "1421", kb: "4524150"},
				{revision: "1451", kb: "4520004"},
				{revision: "1481", kb: "4520006"},
				{revision: "1508", kb: "4525241"},
				{revision: "1565", kb: "4530714"},
				{revision: "1625", kb: "4534276"},
				{revision: "1654", kb: "4534318"},
				{revision: "1686", kb: "4537789"},
				{revision: "1717", kb: "4537816"},
				{revision: "1747", kb: "4540681"},
				{revision: "1775", kb: "4541330"},
				{revision: "1776", kb: "4554342"},
				{revision: "1806", kb: "4550927"},
				{revision: "1868", kb: "4556812"},
				{revision: "1932", kb: "4561602"},
				{revision: "1937", kb: "4567515"},
				{revision: "1992", kb: "4565508"},
				{revision: "2045", kb: "4571741"},
				{revision: "2107", kb: "4577041"},
				{revision: "2166", kb: "4580328"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-0d8c2da6-3dba-66e4-2ef2-059192bf7869
		"17134": {
			rollup: []windowsRelease{
				{revision: "48", kb: "4103721"},
				{revision: "81", kb: "4100403"},
				{revision: "83", kb: "4338548"},
				{revision: "112", kb: "4284835"},
				{revision: "137", kb: "4284848"},
				{revision: "165", kb: "4338819"},
				{revision: "167", kb: "4345421"},
				{revision: "191", kb: "4340917"},
				{revision: "228", kb: "4343909"},
				{revision: "254", kb: "4346783"},
				{revision: "285", kb: "4457128"},
				{revision: "286", kb: "4464218"},
				{revision: "320", kb: "4458469"},
				{revision: "345", kb: "4462919"},
				{revision: "376", kb: "4462933"},
				{revision: "407", kb: "4467702"},
				{revision: "441", kb: "4467682"},
				{revision: "471", kb: "4471324"},
				{revision: "472", kb: "4483234"},
				{revision: "523", kb: "4480966"},
				{revision: "556", kb: "4480976"},
				{revision: "590", kb: "4487017"},
				{revision: "619", kb: "4487029"},
				{revision: "648", kb: "4489868"},
				{revision: "677", kb: "4489894"},
				{revision: "706", kb: "4493464"},
				{revision: "753", kb: "4493437"},
				{revision: "765", kb: "4499167"},
				{revision: "766", kb: "4505064"},
				{revision: "799", kb: "4499183"},
				{revision: "829", kb: "4503286"},
				{revision: "858", kb: "4503288"},
				{revision: "860", kb: "4509478"},
				{revision: "885", kb: "4507435"},
				{revision: "915", kb: "4507466"},
				{revision: "950", kb: "4512501"},
				{revision: "984", kb: "4512509"},
				{revision: "1006", kb: "4516058"},
				{revision: "1009", kb: "4522014"},
				{revision: "1039", kb: "4516045"},
				{revision: "1040", kb: "4524149"},
				{revision: "1069", kb: "4520008"},
				{revision: "1099", kb: "4519978"},
				{revision: "1130", kb: "4525237"},
				{revision: "1184", kb: "4530717"},
				{revision: "1246", kb: "4534293"},
				{revision: "1276", kb: "4534308"},
				{revision: "1304", kb: "4537762"},
				{revision: "1345", kb: "4537795"},
				{revision: "1365", kb: "4540689"},
				{revision: "1399", kb: "4541333"},
				{revision: "1401", kb: "4554349"},
				{revision: "1425", kb: "4550922"},
				{revision: "1456", kb: "4550944"},
				{revision: "1488", kb: "4556807"},
				{revision: "1550", kb: "4561621"},
				{revision: "1553", kb: "4567514"},
				{revision: "1610", kb: "4565489"},
				{revision: "1667", kb: "4571709"},
				{revision: "1726", kb: "4577032"},
				{revision: "1792", kb: "4580330"},
				{revision: "1845", kb: "4586785"},
				{revision: "1902", kb: "4592446"},
				{revision: "1967", kb: "4598245"},
				{revision: "2026", kb: "4601354"},
				{revision: "2087", kb: "5000809"},
				{revision: "2088", kb: "5001565"},
				{revision: "2090", kb: "5001634"},
				{revision: "2145", kb: "5001339"},
				{revision: "2208", kb: "5003174"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2019-update-history-725fc2e1-4443-6831-a5ca-51ff5cbcb059
		"17763": {
			rollup: []windowsRelease{
				{revision: "1", kb: ""},
				{revision: "55", kb: "4464330"},
				{revision: "107", kb: "4464455"},
				{revision: "134", kb: "4467708"},
				{revision: "168", kb: "4469342"},
				{revision: "194", kb: "4471332"},
				{revision: "195", kb: "4483235"},
				{revision: "253", kb: "4480116"},
				{revision: "292", kb: "4476976"},
				{revision: "316", kb: "4487044"},
				{revision: "348", kb: "4482887"},
				{revision: "379", kb: "4489899"},
				{revision: "402", kb: "4490481"},
				{revision: "404", kb: "4490481"},
				{revision: "437", kb: "4493509"},
				{revision: "439", kb: "4501835"},
				{revision: "475", kb: "4495667"},
				{revision: "503", kb: "4494441"},
				{revision: "504", kb: "4505056"},
				{revision: "529", kb: "4497934"},
				{revision: "557", kb: "4503327"},
				{revision: "592", kb: "4501371"},
				{revision: "593", kb: "4509479"},
				{revision: "615", kb: "4507469"},
				{revision: "652", kb: "4505658"},
				{revision: "678", kb: "4511553"},
				{revision: "720", kb: "4512534"},
				{revision: "737", kb: "4512578"},
				{revision: "740", kb: "4522015"},
				{revision: "774", kb: "4516077"},
				{revision: "775", kb: "4524148"},
				{revision: "805", kb: "4519338"},
				{revision: "832", kb: "4520062"},
				{revision: "864", kb: "4523205"},
				{revision: "914", kb: "4530715"},
				{revision: "973", kb: "4534273"},
				{revision: "1012", kb: "4534321"},
				{revision: "1039", kb: "4532691"},
				{revision: "1075", kb: "4537818"},
				{revision: "1098", kb: "4538461"},
				{revision: "1131", kb: "4541331"},
				{revision: "1132", kb: "4554354"},
				{revision: "1158", kb: "4549949"},
				{revision: "1192", kb: "4550969"},
				{revision: "1217", kb: "4551853"},
				{revision: "1282", kb: "4561608"},
				{revision: "1294", kb: "4567513"},
				{revision: "1339", kb: "4558998"},
				{revision: "1369", kb: "4559003"},
				{revision: "1397", kb: "4565349"},
				{revision: "1432", kb: "4571748"},
				{revision: "1457", kb: "4570333"},
				{revision: "1490", kb: "4577069"},
				{revision: "1518", kb: "4577668"},
				{revision: "1554", kb: "4580390"},
				{revision: "1577", kb: "4586793"},
				{revision: "1579", kb: "4594442"},
				{revision: "1613", kb: "4586839"},
				{revision: "1637", kb: "4592440"},
				{revision: "1697", kb: "4598230"},
				{revision: "1728", kb: "4598296"},
				{revision: "1757", kb: "4601345"},
				{revision: "1790", kb: "4601383"},
				{revision: "1817", kb: "5000822"},
				{revision: "1821", kb: "5001568"},
				{revision: "1823", kb: "5001638"},
				{revision: "1852", kb: "5000854"},
				{revision: "1879", kb: "5001342"},
				{revision: "1911", kb: "5001384"},
				{revision: "1935", kb: "5003171"},
				{revision: "1971", kb: "5003217"},
				{revision: "1999", kb: "5003646"},
				{revision: "2028", kb: "5003703"},
				{revision: "2029", kb: "5004947"},
				{revision: "2061", kb: "5004244"},
				{revision: "2090", kb: "5004308"},
				{revision: "2091", kb: "5005394"},
				{revision: "2114", kb: "5005030"},
				{revision: "2145", kb: "5005102"},
				{revision: "2183", kb: "5005568"},
				{revision: "2210", kb: "5005625"},
				{revision: "2213", kb: "5005625"},
				{revision: "2237", kb: "5006672"},
				{revision: "2268", kb: "5006744"},
				{revision: "2300", kb: "5007206"},
				{revision: "2305", kb: "5008602"},
				{revision: "2330", kb: "5007266"},
				{revision: "2366", kb: "5008218"},
				{revision: "2369", kb: "5010196"},
				{revision: "2452", kb: "5009557"},
				{revision: "2458", kb: "5010791"},
				{revision: "2510", kb: "5009616"},
				{revision: "2565", kb: "5010351"},
				{revision: "2628", kb: "5010427"},
				{revision: "2686", kb: "5011503"},
				{revision: "2746", kb: "5011551"},
				{revision: "2803", kb: "5012647"},
				{revision: "2867", kb: "5012636"},
				{revision: "2928", kb: "5013941"},
				{revision: "2931", kb: "5015018"},
				{revision: "2989", kb: "5014022"},
				{revision: "3046", kb: "5014692"},
				{revision: "3113", kb: "5014669"},
				{revision: "3165", kb: "5015811"},
				{revision: "3232", kb: "5015880"},
				{revision: "3287", kb: "5016623"},
				{revision: "3346", kb: "5016690"},
				{revision: "3406", kb: "5017315"},
				{revision: "3469", kb: "5017379"},
				{revision: "3532", kb: "5018419"},
				{revision: "3534", kb: "5020438"},
				{revision: "3650", kb: "5019966"},
				{revision: "3653", kb: "5021655"},
				{revision: "3770", kb: "5021237"},
				{revision: "3772", kb: "5022554"},
				{revision: "3887", kb: "5022286"},
				{revision: "4010", kb: "5022840"},
				{revision: "4131", kb: "5023702"},
				{revision: "4252", kb: "5025229"},
				{revision: "4377", kb: "5026362"},
				{revision: "4499", kb: "5027222"},
				{revision: "4645", kb: "5028168"},
				{revision: "4737", kb: "5029247"},
				{revision: "4851", kb: "5030214"},
				{revision: "4974", kb: "5031361"},
				{revision: "5122", kb: "5032196"},
				{revision: "5206", kb: "5033371"},
				{revision: "5329", kb: "5034127"},
				{revision: "5458", kb: "5034768"},
				{revision: "5576", kb: "5035849"},
				{revision: "5579", kb: "5037425"},
				{revision: "5696", kb: "5036896"},
				{revision: "5820", kb: "5037765"},
				{revision: "5830", kb: "5039705"},
				{revision: "5936", kb: "5039217"},
				{revision: "6054", kb: "5040430"},
				{revision: "6189", kb: "5041578"},
				{revision: "6293", kb: "5043050"},
				{revision: "6414", kb: "5044277"},
				{revision: "6532", kb: "5046615"},
				{revision: "6659", kb: "5048661"},
				{revision: "6775", kb: "5050008"},
				{revision: "6893", kb: "5052000"},
				{revision: "7009", kb: "5053596"},
				{revision: "7136", kb: "5055519"},
				{revision: "7240", kb: "5058922"},
				{revision: "7249", kb: "5059091"},
				{revision: "7314", kb: "5058392"},
				{revision: "7322", kb: "5061978"},
				{revision: "7434", kb: "5060531"},
				{revision: "7558", kb: "5062557"},
				{revision: "7678", kb: "5063877"},
				{revision: "7683", kb: "5066187"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-e6058e7c-4116-38f1-b984-4fcacfba5e5d
		"18362": {
			rollup: []windowsRelease{
				{revision: "116", kb: "4505057"},
				{revision: "145", kb: "4497935"},
				{revision: "175", kb: "4503293"},
				{revision: "207", kb: "4501375"},
				{revision: "239", kb: "4507453"},
				{revision: "267", kb: "4505903"},
				{revision: "295", kb: "4512508"},
				{revision: "329", kb: "4512941"},
				{revision: "356", kb: "4515384"},
				{revision: "357", kb: "4522016"},
				{revision: "387", kb: "4517211"},
				{revision: "388", kb: "4524147"},
				{revision: "418", kb: "4517389"},
				{revision: "449", kb: "4522355"},
				{revision: "476", kb: "4524570"},
				{revision: "535", kb: "4530684"},
				{revision: "592", kb: "4528760"},
				{revision: "628", kb: "4532695"},
				{revision: "657", kb: "4532693"},
				{revision: "693", kb: "4535996"},
				{revision: "719", kb: "4540673"},
				{revision: "720", kb: "4551762"},
				{revision: "752", kb: "4541335"},
				{revision: "753", kb: "4554364"},
				{revision: "778", kb: "4549951"},
				{revision: "815", kb: "4550945"},
				{revision: "836", kb: "4556799"},
				{revision: "900", kb: "4560960"},
				{revision: "904", kb: "4567512"},
				{revision: "959", kb: "4565483"},
				{revision: "997", kb: "4559004"},
				{revision: "1016", kb: "4565351"},
				{revision: "1049", kb: "4566116"},
				{revision: "1082", kb: "4574727"},
				{revision: "1110", kb: "4577062"},
				{revision: "1139", kb: "4577671"},
				{revision: "1171", kb: "4580386"},
				{revision: "1198", kb: "4586786"},
				{revision: "1199", kb: "4594443"},
				{revision: "1237", kb: "4586819"},
				{revision: "1256", kb: "4592449"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-53c270dc-954f-41f7-7ced-488578904dfe
		"18363": {
			rollup: []windowsRelease{
				{revision: "476", kb: "4524570"},
				{revision: "535", kb: "4530684"},
				{revision: "592", kb: "4528760"},
				{revision: "628", kb: "4532695"},
				{revision: "657", kb: "4532693"},
				{revision: "693", kb: "4535996"},
				{revision: "719", kb: "4540673"},
				{revision: "720", kb: "4551762"},
				{revision: "752", kb: "4541335"},
				{revision: "753", kb: "4554364"},
				{revision: "778", kb: "4549951"},
				{revision: "815", kb: "4550945"},
				{revision: "836", kb: "4556799"},
				{revision: "900", kb: "4560960"},
				{revision: "904", kb: "4567512"},
				{revision: "959", kb: "4565483"},
				{revision: "997", kb: "4559004"},
				{revision: "1016", kb: "4565351"},
				{revision: "1049", kb: "4566116"},
				{revision: "1082", kb: "4574727"},
				{revision: "1110", kb: "4577062"},
				{revision: "1139", kb: "4577671"},
				{revision: "1171", kb: "4580386"},
				{revision: "1198", kb: "4586786"},
				{revision: "1199", kb: "4594443"},
				{revision: "1237", kb: "4586819"},
				{revision: "1256", kb: "4592449"},
				{revision: "1316", kb: "4598229"},
				{revision: "1350", kb: "4598298"},
				{revision: "1377", kb: "4601315"},
				{revision: "1379", kb: "5001028"},
				{revision: "1411", kb: "4601380"},
				{revision: "1440", kb: "5000808"},
				{revision: "1441", kb: "5001566"},
				{revision: "1443", kb: "5001648"},
				{revision: "1474", kb: "5000850"},
				{revision: "1500", kb: "5001337"},
				{revision: "1533", kb: "5001396"},
				{revision: "1556", kb: "5003169"},
				{revision: "1593", kb: "5003212"},
				{revision: "1621", kb: "5003635"},
				{revision: "1645", kb: "5003698"},
				{revision: "1646", kb: "5004946"},
				{revision: "1679", kb: "5004245"},
				{revision: "1714", kb: "5004293"},
				{revision: "1734", kb: "5005031"},
				{revision: "1766", kb: "5005103"},
				{revision: "1801", kb: "5005566"},
				{revision: "1830", kb: "5005624"},
				{revision: "1832", kb: "5005624"},
				{revision: "1854", kb: "5006667"},
				{revision: "1916", kb: "5007189"},
				{revision: "1977", kb: "5008206"},
				{revision: "2037", kb: "5009545"},
				{revision: "2039", kb: "5010792"},
				{revision: "2094", kb: "5010345"},
				{revision: "2158", kb: "5011485"},
				{revision: "2212", kb: "5012591"},
				{revision: "2274", kb: "5013945"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-24ea91f4-36e7-d8fd-0ddb-d79d9d0cdbda
		"19041": {
			rollup: []windowsRelease{
				{revision: "264", kb: ""},
				{revision: "329", kb: "4557957"},
				{revision: "331", kb: "4567523"},
				{revision: "388", kb: "4565503"},
				{revision: "423", kb: "4568831"},
				{revision: "450", kb: "4566782"},
				{revision: "488", kb: "4571744"},
				{revision: "508", kb: "4571756"},
				{revision: "546", kb: "4577063"},
				{revision: "572", kb: "4579311"},
				{revision: "610", kb: "4580364"},
				{revision: "630", kb: "4586781"},
				{revision: "631", kb: "4594440"},
				{revision: "662", kb: "4586853"},
				{revision: "685", kb: "4592438"},
				{revision: "746", kb: "4598242"},
				{revision: "789", kb: "4598291"},
				{revision: "804", kb: "4601319"},
				{revision: "844", kb: "4601382"},
				{revision: "867", kb: "5000802"},
				{revision: "868", kb: "5001567"},
				{revision: "870", kb: "5001649"},
				{revision: "906", kb: "5000842"},
				{revision: "928", kb: "5001330"},
				{revision: "964", kb: "5001391"},
				{revision: "985", kb: "5003173"},
				{revision: "1023", kb: "5003214"},
				{revision: "1052", kb: "5003637"},
				{revision: "1055", kb: "5004476"},
				{revision: "1081", kb: "5003690"},
				{revision: "1082", kb: "5004760"},
				{revision: "1083", kb: "5004945"},
				{revision: "1110", kb: "5004237"},
				{revision: "1151", kb: "5004296"},
				{revision: "1165", kb: "5005033"},
				{revision: "1202", kb: "5005101"},
				{revision: "1237", kb: "5005565"},
				{revision: "1266", kb: "5005611"},
				{revision: "1288", kb: "5006670"},
				{revision: "1320", kb: "5006738"},
				{revision: "1348", kb: "5007186"},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-7dd3071a-3906-fa2c-c342-f7f86728a6e3
		"19042": {
			rollup: []windowsRelease{
				{revision: "572", kb: ""},
				{revision: "610", kb: "4580364"},
				{revision: "630", kb: "4586781"},
				{revision: "631", kb: "4594440"},
				{revision: "662", kb: "4586853"},
				{revision: "685", kb: "4592438"},
				{revision: "746", kb: "4598242"},
				{revision: "789", kb: "4598291"},
				{revision: "804", kb: "4601319"},
				{revision: "844", kb: "4601382"},
				{revision: "867", kb: "5000802"},
				{revision: "868", kb: "5001567"},
				{revision: "870", kb: "5001649"},
				{revision: "906", kb: "5000842"},
				{revision: "928", kb: "5001330"},
				{revision: "964", kb: "5001391"},
				{revision: "985", kb: "5003173"},
				{revision: "1023", kb: "5003214"},
				{revision: "1052", kb: "5003637"},
				{revision: "1055", kb: "5004476"},
				{revision: "1081", kb: "5003690"},
				{revision: "1082", kb: "5004760"},
				{revision: "1083", kb: "5004945"},
				{revision: "1110", kb: "5004237"},
				{revision: "1151", kb: "5004296"},
				{revision: "1165", kb: "5005033"},
				{revision: "1202", kb: "5005101"},
				{revision: "1237", kb: "5005565"},
				{revision: "1266", kb: "5005611"},
				{revision: "1288", kb: "5006670"},
				{revision: "1320", kb: "5006738"},
				{revision: "1348", kb: "5007186"},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
				{revision: "1466", kb: "5009543"},
				{revision: "1469", kb: "5010793"},
				{revision: "1503", kb: "5009596"},
				{revision: "1526", kb: "5010342"},
				{revision: "1566", kb: "5010415"},
				{revision: "1586", kb: "5011487"},
				{revision: "1620", kb: "5011543"},
				{revision: "1645", kb: "5012599"},
				{revision: "1682", kb: "5011831"},
				{revision: "1706", kb: "5013942"},
				{revision: "1708", kb: "5015020"},
				{revision: "1741", kb: "5014023"},
				{revision: "1766", kb: "5014699"},
				{revision: "1767", kb: "5016139"},
				{revision: "1806", kb: "5014666"},
				{revision: "1826", kb: "5015807"},
				{revision: "1865", kb: "5015878"},
				{revision: "1889", kb: "5016616"},
				{revision: "1949", kb: "5016688"},
				{revision: "2006", kb: "5017308"},
				{revision: "2075", kb: "5017380"},
				{revision: "2130", kb: "5018410"},
				{revision: "2132", kb: "5020435"},
				{revision: "2193", kb: "5018482"},
				{revision: "2194", kb: "5020953"},
				{revision: "2251", kb: "5019959"},
				{revision: "2311", kb: "5020030"},
				{revision: "2364", kb: "5021233"},
				{revision: "2486", kb: "5022282"},
				{revision: "2546", kb: "5019275"},
				{revision: "2604", kb: "5022834"},
				{revision: "2673", kb: "5022906"},
				{revision: "2728", kb: "5023696"},
				{revision: "2788", kb: "5023773"},
				{revision: "2846", kb: "5025221"},
				{revision: "2965", kb: "5026361"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-1b6aac92-bf01-42b5-b158-f80c6d93eb11
		"19043": {
			rollup: []windowsRelease{
				{revision: "985", kb: "5003173"},
				{revision: "1023", kb: "5003214"},
				{revision: "1052", kb: "5003637"},
				{revision: "1055", kb: "5004476"},
				{revision: "1081", kb: "5003690"},
				{revision: "1082", kb: "5004760"},
				{revision: "1083", kb: "5004945"},
				{revision: "1110", kb: "5004237"},
				{revision: "1151", kb: "5004296"},
				{revision: "1165", kb: "5005033"},
				{revision: "1202", kb: "5005101"},
				{revision: "1237", kb: "5005565"},
				{revision: "1266", kb: "5005611"},
				{revision: "1288", kb: "5006670"},
				{revision: "1320", kb: "5006738"},
				{revision: "1348", kb: "5007186"},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
				{revision: "1466", kb: "5009543"},
				{revision: "1469", kb: "5010793"},
				{revision: "1503", kb: "5009596"},
				{revision: "1526", kb: "5010342"},
				{revision: "1566", kb: "5010415"},
				{revision: "1586", kb: "5011487"},
				{revision: "1620", kb: "5011543"},
				{revision: "1645", kb: "5012599"},
				{revision: "1682", kb: "5011831"},
				{revision: "1706", kb: "5013942"},
				{revision: "1708", kb: "5015020"},
				{revision: "1741", kb: "5014023"},
				{revision: "1766", kb: "5014699"},
				{revision: "1767", kb: "5016139"},
				{revision: "1806", kb: "5014666"},
				{revision: "1826", kb: "5015807"},
				{revision: "1865", kb: "5015878"},
				{revision: "1889", kb: "5016616"},
				{revision: "1949", kb: "5016688"},
				{revision: "2006", kb: "5017308"},
				{revision: "2075", kb: "5017380"},
				{revision: "2130", kb: "5018410"},
				{revision: "2132", kb: "5020435"},
				{revision: "2193", kb: "5018482"},
				{revision: "2194", kb: "5020953"},
				{revision: "2251", kb: "5019959"},
				{revision: "2311", kb: "5020030"},
				{revision: "2364", kb: "5021233"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-857b8ccb-71e4-49e5-b3f6-7073197d98fb
		"19044": {
			rollup: []windowsRelease{
				{revision: "1288", kb: ""},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
				{revision: "1466", kb: "5009543"},
				{revision: "1469", kb: "5010793"},
				{revision: "1503", kb: "5009596"},
				{revision: "1526", kb: "5010342"},
				{revision: "1566", kb: "5010415"},
				{revision: "1586", kb: "5011487"},
				{revision: "1620", kb: "5011543"},
				{revision: "1645", kb: "5012599"},
				{revision: "1682", kb: "5011831"},
				{revision: "1706", kb: "5013942"},
				{revision: "1708", kb: "5015020"},
				{revision: "1741", kb: "5014023"},
				{revision: "1766", kb: "5014699"},
				{revision: "1767", kb: "5016139"},
				{revision: "1806", kb: "5014666"},
				{revision: "1826", kb: "5015807"},
				{revision: "1865", kb: "5015878"},
				{revision: "1889", kb: "5016616"},
				{revision: "1949", kb: "5016688"},
				{revision: "2006", kb: "5017308"},
				{revision: "2075", kb: "5017380"},
				{revision: "2130", kb: "5018410"},
				{revision: "2132", kb: "5020435"},
				{revision: "2193", kb: "5018482"},
				{revision: "2194", kb: "5020953"},
				{revision: "2251", kb: "5019959"},
				{revision: "2311", kb: "5020030"},
				{revision: "2364", kb: "5021233"},
				{revision: "2486", kb: "5022282"},
				{revision: "2546", kb: "5019275"},
				{revision: "2604", kb: "5022834"},
				{revision: "2673", kb: "5022906"},
				{revision: "2728", kb: "5023696"},
				{revision: "2788", kb: "5023773"},
				{revision: "2846", kb: "5025221"},
				{revision: "2965", kb: "5026361"},
				{revision: "3086", kb: "5027215"},
				{revision: "3208", kb: "5028166"},
				{revision: "3324", kb: "5029244"},
				{revision: "3448", kb: "5030211"},
				{revision: "3570", kb: "5031356"},
				{revision: "3693", kb: "5032189"},
				{revision: "3803", kb: "5033372"},
				{revision: "3930", kb: "5034122"},
				{revision: "4046", kb: "5034763"},
				{revision: "4170", kb: "5035845"},
				{revision: "4291", kb: "5036892"},
				{revision: "4412", kb: "5037768"},
				{revision: "4529", kb: "5039211"},
				{revision: "4651", kb: "5040427"},
				{revision: "4780", kb: "5041580"},
				{revision: "4894", kb: "5043064"},
				{revision: "5011", kb: "5044273"},
				{revision: "5131", kb: "5046613"},
				{revision: "5247", kb: "5048652"},
				{revision: "5371", kb: "5049981"},
				{revision: "5487", kb: "5051974"},
				{revision: "5608", kb: "5053606"},
				{revision: "5737", kb: "5055518"},
				{revision: "5854", kb: "5058379"},
				{revision: "5856", kb: "5061768"},
				{revision: "5859", kb: "5061979"},
				{revision: "5965", kb: "5060533"},
				{revision: "6093", kb: "5062554"},
				{revision: "6216", kb: "5063709"},
				{revision: "6218", kb: "5066188"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562
		"19045": {
			rollup: []windowsRelease{
				{revision: "2130", kb: ""},
				{revision: "2194", kb: "5020953"},
				{revision: "2251", kb: "5019959"},
				{revision: "2311", kb: "5020030"},
				{revision: "2364", kb: "5021233"},
				{revision: "2486", kb: "5022282"},
				{revision: "2546", kb: "5019275"},
				{revision: "2604", kb: "5022834"},
				{revision: "2673", kb: "5022906"},
				{revision: "2728", kb: "5023696"},
				{revision: "2788", kb: "5023773"},
				{revision: "2846", kb: "5025221"},
				{revision: "2913", kb: "5025297"},
				{revision: "2965", kb: "5026361"},
				{revision: "3031", kb: "5026435"},
				{revision: "3086", kb: "5027215"},
				{revision: "3155", kb: "5027293"},
				{revision: "3208", kb: "5028166"},
				{revision: "3271", kb: "5028244"},
				{revision: "3324", kb: "5029244"},
				{revision: "3393", kb: "5029331"},
				{revision: "3448", kb: "5030211"},
				{revision: "3516", kb: "5030300"},
				{revision: "3570", kb: "5031356"},
				{revision: "3636", kb: "5031445"},
				{revision: "3693", kb: "5032189"},
				{revision: "3758", kb: "5032278"},
				{revision: "3803", kb: "5033372"},
				{revision: "3930", kb: "5034122"},
				{revision: "3996", kb: "5034203"},
				{revision: "4046", kb: "5034763"},
				{revision: "4123", kb: "5034843"},
				{revision: "4170", kb: "5035845"},
				{revision: "4239", kb: "5035941"},
				{revision: "4291", kb: "5036892"},
				{revision: "4355", kb: "5036979"},
				{revision: "4412", kb: "5037768"},
				{revision: "4474", kb: "5037849"},
				{revision: "4529", kb: "5039211"},
				{revision: "4598", kb: "5039299"},
				{revision: "4651", kb: "5040427"},
				{revision: "4717", kb: "5040525"},
				{revision: "4780", kb: "5041580"},
				{revision: "4842", kb: "5041582"},
				{revision: "4894", kb: "5043064"},
				{revision: "4957", kb: "5043131"},
				{revision: "5011", kb: "5044273"},
				{revision: "5073", kb: "5045594"},
				{revision: "5131", kb: "5046613"},
				{revision: "5198", kb: "5046714"},
				{revision: "5247", kb: "5048652"},
				{revision: "5371", kb: "5049981"},
				{revision: "5440", kb: "5050081"},
				{revision: "5487", kb: "5051974"},
				{revision: "5555", kb: "5052077"},
				{revision: "5608", kb: "5053606"},
				{revision: "5679", kb: "5053643"},
				{revision: "5737", kb: "5055518"},
				{revision: "5796", kb: "5055612"},
				{revision: "5854", kb: "5058379"},
				{revision: "5856", kb: "5061768"},
				{revision: "5859", kb: "5061979"},
				{revision: "5917", kb: "5058481"},
				{revision: "5965", kb: "5060533"},
				{revision: "5968", kb: "5063159"},
				{revision: "6036", kb: "5061087"},
				{revision: "6093", kb: "5062554"},
				{revision: "6159", kb: "5062649"},
				{revision: "6216", kb: "5063709"},
				{revision: "6218", kb: "5066188"},
				{revision: "6282", kb: "5063842"},
			},
		},
	},
	"Windows 11": {
		// https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
		// https://support.microsoft.com/en-us/topic/windows-11-version-21h2-update-history-a19cd327-b57f-44b9-84e0-26ced7109ba9/
		"22000": {
			rollup: []windowsRelease{
				{revision: "194", kb: ""},
				{revision: "258", kb: "5006674"},
				{revision: "282", kb: "5006746"},
				{revision: "318", kb: "5007215"},
				{revision: "348", kb: "5007262"},
				{revision: "376", kb: "5008215"},
				{revision: "434", kb: "5009566"},
				{revision: "438", kb: "5010795"},
				{revision: "469", kb: "5008353"},
				{revision: "493", kb: "5010386"},
				{revision: "527", kb: "5010414"},
				{revision: "556", kb: "5011493"},
				{revision: "593", kb: "5011563"},
				{revision: "613", kb: "5012592"},
				{revision: "652", kb: "5012643"},
				{revision: "675", kb: "5013943"},
				{revision: "708", kb: "5014019"},
				{revision: "739", kb: "5014697"},
				{revision: "740", kb: "5016138"},
				{revision: "778", kb: "5014668"},
				{revision: "795", kb: "5015814"},
				{revision: "832", kb: "5015882"},
				{revision: "856", kb: "5016629"},
				{revision: "918", kb: "5016691"},
				{revision: "978", kb: "5017328"},
				{revision: "1042", kb: "5017383"},
				{revision: "1098", kb: "5018418"},
				{revision: "1100", kb: "5020387"},
				{revision: "1165", kb: "5018483"},
				{revision: "1219", kb: "5019961"},
				{revision: "1281", kb: "5019157"},
				{revision: "1335", kb: "5021234"},
				{revision: "1455", kb: "5022287"},
				{revision: "1516", kb: "5019274"},
				{revision: "1574", kb: "5022836"},
				{revision: "1641", kb: "5022905"},
				{revision: "1696", kb: "5023698"},
				{revision: "1761", kb: "5023774"},
				{revision: "1817", kb: "5025224"},
				{revision: "1880", kb: "5025298"},
				{revision: "1936", kb: "5026368"},
				{revision: "2003", kb: "5026436"},
				{revision: "2057", kb: "5027223"},
				{revision: "2124", kb: "5027292"},
				{revision: "2176", kb: "5028182"},
				{revision: "2245", kb: "5028245"},
				{revision: "2295", kb: "5029253"},
				{revision: "2360", kb: "5029332"},
				{revision: "2416", kb: "5030217"},
				{revision: "2482", kb: "5030301"},
				{revision: "2538", kb: "5031358"},
				{revision: "2600", kb: "5032192"},
				{revision: "2652", kb: "5033369"},
				{revision: "2713", kb: "5034121"},
				{revision: "2777", kb: "5034766"},
				{revision: "2836", kb: "5035854"},
				{revision: "2899", kb: "5036894"},
				{revision: "2960", kb: "5037770"},
				{revision: "3019", kb: "5039213"},
				{revision: "3079", kb: "5040431"},
				{revision: "3147", kb: "5041592"},
				{revision: "3197", kb: "5043067"},
				{revision: "3260", kb: "5044280"},
			},
		},
		// https://support.microsoft.com/en-us/topic/windows-11-version-22h2-update-history-ec4229c3-9c5f-4e75-9d6d-9025ab70fcce
		"22621": {
			rollup: []windowsRelease{
				{revision: "521", kb: ""},
				{revision: "525", kb: "5019311"},
				{revision: "608", kb: "5017389"},
				{revision: "674", kb: "5018427"},
				{revision: "675", kb: "5019509"},
				{revision: "755", kb: "5018496"},
				{revision: "819", kb: "5019980"},
				{revision: "900", kb: "5020044"},
				{revision: "963", kb: "5021255"},
				{revision: "1105", kb: "5022303"},
				{revision: "1194", kb: "5022360"},
				{revision: "1265", kb: "5022845"},
				{revision: "1344", kb: "5022913"},
				{revision: "1413", kb: "5023706"},
				{revision: "1485", kb: "5023778"},
				{revision: "1555", kb: "5025239"},
				{revision: "1635", kb: "5025305"},
				{revision: "1702", kb: "5026372"},
				{revision: "1778", kb: "5026446"},
				{revision: "1848", kb: "5027231"},
				{revision: "1928", kb: "5027303"},
				{revision: "1992", kb: "5028185"},
				{revision: "2070", kb: "5028254"},
				{revision: "2134", kb: "5029263"},
				{revision: "2215", kb: "5029351"},
				{revision: "2283", kb: "5030219"},
				{revision: "2361", kb: "5030310"},
				{revision: "2428", kb: "5031354"},
				{revision: "2506", kb: "5031455"},
				{revision: "2715", kb: "5032190"},
				{revision: "2792", kb: "5032288"},
				{revision: "2861", kb: "5033375"},
				{revision: "3007", kb: "5034123"},
				{revision: "3085", kb: "5034204"},
				{revision: "3155", kb: "5034765"},
				{revision: "3235", kb: "5034848"},
				{revision: "3296", kb: "5035853"},
				{revision: "3374", kb: "5035942"},
				{revision: "3447", kb: "5036893"},
				{revision: "3527", kb: "5036980"},
				{revision: "3593", kb: "5037771"},
				{revision: "3672", kb: "5037853"},
				{revision: "3737", kb: "5039212"},
				{revision: "3810", kb: "5039302"},
				{revision: "3880", kb: "5040442"},
				{revision: "3958", kb: "5040527"},
				{revision: "4037", kb: "5041585"},
				{revision: "4112", kb: "5041587"},
				{revision: "4169", kb: "5043076"},
				{revision: "4249", kb: "5043145"},
				{revision: "4317", kb: "5044285"},
				{revision: "4391", kb: "5044380"},
				{revision: "4460", kb: "5046633"},
				{revision: "4541", kb: "5046732"},
				{revision: "4602", kb: "5048685"},
				{revision: "4751", kb: "5050021"},
				{revision: "4830", kb: "5050092"},
				{revision: "4890", kb: "5051989"},
				{revision: "4974", kb: "5052094"},
				{revision: "5039", kb: "5053602"},
				{revision: "5126", kb: "5053657"},
				{revision: "5189", kb: "5055528"},
				{revision: "5192", kb: "5058919"},
				{revision: "5262", kb: "5055629"},
				{revision: "5335", kb: "5058405"},
				{revision: "5413", kb: "5058502"},
				{revision: "5415", kb: "5062170"},
				{revision: "5472", kb: "5060999"},
				{revision: "5549", kb: "5060826"},
				{revision: "5624", kb: "5062552"},
				{revision: "5768", kb: "5063875"},
				{revision: "5771", kb: "5066189"},
			},
		},
		"22631": {
			rollup: []windowsRelease{
				{revision: "2428", kb: ""},
				{revision: "2506", kb: "5031455"},
				{revision: "2715", kb: "5032190"},
				{revision: "2792", kb: "5032288"},
				{revision: "2861", kb: "5033375"},
				{revision: "3007", kb: "5034123"},
				{revision: "3085", kb: "5034204"},
				{revision: "3155", kb: "5034765"},
				{revision: "3235", kb: "5034848"},
				{revision: "3296", kb: "5035853"},
				{revision: "3374", kb: "5035942"},
				{revision: "3447", kb: "5036893"},
				{revision: "3527", kb: "5036980"},
				{revision: "3593", kb: "5037771"},
				{revision: "3672", kb: "5037853"},
				{revision: "3737", kb: "5039212"},
				{revision: "3810", kb: "5039302"},
				{revision: "3880", kb: "5040442"},
				{revision: "3958", kb: "5040527"},
				{revision: "4037", kb: "5041585"},
				{revision: "4112", kb: "5041587"},
				{revision: "4169", kb: "5043076"},
				{revision: "4249", kb: "5043145"},
				{revision: "4317", kb: "5044285"},
				{revision: "4391", kb: "5044380"},
				{revision: "4460", kb: "5046633"},
				{revision: "4541", kb: "5046732"},
				{revision: "4602", kb: "5048685"},
				{revision: "4751", kb: "5050021"},
				{revision: "4830", kb: "5050092"},
				{revision: "4890", kb: "5051989"},
				{revision: "4974", kb: "5052094"},
				{revision: "5039", kb: "5053602"},
				{revision: "5126", kb: "5053657"},
				{revision: "5189", kb: "5055528"},
				{revision: "5192", kb: "5058919"},
				{revision: "5262", kb: "5055629"},
				{revision: "5335", kb: "5058405"},
				{revision: "5413", kb: "5058502"},
				{revision: "5415", kb: "5062170"},
				{revision: "5472", kb: "5060999"},
				{revision: "5549", kb: "5060826"},
				{revision: "5624", kb: "5062552"},
				{revision: "5768", kb: "5063875"},
				{revision: "5771", kb: "5066189"},
				{revision: "5840", kb: "5064080"},
			},
		},
		"26100": {
			rollup: []windowsRelease{
				{revision: "1742", kb: ""},
				{revision: "2033", kb: "5044284"},
				{revision: "2161", kb: "5044384"},
				{revision: "2314", kb: "5046617"},
				{revision: "2454", kb: "5046740"},
				{revision: "2605", kb: "5048667"},
				{revision: "2894", kb: "5050009"},
				{revision: "3037", kb: "5050094"},
				{revision: "3194", kb: "5051987"},
				{revision: "3323", kb: "5052093"},
				{revision: "3476", kb: "5053598"},
				{revision: "3624", kb: "5053656"},
				{revision: "3775", kb: "5055523"},
				{revision: "3915", kb: "5055627"},
				{revision: "4061", kb: "5058411"},
				{revision: "4066", kb: "5061977"},
				{revision: "4202", kb: "5058499"},
				{revision: "4349", kb: "5060842"},
				{revision: "4351", kb: "5063060"},
				{revision: "4484", kb: "5060829"},
				{revision: "4652", kb: "5062553"},
				{revision: "4656", kb: "5064489"},
				{revision: "4770", kb: "5062660"},
				{revision: "4946", kb: "5063878"},
				{revision: "5074", kb: "5064081"},
			},
		},
	},
	"Windows Server 2008": {
		// https://support.microsoft.com/en-us/topic/windows-server-2008-sp2-update-history-9197740a-7430-f69f-19ff-4998a4e8b25b
		"SP2": {
			rollup: []windowsRelease{
				{revision: "", kb: "4458010"},
				{revision: "", kb: "4458315"},
				{revision: "", kb: "4463097"},
				{revision: "", kb: "4463105"},
				{revision: "", kb: "4467706"},
				{revision: "", kb: "4467687"},
				{revision: "", kb: "4471325"},
				{revision: "", kb: "4480968"},
				{revision: "", kb: "4480974"},
				{revision: "", kb: "4487023"},
				{revision: "", kb: "4487022"},
				{revision: "", kb: "4489880"},
				{revision: "", kb: "4489887"},
				{revision: "", kb: "4493471"},
				{revision: "", kb: "4493460"},
				{revision: "", kb: "4499149"},
				{revision: "", kb: "4499184"},
				{revision: "", kb: "4503273"},
				{revision: "", kb: "4503271"},
				{revision: "", kb: "4507452"},
				{revision: "", kb: "4507451"},
				{revision: "", kb: "4512476"},
				{revision: "", kb: "4512499"},
				{revision: "", kb: "4516026"},
				{revision: "", kb: "4516030"},
				{revision: "", kb: "4520002"},
				{revision: "", kb: "4520015"},
				{revision: "", kb: "4525234"},
				{revision: "", kb: "4525244"},
				{revision: "", kb: "4530695"},
				{revision: "", kb: "4534303"},
				{revision: "", kb: "4537810"},
				{revision: "", kb: "4541506"},
				{revision: "", kb: "4550951"},
				{revision: "", kb: "4556860"},
				{revision: "", kb: "4561670"},
				{revision: "", kb: "4565536"},
				{revision: "", kb: "4571730"},
				{revision: "", kb: "4577064"},
				{revision: "", kb: "4580378"},
				{revision: "", kb: "4586807"},
				{revision: "", kb: "4592498"},
				{revision: "", kb: "4598288"},
				{revision: "", kb: "4601360"},
				{revision: "", kb: "5000844"},
				{revision: "", kb: "5001389"},
				{revision: "", kb: "5003210"},
				{revision: "", kb: "5003661"},
				{revision: "", kb: "5004955"},
				{revision: "", kb: "5004305"},
				{revision: "", kb: "5005090"},
				{revision: "", kb: "5005606"},
				{revision: "", kb: "5006736"},
				{revision: "", kb: "5007263"},
				{revision: "", kb: "5008274"},
				{revision: "", kb: "5009627"},
				{revision: "", kb: "5010384"},
				{revision: "", kb: "5011534"},
				{revision: "", kb: "5012658"},
				{revision: "", kb: "5014010"},
				{revision: "", kb: "5014752"},
				{revision: "", kb: "5015866"},
				{revision: "", kb: "5016669"},
				{revision: "", kb: "5017358"},
				{revision: "", kb: "5018450"},
				{revision: "", kb: "5020019"},
				{revision: "", kb: "5021289"},
				{revision: "", kb: "5022340"},
				{revision: "", kb: "5022890"},
				{revision: "", kb: "5023755"},
				{revision: "", kb: "5025271"},
				{revision: "", kb: "5026408"},
				{revision: "", kb: "5027279"},
				{revision: "", kb: "5028222"},
				{revision: "", kb: "5029318"},
				{revision: "", kb: "5030271"},
				{revision: "", kb: "5031416"},
				{revision: "", kb: "5032254"},
				{revision: "", kb: "5033422"},
				{revision: "", kb: "5034173"},
			},
			securityOnly: []string{
				"4457984",
				"4463104",
				"4467700",
				"4471319",
				"4480957",
				"4487019",
				"4489876",
				"4493458",
				"4499180",
				"4503287",
				"4507461",
				"4512491",
				"4516051",
				"4520009",
				"4525239",
				"4530719",
				"4534312",
				"4537822",
				"4541504",
				"4550957",
				"4556854",
				"4561645",
				"4565529",
				"4571746",
				"4577070",
				"4580385",
				"4586817",
				"4592504",
				"4598287",
				"4601366",
				"5000856",
				"5001332",
				"5003225",
				"5003695",
				"5004959",
				"5004299",
				"5005095",
				"5005618",
				"5006715",
				"5007246",
				"5008271",
				"5009601",
				"5010403",
				"5011525",
				"5012632",
				"5014006",
				"5014743",
				"5015870",
				"5016686",
				"5017371",
				"5018446",
				"5020005",
				"5021293",
				"5022353",
				"5022893",
				"5023754",
				"5025273",
				"5026427",
				"5027277",
				"5028226",
				"5029301",
				"5030286",
				"5031411",
				"5032248",
				"5033427",
				"5034176",
			},
		},
	},
	"Windows Server 2008 R2": {
		// https://support.microsoft.com/en-us/topic/windows-7-sp1-and-windows-server-2008-r2-sp1-update-history-720c2590-fd58-26ba-16cc-6d8f3b547599
		"SP1": {
			rollup: []windowsRelease{
				{revision: "", kb: "3172605"},
				{revision: "", kb: "3179573"},
				{revision: "", kb: "3185278"},
				{revision: "", kb: "3185330"},
				{revision: "", kb: "3192403"},
				{revision: "", kb: "3197868"},
				{revision: "", kb: "3197869"},
				{revision: "", kb: "3207752"},
				{revision: "", kb: "3212646"},
				{revision: "", kb: "4012215"},
				{revision: "", kb: "4012218"},
				{revision: "", kb: "4015549"},
				{revision: "", kb: "4015552"},
				{revision: "", kb: "4019264"},
				{revision: "", kb: "4019265"},
				{revision: "", kb: "4022719"},
				{revision: "", kb: "4022168"},
				{revision: "", kb: "4025341"},
				{revision: "", kb: "4025340"},
				{revision: "", kb: "4034664"},
				{revision: "", kb: "4034670"},
				{revision: "", kb: "4038777"},
				{revision: "", kb: "4038803"},
				{revision: "", kb: "4041681"},
				{revision: "", kb: "4041686"},
				{revision: "", kb: "4048957"},
				{revision: "", kb: "4051034"},
				{revision: "", kb: "4054518"},
				{revision: "", kb: "4056894"},
				{revision: "", kb: "4057400"},
				{revision: "", kb: "4074598"},
				{revision: "", kb: "4075211"},
				{revision: "", kb: "4088875"},
				{revision: "", kb: "4088881"},
				{revision: "", kb: "4093118"},
				{revision: "", kb: "4093113"},
				{revision: "", kb: "4103718"},
				{revision: "", kb: "4103713"},
				{revision: "", kb: "4284826"},
				{revision: "", kb: "4284842"},
				{revision: "", kb: "4338818"},
				{revision: "", kb: "4338821"},
				{revision: "", kb: "4343900"},
				{revision: "", kb: "4343894"},
				{revision: "", kb: "4457144"},
				{revision: "", kb: "4457139"},
				{revision: "", kb: "4462923"},
				{revision: "", kb: "4462927"},
				{revision: "", kb: "4467107"},
				{revision: "", kb: "4467108"},
				{revision: "", kb: "4471318"},
				{revision: "", kb: "4480970"},
				{revision: "", kb: "4480955"},
				{revision: "", kb: "4486563"},
				{revision: "", kb: "4486565"},
				{revision: "", kb: "4489878"},
				{revision: "", kb: "4489892"},
				{revision: "", kb: "4493472"},
				{revision: "", kb: "4493453"},
				{revision: "", kb: "4499164"},
				{revision: "", kb: "4499178"},
				{revision: "", kb: "4503292"},
				{revision: "", kb: "4503277"},
				{revision: "", kb: "4507449"},
				{revision: "", kb: "4507437"},
				{revision: "", kb: "4512506"},
				{revision: "", kb: "4512514"},
				{revision: "", kb: "4516065"},
				{revision: "", kb: "4516048"},
				{revision: "", kb: "4524157"},
				{revision: "", kb: "4519976"},
				{revision: "", kb: "4519972"},
				{revision: "", kb: "4525235"},
				{revision: "", kb: "4525251"},
				{revision: "", kb: "4530734"},
				{revision: "", kb: "4534310"},
				{revision: "", kb: "4539601"},
				{revision: "", kb: "4537820"},
				{revision: "", kb: "4540688"},
				{revision: "", kb: "4550964"},
				{revision: "", kb: "4556836"},
				{revision: "", kb: "4561643"},
				{revision: "", kb: "4565524"},
				{revision: "", kb: "4571729"},
				{revision: "", kb: "4577051"},
				{revision: "", kb: "4580345"},
				{revision: "", kb: "4586827"},
				{revision: "", kb: "4592471"},
				{revision: "", kb: "4598279"},
				{revision: "", kb: "4601347"},
				{revision: "", kb: "5000841"},
				{revision: "", kb: "5001335"},
				{revision: "", kb: "5003233"},
				{revision: "", kb: "5003667"},
				{revision: "", kb: "5004953"},
				{revision: "", kb: "5004289"},
				{revision: "", kb: "5005088"},
				{revision: "", kb: "5005633"},
				{revision: "", kb: "5006743"},
				{revision: "", kb: "5007236"},
				{revision: "", kb: "5008244"},
				{revision: "", kb: "5009610"},
				{revision: "", kb: "5010404"},
				{revision: "", kb: "5011552"},
				{revision: "", kb: "5012626"},
				{revision: "", kb: "5014012"},
				{revision: "", kb: "5014748"},
				{revision: "", kb: "5015861"},
				{revision: "", kb: "5016676"},
				{revision: "", kb: "5017361"},
				{revision: "", kb: "5018454"},
				{revision: "", kb: "5020000"},
				{revision: "", kb: "5021291"},
				{revision: "", kb: "5022338"},
				{revision: "", kb: "5022872"},
				{revision: "", kb: "5023769"},
				{revision: "", kb: "5025279"},
				{revision: "", kb: "5026413"},
				{revision: "", kb: "5027275"},
				{revision: "", kb: "5028240"},
				{revision: "", kb: "5029296"},
				{revision: "", kb: "5030265"},
				{revision: "", kb: "5031408"},
				{revision: "", kb: "5032252"},
				{revision: "", kb: "5033433"},
				{revision: "", kb: "5034169"},
			},
			securityOnly: []string{
				"3192391",
				"3197867",
				"3205394",
				"3212642",
				"4012212",
				"4015546",
				"4019263",
				"4022722",
				"4025337",
				"4034679",
				"4038779",
				"4041678",
				"4048960",
				"4054521",
				"4056897",
				"4074587",
				"4088878",
				"4093108",
				"4103712",
				"4284867",
				"4338823",
				"4343899",
				"4457145",
				"4462915",
				"4467106",
				"4471328",
				"4480960",
				"4486564",
				"4489885",
				"4493448",
				"4499175",
				"4503269",
				"4507456",
				"4512486",
				"4516033",
				"4520003",
				"4525233",
				"4530692",
				"4534314",
				"4537813",
				"4541500",
				"4550965",
				"4556843",
				"4561669",
				"4565539",
				"4571719",
				"4577053",
				"4580387",
				"4586805",
				"4592503",
				"4598289",
				"4601363",
				"5000851",
				"5001392",
				"5003228",
				"5003694",
				"5004951",
				"5004307",
				"5005089",
				"5005615",
				"5006728",
				"5007233",
				"5008282",
				"5009621",
				"5010422",
				"5011529",
				"5012649",
				"5013999",
				"5014742",
				"5015862",
				"5016679",
				"5017373",
				"5018479",
				"5020013",
				"5021288",
				"5022339",
				"5022874",
				"5023759",
				"5025277",
				"5026426",
				"5027256",
				"5028224",
				"5029307",
				"5030261",
				"5031441",
				"5032250",
				"5033424",
				"5034167",
			},
		},
	},
	"Windows Server 2012": {
		// https://support.microsoft.com/en-us/topic/windows-server-2012-update-history-abfb9afd-2ebf-1c19-4224-ad86f8741edd
		"": {
			rollup: []windowsRelease{
				{revision: "", kb: "3172615"},
				{revision: "", kb: "3179575"},
				{revision: "", kb: "3185280"},
				{revision: "", kb: "3185332"},
				{revision: "", kb: "3192406"},
				{revision: "", kb: "3197877"},
				{revision: "", kb: "3197878"},
				{revision: "", kb: "3205409"},
				{revision: "", kb: "4012217"},
				{revision: "", kb: "4012220"},
				{revision: "", kb: "4015551"},
				{revision: "", kb: "4015554"},
				{revision: "", kb: "4019216"},
				{revision: "", kb: "4019218"},
				{revision: "", kb: "4022724"},
				{revision: "", kb: "4022721"},
				{revision: "", kb: "4025331"},
				{revision: "", kb: "4025332"},
				{revision: "", kb: "4034665"},
				{revision: "", kb: "4034659"},
				{revision: "", kb: "4038799"},
				{revision: "", kb: "4038797"},
				{revision: "", kb: "4041690"},
				{revision: "", kb: "4041692"},
				{revision: "", kb: "4048959"},
				{revision: "", kb: "4050945"},
				{revision: "", kb: "4054520"},
				{revision: "", kb: "4056896"},
				{revision: "", kb: "4057402"},
				{revision: "", kb: "4074593"},
				{revision: "", kb: "4075213"},
				{revision: "", kb: "4088877"},
				{revision: "", kb: "4088883"},
				{revision: "", kb: "4093123"},
				{revision: "", kb: "4093116"},
				{revision: "", kb: "4103730"},
				{revision: "", kb: "4103719"},
				{revision: "", kb: "4284855"},
				{revision: "", kb: "4284852"},
				{revision: "", kb: "4338830"},
				{revision: "", kb: "4338816"},
				{revision: "", kb: "4343901"},
				{revision: "", kb: "4343895"},
				{revision: "", kb: "4457135"},
				{revision: "", kb: "4457134"},
				{revision: "", kb: "4462929"},
				{revision: "", kb: "4462925"},
				{revision: "", kb: "4467701"},
				{revision: "", kb: "4467683"},
				{revision: "", kb: "4471330"},
				{revision: "", kb: "4480975"},
				{revision: "", kb: "4480971"},
				{revision: "", kb: "4487025"},
				{revision: "", kb: "4487024"},
				{revision: "", kb: "4489891"},
				{revision: "", kb: "4489920"},
				{revision: "", kb: "4493451"},
				{revision: "", kb: "4493462"},
				{revision: "", kb: "4499171"},
				{revision: "", kb: "4499145"},
				{revision: "", kb: "4503285"},
				{revision: "", kb: "4503295"},
				{revision: "", kb: "4507462"},
				{revision: "", kb: "4507447"},
				{revision: "", kb: "4512518"},
				{revision: "", kb: "4512512"},
				{revision: "", kb: "4516055"},
				{revision: "", kb: "4516069"},
				{revision: "", kb: "4524154"},
				{revision: "", kb: "4520007"},
				{revision: "", kb: "4520013"},
				{revision: "", kb: "4525246"},
				{revision: "", kb: "4525242"},
				{revision: "", kb: "4530691"},
				{revision: "", kb: "4534283"},
				{revision: "", kb: "4534320"},
				{revision: "", kb: "4537814"},
				{revision: "", kb: "4537807"},
				{revision: "", kb: "4541510"},
				{revision: "", kb: "4541332"},
				{revision: "", kb: "4550917"},
				{revision: "", kb: "4550960"},
				{revision: "", kb: "4556840"},
				{revision: "", kb: "4561612"},
				{revision: "", kb: "4565537"},
				{revision: "", kb: "4571736"},
				{revision: "", kb: "4577038"},
				{revision: "", kb: "4580382"},
				{revision: "", kb: "4586834"},
				{revision: "", kb: "4592468"},
				{revision: "", kb: "4598278"},
				{revision: "", kb: "4601348"},
				{revision: "", kb: "5000847"},
				{revision: "", kb: "5001387"},
				{revision: "", kb: "5003208"},
				{revision: "", kb: "5003697"},
				{revision: "", kb: "5004956"},
				{revision: "", kb: "5004294"},
				{revision: "", kb: "5005099"},
				{revision: "", kb: "5005623"},
				{revision: "", kb: "5006739"},
				{revision: "", kb: "5007260"},
				{revision: "", kb: "5008277"},
				{revision: "", kb: "5009586"},
				{revision: "", kb: "5010392"},
				{revision: "", kb: "5011535"},
				{revision: "", kb: "5012650"},
				{revision: "", kb: "5014017"},
				{revision: "", kb: "5014747"},
				{revision: "", kb: "5015863"},
				{revision: "", kb: "5016672"},
				{revision: "", kb: "5017370"},
				{revision: "", kb: "5018457"},
				{revision: "", kb: "5020009"},
				{revision: "", kb: "5021285"},
				{revision: "", kb: "5022348"},
				{revision: "", kb: "5022903"},
				{revision: "", kb: "5023756"},
				{revision: "", kb: "5025287"},
				{revision: "", kb: "5026419"},
				{revision: "", kb: "5027283"},
				{revision: "", kb: "5028232"},
				{revision: "", kb: "5029295"},
				{revision: "", kb: "5030278"},
				{revision: "", kb: "5031442"},
				{revision: "", kb: "5032247"},
				{revision: "", kb: "5033429"},
				{revision: "", kb: "5034184"},
				{revision: "", kb: "5034830"},
				{revision: "", kb: "5035930"},
				{revision: "", kb: "5036969"},
				{revision: "", kb: "5037778"},
				{revision: "", kb: "5039260"},
				{revision: "", kb: "5040485"},
				{revision: "", kb: "5041851"},
				{revision: "", kb: "5043125"},
				{revision: "", kb: "5044342"},
				{revision: "", kb: "5046697"},
				{revision: "", kb: "5048699"},
				{revision: "", kb: "5050004"},
				{revision: "", kb: "5052020"},
				{revision: "", kb: "5053886"},
				{revision: "", kb: "5055581"},
				{revision: "", kb: "5058451"},
				{revision: "", kb: "5061059"},
				{revision: "", kb: "5062592"},
				{revision: "", kb: "5063906"},
				{revision: "", kb: "5065509"},
			},
			securityOnly: []string{
				"3192393",
				"3197876",
				"3205408",
				"4012214",
				"4015548",
				"4019214",
				"4022718",
				"4025343",
				"4034666",
				"4038786",
				"4041679",
				"4048962",
				"4054523",
				"4056899",
				"4074589",
				"4088880",
				"4093122",
				"4103726",
				"4284846",
				"4338820",
				"4343896",
				"4457140",
				"4462931",
				"4467678",
				"4471326",
				"4480972",
				"4486993",
				"4489884",
				"4493450",
				"4499158",
				"4503263",
				"4507464",
				"4512482",
				"4516062",
				"4519985",
				"4525253",
				"4530698",
				"4534288",
				"4537794",
				"4540694",
				"4550971",
				"4556852",
				"4561674",
				"4565535",
				"4571702",
				"4577048",
				"4580353",
				"4586808",
				"4592497",
				"4598297",
				"4601357",
				"5000840",
				"5001383",
				"5003203",
				"5003696",
				"5004960",
				"5004302",
				"5005094",
				"5005607",
				"5006732",
				"5007245",
				"5008255",
				"5009619",
				"5010412",
				"5011527",
				"5012666",
				"5014018",
				"5014741",
				"5015875",
				"5016684",
				"5017377",
				"5018478",
				"5020003",
				"5021303",
				"5022343",
				"5022895",
				"5023752",
				"5025272",
				"5026411",
				"5027281",
				"5028233",
				"5029308",
				"5030279",
				"5031427",
			},
		},
	},
	"Windows Server 2012 R2": {
		// https://support.microsoft.com/en-us/topic/windows-8-1-and-windows-server-2012-r2-update-history-47d81dd2-6804-b6ae-4112-20089467c7a6
		"": {
			rollup: []windowsRelease{
				{revision: "", kb: "3172614"},
				{revision: "", kb: "3179574"},
				{revision: "", kb: "3185279"},
				{revision: "", kb: "3185331"},
				{revision: "", kb: "3192404"},
				{revision: "", kb: "3197874"},
				{revision: "", kb: "3197875"},
				{revision: "", kb: "3205401"},
				{revision: "", kb: "4012216"},
				{revision: "", kb: "4012219"},
				{revision: "", kb: "4015550"},
				{revision: "", kb: "4015553"},
				{revision: "", kb: "4019215"},
				{revision: "", kb: "4019217"},
				{revision: "", kb: "4022726"},
				{revision: "", kb: "4022720"},
				{revision: "", kb: "4025336"},
				{revision: "", kb: "4025335"},
				{revision: "", kb: "4034681"},
				{revision: "", kb: "4034663"},
				{revision: "", kb: "4038792"},
				{revision: "", kb: "4038774"},
				{revision: "", kb: "4041693"},
				{revision: "", kb: "4041685"},
				{revision: "", kb: "4048958"},
				{revision: "", kb: "4050946"},
				{revision: "", kb: "4054519"},
				{revision: "", kb: "4056895"},
				{revision: "", kb: "4057401"},
				{revision: "", kb: "4074594"},
				{revision: "", kb: "4075212"},
				{revision: "", kb: "4088876"},
				{revision: "", kb: "4088882"},
				{revision: "", kb: "4093114"},
				{revision: "", kb: "4093121"},
				{revision: "", kb: "4103725"},
				{revision: "", kb: "4103724"},
				{revision: "", kb: "4284815"},
				{revision: "", kb: "4284863"},
				{revision: "", kb: "4338815"},
				{revision: "", kb: "4338831"},
				{revision: "", kb: "4343898"},
				{revision: "", kb: "4343891"},
				{revision: "", kb: "4457129"},
				{revision: "", kb: "4457133"},
				{revision: "", kb: "4462926"},
				{revision: "", kb: "4462921"},
				{revision: "", kb: "4467697"},
				{revision: "", kb: "4467695"},
				{revision: "", kb: "4471320"},
				{revision: "", kb: "4480963"},
				{revision: "", kb: "4480969"},
				{revision: "", kb: "4487000"},
				{revision: "", kb: "4487016"},
				{revision: "", kb: "4489881"},
				{revision: "", kb: "4489893"},
				{revision: "", kb: "4493446"},
				{revision: "", kb: "4493443"},
				{revision: "", kb: "4499151"},
				{revision: "", kb: "4499182"},
				{revision: "", kb: "4503276"},
				{revision: "", kb: "4503283"},
				{revision: "", kb: "4507448"},
				{revision: "", kb: "4507463"},
				{revision: "", kb: "4512488"},
				{revision: "", kb: "4512478"},
				{revision: "", kb: "4516067"},
				{revision: "", kb: "4516041"},
				{revision: "", kb: "4524156"},
				{revision: "", kb: "4520005"},
				{revision: "", kb: "4520012"},
				{revision: "", kb: "4525243"},
				{revision: "", kb: "4525252"},
				{revision: "", kb: "4530702"},
				{revision: "", kb: "4534297"},
				{revision: "", kb: "4534324"},
				{revision: "", kb: "4537821"},
				{revision: "", kb: "4537819"},
				{revision: "", kb: "4541509"},
				{revision: "", kb: "4541334"},
				{revision: "", kb: "4550961"},
				{revision: "", kb: "4550958"},
				{revision: "", kb: "4556846"},
				{revision: "", kb: "4561666"},
				{revision: "", kb: "4565541"},
				{revision: "", kb: "4571703"},
				{revision: "", kb: "4577066"},
				{revision: "", kb: "4580347"},
				{revision: "", kb: "4586845"},
				{revision: "", kb: "4592484"},
				{revision: "", kb: "4598285"},
				{revision: "", kb: "4601384"},
				{revision: "", kb: "5000848"},
				{revision: "", kb: "5001382"},
				{revision: "", kb: "5003209"},
				{revision: "", kb: "5003671"},
				{revision: "", kb: "5004954"},
				{revision: "", kb: "5004298"},
				{revision: "", kb: "5005076"},
				{revision: "", kb: "5005613"},
				{revision: "", kb: "5006714"},
				{revision: "", kb: "5007247"},
				{revision: "", kb: "5008263"},
				{revision: "", kb: "5009624"},
				{revision: "", kb: "5010419"},
				{revision: "", kb: "5011564"},
				{revision: "", kb: "5012670"},
				{revision: "", kb: "5014011"},
				{revision: "", kb: "5014738"},
				{revision: "", kb: "5015874"},
				{revision: "", kb: "5016681"},
				{revision: "", kb: "5017367"},
				{revision: "", kb: "5018474"},
				{revision: "", kb: "5020023"},
				{revision: "", kb: "5021294"},
				{revision: "", kb: "5022352"},
				{revision: "", kb: "5022899"},
				{revision: "", kb: "5023765"},
				{revision: "", kb: "5025285"},
				{revision: "", kb: "5026415"},
				{revision: "", kb: "5027271"},
				{revision: "", kb: "5028228"},
				{revision: "", kb: "5029312"},
				{revision: "", kb: "5030269"},
				{revision: "", kb: "5031419"},
				{revision: "", kb: "5032249"},
				{revision: "", kb: "5033420"},
				{revision: "", kb: "5034171"},
				{revision: "", kb: "5034819"},
				{revision: "", kb: "5035885"},
				{revision: "", kb: "5036960"},
				{revision: "", kb: "5037823"},
				{revision: "", kb: "5039294"},
				{revision: "", kb: "5040456"},
				{revision: "", kb: "5041828"},
				{revision: "", kb: "5043138"},
				{revision: "", kb: "5044343"},
				{revision: "", kb: "5046682"},
				{revision: "", kb: "5048735"},
				{revision: "", kb: "5050048"},
				{revision: "", kb: "5052042"},
				{revision: "", kb: "5053887"},
				{revision: "", kb: "5055557"},
				{revision: "", kb: "5058403"},
				{revision: "", kb: "5061018"},
				{revision: "", kb: "5062597"},
				{revision: "", kb: "5063950"},
				{revision: "", kb: "5065507"},
			},
			securityOnly: []string{
				"3192392",
				"3197873",
				"3205400",
				"4012213",
				"4015547",
				"4019213",
				"4022717",
				"4025333",
				"4034672",
				"4038793",
				"4041687",
				"4048961",
				"4054522",
				"4056898",
				"4074597",
				"4088879",
				"4093115",
				"4103715",
				"4284878",
				"4338824",
				"4343888",
				"4457143",
				"4462941",
				"4467703",
				"4471322",
				"4480964",
				"4487028",
				"4489883",
				"4493467",
				"4499165",
				"4503290",
				"4507457",
				"4512489",
				"4516064",
				"4519990",
				"4525250",
				"4530730",
				"4534309",
				"4537803",
				"4541505",
				"4550970",
				"4556853",
				"4561673",
				"4565540",
				"4571723",
				"4577071",
				"4580358",
				"4586823",
				"4592495",
				"4598275",
				"4601349",
				"5000853",
				"5001393",
				"5003220",
				"5003681",
				"5004958",
				"5004285",
				"5005106",
				"5005627",
				"5006729",
				"5007255",
				"5008285",
				"5009595",
				"5010395",
				"5011560",
				"5012639",
				"5014001",
				"5014746",
				"5015877",
				"5016683",
				"5017365",
				"5018476",
				"5020010",
				"5021296",
				"5022346",
				"5022894",
				"5023764",
				"5025288",
				"5026409",
				"5027282",
				"5028223",
				"5029304",
				"5030287",
				"5031407",
			},
		},
	},
	"Windows Server 2016": {
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2016-update-history-4acfbc84-a290-1b54-536a-1c0430e9f3fd
		"14393": {
			rollup: []windowsRelease{
				{revision: "10", kb: "3176929"},
				{revision: "51", kb: "3176495"},
				{revision: "82", kb: "3176934"},
				{revision: "105", kb: "3176938"},
				{revision: "187", kb: "3189866"},
				{revision: "187", kb: "3193494"},
				{revision: "189", kb: "3193494"},
				{revision: "222", kb: "3194496"},
				{revision: "321", kb: "3194798"},
				{revision: "351", kb: "3197954"},
				{revision: "447", kb: "3200970"},
				{revision: "448", kb: "3200970"},
				{revision: "479", kb: "3201845"},
				{revision: "571", kb: "3206632"},
				{revision: "576", kb: "3206632"},
				{revision: "693", kb: "3213986"},
				{revision: "729", kb: "4010672"},
				{revision: "953", kb: "4013429"},
				{revision: "969", kb: "4015438"},
				{revision: "970", kb: "4016635"},
				{revision: "1066", kb: "4015217"},
				{revision: "1083", kb: "4015217"},
				{revision: "1198", kb: "4019472"},
				{revision: "1230", kb: "4023680"},
				{revision: "1358", kb: "4022715"},
				{revision: "1378", kb: "4022723"},
				{revision: "1480", kb: "4025339"},
				{revision: "1532", kb: "4025334"},
				{revision: "1537", kb: "4038220"},
				{revision: "1593", kb: "4034658"},
				{revision: "1613", kb: "4034661"},
				{revision: "1670", kb: "4039396"},
				{revision: "1715", kb: "4038782"},
				{revision: "1737", kb: "4038801"},
				{revision: "1770", kb: "4041691"},
				{revision: "1794", kb: "4041688"},
				{revision: "1797", kb: "4052231"},
				{revision: "1884", kb: "4048953"},
				{revision: "1914", kb: "4051033"},
				{revision: "1944", kb: "4053579"},
				{revision: "2007", kb: "4056890"},
				{revision: "2034", kb: "4057142"},
				{revision: "2035", kb: "4057142"},
				{revision: "2068", kb: "4074590"},
				{revision: "2097", kb: "4077525"},
				{revision: "2125", kb: "4088787"},
				{revision: "2126", kb: "4088787"},
				{revision: "2155", kb: "4088889"},
				{revision: "2156", kb: "4096309"},
				{revision: "2189", kb: "4093119"},
				{revision: "2214", kb: "4093120"},
				{revision: "2248", kb: "4103723"},
				{revision: "2273", kb: "4103720"},
				{revision: "2312", kb: "4284880"},
				{revision: "2339", kb: "4284833"},
				{revision: "2363", kb: "4338814"},
				{revision: "2368", kb: "4345418"},
				{revision: "2395", kb: "4338822"},
				{revision: "2396", kb: "4346877"},
				{revision: "2430", kb: "4343887"},
				{revision: "2457", kb: "4343884"},
				{revision: "2485", kb: "4457131"},
				{revision: "2515", kb: "4457127"},
				{revision: "2551", kb: "4462917"},
				{revision: "2580", kb: "4462928"},
				{revision: "2608", kb: "4467691"},
				{revision: "2639", kb: "4467684"},
				{revision: "2641", kb: "4478877"},
				{revision: "2665", kb: "4471321"},
				{revision: "2670", kb: "4483229"},
				{revision: "2724", kb: "4480961"},
				{revision: "2759", kb: "4480977"},
				{revision: "2791", kb: "4487026"},
				{revision: "2828", kb: "4487006"},
				{revision: "2848", kb: "4489882"},
				{revision: "2879", kb: "4489889"},
				{revision: "2906", kb: "4493470"},
				{revision: "2908", kb: "4499418"},
				{revision: "2941", kb: "4493473"},
				{revision: "2969", kb: "4494440"},
				{revision: "2972", kb: "4505052"},
				{revision: "2999", kb: "4499177"},
				{revision: "3025", kb: "4503267"},
				{revision: "3053", kb: "4503294"},
				{revision: "3056", kb: "4509475"},
				{revision: "3085", kb: "4507460"},
				{revision: "3115", kb: "4507459"},
				{revision: "3144", kb: "4512517"},
				{revision: "3181", kb: "4512495"},
				{revision: "3204", kb: "4516044"},
				{revision: "3206", kb: "4522010"},
				{revision: "3242", kb: "4516061"},
				{revision: "3243", kb: "4524152"},
				{revision: "3274", kb: "4519998"},
				{revision: "3300", kb: "4519979"},
				{revision: "3326", kb: "4525236"},
				{revision: "3384", kb: "4530689"},
				{revision: "3443", kb: "4534271"},
				{revision: "3474", kb: "4534307"},
				{revision: "3504", kb: "4537764"},
				{revision: "3542", kb: "4537806"},
				{revision: "3564", kb: "4540670"},
				{revision: "3595", kb: "4541329"},
				{revision: "3630", kb: "4550929"},
				{revision: "3659", kb: "4550947"},
				{revision: "3686", kb: "4556813"},
				{revision: "3750", kb: "4561616"},
				{revision: "3755", kb: "4567517"},
				{revision: "3808", kb: "4565511"},
				{revision: "3866", kb: "4571694"},
				{revision: "3930", kb: "4577015"},
				{revision: "3986", kb: "4580346"},
				{revision: "4046", kb: "4586830"},
				{revision: "4048", kb: "4594441"},
				{revision: "4104", kb: "4593226"},
				{revision: "4169", kb: "4598243"},
				{revision: "4225", kb: "4601318"},
				{revision: "4283", kb: "5000803"},
				{revision: "4288", kb: "5001633"},
				{revision: "4350", kb: "5001347"},
				{revision: "4402", kb: "5003197"},
				{revision: "4467", kb: "5003638"},
				{revision: "4470", kb: "5004948"},
				{revision: "4530", kb: "5004238"},
				{revision: "4532", kb: "5005393"},
				{revision: "4583", kb: "5005043"},
				{revision: "4651", kb: "5005573"},
				{revision: "4704", kb: "5006669"},
				{revision: "4770", kb: "5007192"},
				{revision: "4771", kb: "5008601"},
				{revision: "4825", kb: "5008207"},
				{revision: "4827", kb: "5010195"},
				{revision: "4886", kb: "5009546"},
				{revision: "4889", kb: "5010790"},
				{revision: "4946", kb: "5010359"},
				{revision: "5006", kb: "5011495"},
				{revision: "5066", kb: "5012596"},
				{revision: "5125", kb: "5013952"},
				{revision: "5127", kb: "5015019"},
				{revision: "5192", kb: "5014702"},
				{revision: "5246", kb: "5015808"},
				{revision: "5291", kb: "5016622"},
				{revision: "5356", kb: "5017305"},
				{revision: "5427", kb: "5018411"},
				{revision: "5429", kb: "5020439"},
				{revision: "5501", kb: "5019964"},
				{revision: "5502", kb: "5021654"},
				{revision: "5582", kb: "5021235"},
				{revision: "5648", kb: "5022289"},
				{revision: "5717", kb: "5022838"},
				{revision: "5786", kb: "5023697"},
				{revision: "5850", kb: "5025228"},
				{revision: "5921", kb: "5026363"},
				{revision: "5989", kb: "5027219"},
				{revision: "5996", kb: "5028623"},
				{revision: "6085", kb: "5028169"},
				{revision: "6167", kb: "5029242"},
				{revision: "6252", kb: "5030213"},
				{revision: "6351", kb: "5031362"},
				{revision: "6452", kb: "5032197"},
				{revision: "6529", kb: "5033373"},
				{revision: "6614", kb: "5034119"},
				{revision: "6709", kb: "5034767"},
				{revision: "6796", kb: "5035855"},
				{revision: "6799", kb: "5037423"},
				{revision: "6800", kb: "5037423"},
				{revision: "6897", kb: "5036899"},
				{revision: "6981", kb: "5037763"},
				{revision: "7070", kb: "5039214"},
				{revision: "7159", kb: "5040434"},
				{revision: "7259", kb: "5041773"},
				{revision: "7336", kb: "5043051"},
				{revision: "7428", kb: "5044293"},
				{revision: "7515", kb: "5046612"},
				{revision: "7606", kb: "5048671"},
				{revision: "7699", kb: "5049993"},
				{revision: "7785", kb: "5052006"},
				{revision: "7876", kb: "5053594"},
				{revision: "7969", kb: "5055521"},
				{revision: "7973", kb: "5058921"},
				{revision: "8066", kb: "5058383"},
				{revision: "8148", kb: "5061010"},
				{revision: "8246", kb: "5062560"},
				{revision: "8330", kb: "5063871"},
				{revision: "8422", kb: "5065427"},
			},
		},
	},
	"Windows Server, Version 1709": {
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562
		"16299": {
			rollup: []windowsRelease{
				{revision: "19", kb: "4043961"},
				{revision: "64", kb: "4048955"},
				{revision: "98", kb: "4051963"},
				{revision: "125", kb: "4054517"},
				{revision: "192", kb: "4056892"},
				{revision: "194", kb: "4073290"},
				{revision: "201", kb: "4073291"},
				{revision: "214", kb: "4058258"},
				{revision: "248", kb: "4074588"},
				{revision: "251", kb: "4090913"},
				{revision: "309", kb: "4088776"},
				{revision: "334", kb: "4089848"},
				{revision: "371", kb: "4093112"},
				{revision: "402", kb: "4093105"},
				{revision: "431", kb: "4103727"},
				{revision: "461", kb: "4103714"},
				{revision: "492", kb: "4284819"},
				{revision: "522", kb: "4284822"},
				{revision: "547", kb: "4338825"},
				{revision: "551", kb: "4345420"},
				{revision: "579", kb: "4338817"},
				{revision: "611", kb: "4343897"},
				{revision: "637", kb: "4343893"},
				{revision: "665", kb: "4457142"},
				{revision: "666", kb: "4464217"},
				{revision: "699", kb: "4457136"},
				{revision: "726", kb: "4462918"},
				{revision: "755", kb: "4462932"},
				{revision: "785", kb: "4467686"},
				{revision: "820", kb: "4467681"},
				{revision: "846", kb: "4471329"},
				{revision: "847", kb: "4483232"},
				{revision: "904", kb: "4480978"},
				{revision: "936", kb: "4480967"},
				{revision: "967", kb: "4486996"},
				{revision: "1004", kb: "4487021"},
				{revision: "1029", kb: "4489886"},
				{revision: "1059", kb: "4489890"},
				{revision: "1087", kb: "4493441"},
				{revision: "1127", kb: "4493440"},
				{revision: "1146", kb: "4499179"},
				{revision: "1150", kb: "4505062"},
				{revision: "1182", kb: "4499147"},
				{revision: "1217", kb: "4503284"},
				{revision: "1237", kb: "4503281"},
				{revision: "1239", kb: "4509477"},
				{revision: "1268", kb: "4507455"},
				{revision: "1296", kb: "4507465"},
				{revision: "1331", kb: "4512516"},
				{revision: "1365", kb: "4512494"},
				{revision: "1387", kb: "4516066"},
				{revision: "1392", kb: "4522012"},
				{revision: "1420", kb: "4516071"},
				{revision: "1421", kb: "4524150"},
				{revision: "1451", kb: "4520004"},
				{revision: "1481", kb: "4520006"},
				{revision: "1508", kb: "4525241"},
				{revision: "1565", kb: "4530714"},
				{revision: "1625", kb: "4534276"},
				{revision: "1654", kb: "4534318"},
				{revision: "1686", kb: "4537789"},
				{revision: "1717", kb: "4537816"},
				{revision: "1747", kb: "4540681"},
				{revision: "1775", kb: "4541330"},
				{revision: "1776", kb: "4554342"},
				{revision: "1806", kb: "4550927"},
				{revision: "1868", kb: "4556812"},
				{revision: "1932", kb: "4561602"},
				{revision: "1937", kb: "4567515"},
				{revision: "1992", kb: "4565508"},
				{revision: "2045", kb: "4571741"},
				{revision: "2107", kb: "4577041"},
				{revision: "2166", kb: "4580328"},
			},
		},
	},
	"Windows Server, Version 1803": {
		"17134": {
			rollup: []windowsRelease{},
		},
	},
	"Windows Server, Version 1809": {
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2019-update-history-725fc2e1-4443-6831-a5ca-51ff5cbcb059
		"17763": {
			rollup: []windowsRelease{
				{revision: "1", kb: ""},
				{revision: "55", kb: "4464330"},
				{revision: "107", kb: "4464455"},
				{revision: "134", kb: "4467708"},
				{revision: "168", kb: "4469342"},
				{revision: "194", kb: "4471332"},
				{revision: "195", kb: "4483235"},
				{revision: "253", kb: "4480116"},
				{revision: "292", kb: "4476976"},
				{revision: "316", kb: "4487044"},
				{revision: "348", kb: "4482887"},
				{revision: "379", kb: "4489899"},
				{revision: "402", kb: "4490481"},
				{revision: "404", kb: "4490481"},
				{revision: "437", kb: "4493509"},
				{revision: "439", kb: "4501835"},
				{revision: "475", kb: "4495667"},
				{revision: "503", kb: "4494441"},
				{revision: "504", kb: "4505056"},
				{revision: "529", kb: "4497934"},
				{revision: "557", kb: "4503327"},
				{revision: "592", kb: "4501371"},
				{revision: "593", kb: "4509479"},
				{revision: "615", kb: "4507469"},
				{revision: "652", kb: "4505658"},
				{revision: "678", kb: "4511553"},
				{revision: "720", kb: "4512534"},
				{revision: "737", kb: "4512578"},
				{revision: "740", kb: "4522015"},
				{revision: "774", kb: "4516077"},
				{revision: "775", kb: "4524148"},
				{revision: "805", kb: "4519338"},
				{revision: "832", kb: "4520062"},
				{revision: "864", kb: "4523205"},
				{revision: "914", kb: "4530715"},
				{revision: "973", kb: "4534273"},
				{revision: "1012", kb: "4534321"},
				{revision: "1039", kb: "4532691"},
				{revision: "1075", kb: "4537818"},
				{revision: "1098", kb: "4538461"},
				{revision: "1131", kb: "4541331"},
				{revision: "1132", kb: "4554354"},
				{revision: "1158", kb: "4549949"},
				{revision: "1192", kb: "4550969"},
				{revision: "1217", kb: "4551853"},
				{revision: "1282", kb: "4561608"},
				{revision: "1294", kb: "4567513"},
				{revision: "1339", kb: "4558998"},
				{revision: "1369", kb: "4559003"},
				{revision: "1397", kb: "4565349"},
				{revision: "1432", kb: "4571748"},
				{revision: "1457", kb: "4570333"},
				{revision: "1490", kb: "4577069"},
				{revision: "1518", kb: "4577668"},
				{revision: "1554", kb: "4580390"},
				{revision: "1577", kb: "4586793"},
				{revision: "1579", kb: "4594442"},
				{revision: "1613", kb: "4586839"},
				{revision: "1637", kb: "4592440"},
				{revision: "1697", kb: "4598230"},
				{revision: "1728", kb: "4598296"},
				{revision: "1757", kb: "4601345"},
				{revision: "1790", kb: "4601383"},
				{revision: "1817", kb: "5000822"},
				{revision: "1821", kb: "5001568"},
				{revision: "1823", kb: "5001638"},
				{revision: "1852", kb: "5000854"},
				{revision: "1879", kb: "5001342"},
				{revision: "1911", kb: "5001384"},
				{revision: "1935", kb: "5003171"},
			},
		},
	},
	"Windows Server 2019": {
		// https://support.microsoft.com/en-us/topic/windows-10-and-windows-server-2019-update-history-725fc2e1-4443-6831-a5ca-51ff5cbcb059
		"17763": {
			rollup: []windowsRelease{
				{revision: "1", kb: ""},
				{revision: "55", kb: "4464330"},
				{revision: "107", kb: "4464455"},
				{revision: "134", kb: "4467708"},
				{revision: "168", kb: "4469342"},
				{revision: "194", kb: "4471332"},
				{revision: "195", kb: "4483235"},
				{revision: "253", kb: "4480116"},
				{revision: "292", kb: "4476976"},
				{revision: "316", kb: "4487044"},
				{revision: "348", kb: "4482887"},
				{revision: "379", kb: "4489899"},
				{revision: "402", kb: "4490481"},
				{revision: "404", kb: "4490481"},
				{revision: "437", kb: "4493509"},
				{revision: "439", kb: "4501835"},
				{revision: "475", kb: "4495667"},
				{revision: "503", kb: "4494441"},
				{revision: "504", kb: "4505056"},
				{revision: "529", kb: "4497934"},
				{revision: "557", kb: "4503327"},
				{revision: "592", kb: "4501371"},
				{revision: "593", kb: "4509479"},
				{revision: "615", kb: "4507469"},
				{revision: "652", kb: "4505658"},
				{revision: "678", kb: "4511553"},
				{revision: "720", kb: "4512534"},
				{revision: "737", kb: "4512578"},
				{revision: "740", kb: "4522015"},
				{revision: "774", kb: "4516077"},
				{revision: "775", kb: "4524148"},
				{revision: "805", kb: "4519338"},
				{revision: "832", kb: "4520062"},
				{revision: "864", kb: "4523205"},
				{revision: "914", kb: "4530715"},
				{revision: "973", kb: "4534273"},
				{revision: "1012", kb: "4534321"},
				{revision: "1039", kb: "4532691"},
				{revision: "1075", kb: "4537818"},
				{revision: "1098", kb: "4538461"},
				{revision: "1131", kb: "4541331"},
				{revision: "1132", kb: "4554354"},
				{revision: "1158", kb: "4549949"},
				{revision: "1192", kb: "4550969"},
				{revision: "1217", kb: "4551853"},
				{revision: "1282", kb: "4561608"},
				{revision: "1294", kb: "4567513"},
				{revision: "1339", kb: "4558998"},
				{revision: "1369", kb: "4559003"},
				{revision: "1397", kb: "4565349"},
				{revision: "1432", kb: "4571748"},
				{revision: "1457", kb: "4570333"},
				{revision: "1490", kb: "4577069"},
				{revision: "1518", kb: "4577668"},
				{revision: "1554", kb: "4580390"},
				{revision: "1577", kb: "4586793"},
				{revision: "1579", kb: "4594442"},
				{revision: "1613", kb: "4586839"},
				{revision: "1637", kb: "4592440"},
				{revision: "1697", kb: "4598230"},
				{revision: "1728", kb: "4598296"},
				{revision: "1757", kb: "4601345"},
				{revision: "1790", kb: "4601383"},
				{revision: "1817", kb: "5000822"},
				{revision: "1821", kb: "5001568"},
				{revision: "1823", kb: "5001638"},
				{revision: "1852", kb: "5000854"},
				{revision: "1879", kb: "5001342"},
				{revision: "1911", kb: "5001384"},
				{revision: "1935", kb: "5003171"},
				{revision: "1971", kb: "5003217"},
				{revision: "1999", kb: "5003646"},
				{revision: "2028", kb: "5003703"},
				{revision: "2029", kb: "5004947"},
				{revision: "2061", kb: "5004244"},
				{revision: "2090", kb: "5004308"},
				{revision: "2091", kb: "5005394"},
				{revision: "2114", kb: "5005030"},
				{revision: "2145", kb: "5005102"},
				{revision: "2183", kb: "5005568"},
				{revision: "2210", kb: "5005625"},
				{revision: "2213", kb: "5005625"},
				{revision: "2237", kb: "5006672"},
				{revision: "2268", kb: "5006744"},
				{revision: "2300", kb: "5007206"},
				{revision: "2305", kb: "5008602"},
				{revision: "2330", kb: "5007266"},
				{revision: "2366", kb: "5008218"},
				{revision: "2369", kb: "5010196"},
				{revision: "2452", kb: "5009557"},
				{revision: "2458", kb: "5010791"},
				{revision: "2510", kb: "5009616"},
				{revision: "2565", kb: "5010351"},
				{revision: "2628", kb: "5010427"},
				{revision: "2686", kb: "5011503"},
				{revision: "2746", kb: "5011551"},
				{revision: "2803", kb: "5012647"},
				{revision: "2867", kb: "5012636"},
				{revision: "2928", kb: "5013941"},
				{revision: "2931", kb: "5015018"},
				{revision: "2989", kb: "5014022"},
				{revision: "3046", kb: "5014692"},
				{revision: "3113", kb: "5014669"},
				{revision: "3165", kb: "5015811"},
				{revision: "3232", kb: "5015880"},
				{revision: "3287", kb: "5016623"},
				{revision: "3346", kb: "5016690"},
				{revision: "3406", kb: "5017315"},
				{revision: "3469", kb: "5017379"},
				{revision: "3532", kb: "5018419"},
				{revision: "3534", kb: "5020438"},
				{revision: "3650", kb: "5019966"},
				{revision: "3653", kb: "5021655"},
				{revision: "3770", kb: "5021237"},
				{revision: "3772", kb: "5022554"},
				{revision: "3887", kb: "5022286"},
				{revision: "4010", kb: "5022840"},
				{revision: "4131", kb: "5023702"},
				{revision: "4252", kb: "5025229"},
				{revision: "4377", kb: "5026362"},
				{revision: "4499", kb: "5027222"},
				{revision: "4645", kb: "5028168"},
				{revision: "4737", kb: "5029247"},
				{revision: "4851", kb: "5030214"},
				{revision: "4974", kb: "5031361"},
				{revision: "5122", kb: "5032196"},
				{revision: "5206", kb: "5033371"},
				{revision: "5329", kb: "5034127"},
				{revision: "5458", kb: "5034768"},
				{revision: "5576", kb: "5035849"},
				{revision: "5579", kb: "5037425"},
				{revision: "5696", kb: "5036896"},
				{revision: "5820", kb: "5037765"},
				{revision: "5830", kb: "5039705"},
				{revision: "5936", kb: "5039217"},
				{revision: "6054", kb: "5040430"},
				{revision: "6189", kb: "5041578"},
				{revision: "6293", kb: "5043050"},
				{revision: "6414", kb: "5044277"},
				{revision: "6532", kb: "5046615"},
				{revision: "6659", kb: "5048661"},
				{revision: "6775", kb: "5050008"},
				{revision: "6893", kb: "5052000"},
				{revision: "7009", kb: "5053596"},
				{revision: "7136", kb: "5055519"},
				{revision: "7240", kb: "5058922"},
				{revision: "7249", kb: "5059091"},
				{revision: "7314", kb: "5058392"},
				{revision: "7322", kb: "5061978"},
				{revision: "7434", kb: "5060531"},
				{revision: "7558", kb: "5062557"},
				{revision: "7678", kb: "5063877"},
				{revision: "7683", kb: "5066187"},
				{revision: "7792", kb: "5065428"},
			},
		},
	},
	"Windows Server, Version 1903": {
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-e6058e7c-4116-38f1-b984-4fcacfba5e5d
		"18362": {
			rollup: []windowsRelease{
				{revision: "116", kb: "4505057"},
				{revision: "145", kb: "4497935"},
				{revision: "175", kb: "4503293"},
				{revision: "207", kb: "4501375"},
				{revision: "239", kb: "4507453"},
				{revision: "267", kb: "4505903"},
				{revision: "295", kb: "4512508"},
				{revision: "329", kb: "4512941"},
				{revision: "356", kb: "4515384"},
				{revision: "357", kb: "4522016"},
				{revision: "387", kb: "4517211"},
				{revision: "388", kb: "4524147"},
				{revision: "418", kb: "4517389"},
				{revision: "449", kb: "4522355"},
				{revision: "476", kb: "4524570"},
				{revision: "535", kb: "4530684"},
				{revision: "592", kb: "4528760"},
				{revision: "628", kb: "4532695"},
				{revision: "657", kb: "4532693"},
				{revision: "693", kb: "4535996"},
				{revision: "719", kb: "4540673"},
				{revision: "720", kb: "4551762"},
				{revision: "752", kb: "4541335"},
				{revision: "753", kb: "4554364"},
				{revision: "778", kb: "4549951"},
				{revision: "815", kb: "4550945"},
				{revision: "836", kb: "4556799"},
				{revision: "900", kb: "4560960"},
				{revision: "904", kb: "4567512"},
				{revision: "959", kb: "4565483"},
				{revision: "997", kb: "4559004"},
				{revision: "1016", kb: "4565351"},
				{revision: "1049", kb: "4566116"},
				{revision: "1082", kb: "4574727"},
				{revision: "1110", kb: "4577062"},
				{revision: "1139", kb: "4577671"},
				{revision: "1171", kb: "4580386"},
				{revision: "1198", kb: "4586786"},
				{revision: "1199", kb: "4594443"},
				{revision: "1237", kb: "4586819"},
				{revision: "1256", kb: "4592449"},
			},
		},
	},
	"Windows Server, Version 1909": {
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-53c270dc-954f-41f7-7ced-488578904dfe
		"18363": {
			rollup: []windowsRelease{
				{revision: "476", kb: "4524570"},
				{revision: "535", kb: "4530684"},
				{revision: "592", kb: "4528760"},
				{revision: "628", kb: "4532695"},
				{revision: "657", kb: "4532693"},
				{revision: "693", kb: "4535996"},
				{revision: "719", kb: "4540673"},
				{revision: "720", kb: "4551762"},
				{revision: "752", kb: "4541335"},
				{revision: "753", kb: "4554364"},
				{revision: "778", kb: "4549951"},
				{revision: "815", kb: "4550945"},
				{revision: "836", kb: "4556799"},
				{revision: "900", kb: "4560960"},
				{revision: "904", kb: "4567512"},
				{revision: "959", kb: "4565483"},
				{revision: "997", kb: "4559004"},
				{revision: "1016", kb: "4565351"},
				{revision: "1049", kb: "4566116"},
				{revision: "1082", kb: "4574727"},
				{revision: "1110", kb: "4577062"},
				{revision: "1139", kb: "4577671"},
				{revision: "1171", kb: "4580386"},
				{revision: "1198", kb: "4586786"},
				{revision: "1199", kb: "4594443"},
				{revision: "1237", kb: "4586819"},
				{revision: "1256", kb: "4592449"},
				{revision: "1316", kb: "4598229"},
				{revision: "1350", kb: "4598298"},
				{revision: "1377", kb: "4601315"},
				{revision: "1379", kb: "5001028"},
				{revision: "1411", kb: "4601380"},
				{revision: "1440", kb: "5000808"},
				{revision: "1441", kb: "5001566"},
				{revision: "1443", kb: "5001648"},
				{revision: "1474", kb: "5000850"},
				{revision: "1500", kb: "5001337"},
				{revision: "1533", kb: "5001396"},
				{revision: "1556", kb: "5003169"},
				{revision: "1593", kb: "5003212"},
				{revision: "1621", kb: "5003635"},
				{revision: "1645", kb: "5003698"},
				{revision: "1646", kb: "5004946"},
				{revision: "1679", kb: "5004245"},
				{revision: "1714", kb: "5004293"},
				{revision: "1734", kb: "5005031"},
				{revision: "1766", kb: "5005103"},
				{revision: "1801", kb: "5005566"},
				{revision: "1830", kb: "5005624"},
				{revision: "1832", kb: "5005624"},
				{revision: "1854", kb: "5006667"},
				{revision: "1916", kb: "5007189"},
				{revision: "1977", kb: "5008206"},
				{revision: "2037", kb: "5009545"},
				{revision: "2039", kb: "5010792"},
				{revision: "2094", kb: "5010345"},
				{revision: "2158", kb: "5011485"},
				{revision: "2212", kb: "5012591"},
				{revision: "2274", kb: "5013945"},
			},
		},
	},
	"Windows Server, Version 2004": {
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-24ea91f4-36e7-d8fd-0ddb-d79d9d0cdbda
		"19041": {
			rollup: []windowsRelease{
				{revision: "264", kb: ""},
				{revision: "329", kb: "4557957"},
				{revision: "331", kb: "4567523"},
				{revision: "388", kb: "4565503"},
				{revision: "423", kb: "4568831"},
				{revision: "450", kb: "4566782"},
				{revision: "488", kb: "4571744"},
				{revision: "508", kb: "4571756"},
				{revision: "546", kb: "4577063"},
				{revision: "572", kb: "4579311"},
				{revision: "610", kb: "4580364"},
				{revision: "630", kb: "4586781"},
				{revision: "631", kb: "4594440"},
				{revision: "662", kb: "4586853"},
				{revision: "685", kb: "4592438"},
				{revision: "746", kb: "4598242"},
				{revision: "789", kb: "4598291"},
				{revision: "804", kb: "4601319"},
				{revision: "844", kb: "4601382"},
				{revision: "867", kb: "5000802"},
				{revision: "868", kb: "5001567"},
				{revision: "870", kb: "5001649"},
				{revision: "906", kb: "5000842"},
				{revision: "928", kb: "5001330"},
				{revision: "964", kb: "5001391"},
				{revision: "985", kb: "5003173"},
				{revision: "1023", kb: "5003214"},
				{revision: "1052", kb: "5003637"},
				{revision: "1055", kb: "5004476"},
				{revision: "1081", kb: "5003690"},
				{revision: "1082", kb: "5004760"},
				{revision: "1083", kb: "5004945"},
				{revision: "1110", kb: "5004237"},
				{revision: "1151", kb: "5004296"},
				{revision: "1165", kb: "5005033"},
				{revision: "1202", kb: "5005101"},
				{revision: "1237", kb: "5005565"},
				{revision: "1266", kb: "5005611"},
				{revision: "1288", kb: "5006670"},
				{revision: "1320", kb: "5006738"},
				{revision: "1348", kb: "5007186"},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
			},
		},
	},
	"Windows Server, Version 20H2": {
		// https://support.microsoft.com/en-us/topic/windows-10-update-history-7dd3071a-3906-fa2c-c342-f7f86728a6e3
		"19042": {
			rollup: []windowsRelease{
				{revision: "572", kb: ""},
				{revision: "610", kb: "4580364"},
				{revision: "630", kb: "4586781"},
				{revision: "631", kb: "4594440"},
				{revision: "662", kb: "4586853"},
				{revision: "685", kb: "4592438"},
				{revision: "746", kb: "4598242"},
				{revision: "789", kb: "4598291"},
				{revision: "804", kb: "4601319"},
				{revision: "844", kb: "4601382"},
				{revision: "867", kb: "5000802"},
				{revision: "868", kb: "5001567"},
				{revision: "870", kb: "5001649"},
				{revision: "906", kb: "5000842"},
				{revision: "928", kb: "5001330"},
				{revision: "964", kb: "5001391"},
				{revision: "985", kb: "5003173"},
				{revision: "1023", kb: "5003214"},
				{revision: "1052", kb: "5003637"},
				{revision: "1055", kb: "5004476"},
				{revision: "1081", kb: "5003690"},
				{revision: "1082", kb: "5004760"},
				{revision: "1083", kb: "5004945"},
				{revision: "1110", kb: "5004237"},
				{revision: "1151", kb: "5004296"},
				{revision: "1165", kb: "5005033"},
				{revision: "1202", kb: "5005101"},
				{revision: "1237", kb: "5005565"},
				{revision: "1266", kb: "5005611"},
				{revision: "1288", kb: "5006670"},
				{revision: "1320", kb: "5006738"},
				{revision: "1348", kb: "5007186"},
				{revision: "1387", kb: "5007253"},
				{revision: "1415", kb: "5008212"},
				{revision: "1466", kb: "5009543"},
				{revision: "1469", kb: "5010793"},
				{revision: "1503", kb: "5009596"},
				{revision: "1526", kb: "5010342"},
				{revision: "1566", kb: "5010415"},
				{revision: "1586", kb: "5011487"},
				{revision: "1620", kb: "5011543"},
				{revision: "1645", kb: "5012599"},
				{revision: "1682", kb: "5011831"},
				{revision: "1706", kb: "5013942"},
				{revision: "1708", kb: "5015020"},
				{revision: "1741", kb: "5014023"},
				{revision: "1766", kb: "5014699"},
				{revision: "1767", kb: "5016139"},
				{revision: "1806", kb: "5014666"},
				{revision: "1826", kb: "5015807"},
				{revision: "1865", kb: "5015878"},
				{revision: "1889", kb: "5016616"},
				{revision: "1949", kb: "5016688"},
				{revision: "2006", kb: "5017308"},
				{revision: "2075", kb: "5017380"},
				{revision: "2130", kb: "5018410"},
				{revision: "2132", kb: "5020435"},
				{revision: "2193", kb: "5018482"},
				{revision: "2194", kb: "5020953"},
				{revision: "2251", kb: "5019959"},
				{revision: "2311", kb: "5020030"},
				{revision: "2364", kb: "5021233"},
				{revision: "2486", kb: "5022282"},
				{revision: "2546", kb: "5019275"},
				{revision: "2604", kb: "5022834"},
				{revision: "2673", kb: "5022906"},
				{revision: "2728", kb: "5023696"},
				{revision: "2788", kb: "5023773"},
				{revision: "2846", kb: "5025221"},
				{revision: "2965", kb: "5026361"},
			},
		},
	},
	"Windows Server 2022": {
		// https://support.microsoft.com/en-us/topic/windows-server-2022-update-history-e1caa597-00c5-4ab9-9f3e-8212fe80b2ee
		"20348": {
			rollup: []windowsRelease{
				{revision: "202", kb: "5005104"},
				{revision: "230", kb: "5005575"},
				{revision: "261", kb: "5005619"},
				{revision: "288", kb: "5006699"},
				{revision: "320", kb: "5006745"},
				{revision: "350", kb: "5007205"},
				{revision: "380", kb: "5007254"},
				{revision: "405", kb: "5008223"},
				{revision: "407", kb: "5010197"},
				{revision: "469", kb: "5009555"},
				{revision: "473", kb: "5010796"},
				{revision: "502", kb: "5009608"},
				{revision: "524", kb: "5010354"},
				{revision: "558", kb: "5010421"},
				{revision: "587", kb: "5011497"},
				{revision: "617", kb: "5011558"},
				{revision: "643", kb: "5012604"},
				{revision: "681", kb: "5012637"},
				{revision: "707", kb: "5013944"},
				{revision: "709", kb: "5015013"},
				{revision: "740", kb: "5014021"},
				{revision: "768", kb: "5014678"},
				{revision: "803", kb: "5014665"},
				{revision: "825", kb: "5015827"},
				{revision: "859", kb: "5015879"},
				{revision: "887", kb: "5016627"},
				{revision: "946", kb: "5016693"},
				{revision: "1006", kb: "5017316"},
				{revision: "1070", kb: "5017381"},
				{revision: "1129", kb: "5018421"},
				{revision: "1131", kb: "5020436"},
				{revision: "1194", kb: "5018485"},
				{revision: "1249", kb: "5019081"},
				{revision: "1251", kb: "5021656"},
				{revision: "1311", kb: "5020032"},
				{revision: "1366", kb: "5021249"},
				{revision: "1368", kb: "5022553"},
				{revision: "1487", kb: "5022291"},
				{revision: "1547", kb: "5022842"},
				{revision: "1607", kb: "5023705"},
				{revision: "1668", kb: "5025230"},
				{revision: "1726", kb: "5026370"},
				{revision: "1787", kb: "5027225"},
				{revision: "1850", kb: "5028171"},
				{revision: "1906", kb: "5029250"},
				{revision: "1970", kb: "5030216"},
				{revision: "2031", kb: "5031364"},
				{revision: "2113", kb: "5032198"},
				{revision: "2159", kb: "5033118"},
				{revision: "2227", kb: "5034129"},
				{revision: "2322", kb: "5034770"},
				{revision: "2340", kb: "5035857"},
				{revision: "2342", kb: "5037422"},
				{revision: "2402", kb: "5036909"},
				{revision: "2461", kb: "5037782"},
				{revision: "2527", kb: "5039227"},
				{revision: "2529", kb: "5041054"},
				{revision: "2582", kb: "5040437"},
				{revision: "2655", kb: "5041160"},
				{revision: "2700", kb: "5042881"},
				{revision: "2762", kb: "5044281"},
				{revision: "2849", kb: "5046616"},
				{revision: "2966", kb: "5048654"},
				{revision: "3091", kb: "5049983"},
				{revision: "3207", kb: "5051979"},
				{revision: "3328", kb: "5053603"},
				{revision: "3453", kb: "5055526"},
				{revision: "3561", kb: "5058920"},
				{revision: "3566", kb: "5059092"},
				{revision: "3692", kb: "5058385"},
				{revision: "3695", kb: "5061906"},
				{revision: "3807", kb: "5060526"},
				{revision: "3932", kb: "5062572"},
				{revision: "4052", kb: "5063880"},
				{revision: "4171", kb: "5065432"},
			},
		},
	},
	"Windows Server 2022, 23H2 Edition": {
		// https://support.microsoft.com/en-us/topic/windows-server-version-23h2-update-history-68c851ff-825a-4dbc-857b-51c5aa0ab248
		"25398": {
			rollup: []windowsRelease{
				{revision: "531", kb: "5032202"},
				{revision: "584", kb: "5033383"},
				{revision: "643", kb: "5034130"},
				{revision: "709", kb: "5034769"},
				{revision: "763", kb: "5035856"},
				{revision: "830", kb: "5036910"},
				{revision: "887", kb: "5037781"},
				{revision: "950", kb: "5039236"},
				{revision: "1009", kb: "5040438"},
				{revision: "1085", kb: "5041573"},
				{revision: "1128", kb: "5043055"},
				{revision: "1189", kb: "5044288"},
				{revision: "1251", kb: "5046618"},
				{revision: "1308", kb: "5048653"},
				{revision: "1369", kb: "5049984"},
				{revision: "1425", kb: "5051980"},
				{revision: "1486", kb: "5053599"},
				{revision: "1551", kb: "5055527"},
				{revision: "1611", kb: "5058384"},
				{revision: "1665", kb: "5060118"},
				{revision: "1668", kb: "5063774"},
				{revision: "1732", kb: "5062570"},
				{revision: "1791", kb: "5063899"},
				{revision: "1849", kb: "5065425"},
			},
		},
	},
	"Windows Server 2025": {
		// https://support.microsoft.com/en-us/topic/windows-server-2025-update-history-10f58da7-e57b-4a9d-9c16-9f1dcd72d7d7
		"26100": {
			rollup: []windowsRelease{
				{revision: "1742", kb: ""},
				{revision: "2033", kb: "5044284"},
				{revision: "2314", kb: "5046617"},
				{revision: "2605", kb: "5048667"},
				{revision: "2894", kb: "5050009"},
				{revision: "3194", kb: "5051987"},
				{revision: "3476", kb: "5053598"},
				{revision: "3775", kb: "5055523"},
				{revision: "3781", kb: "5059087"},
				{revision: "4061", kb: "5058411"},
				{revision: "4066", kb: "5061977"},
				{revision: "4349", kb: "5060842"},
				{revision: "4652", kb: "5062553"},
				{revision: "4656", kb: "5064489"},
				{revision: "4946", kb: "5063878"},
				{revision: "6584", kb: "5065426"},
			},
		},
	},
}

// DetectKBsFromKernelVersion detects the KBs from the kernel version
func DetectKBsFromKernelVersion(release, kernelVersion string) (models.WindowsKB, error) {
	switch ss := strings.Split(kernelVersion, "."); len(ss) {
	case 3:
		return models.WindowsKB{}, nil
	case 4:
		var osver string
		switch {
		case strings.HasPrefix(release, "Windows 10 "):
			osver = "Windows 10"
		case strings.HasPrefix(release, "Windows 11 "):
			osver = "Windows 11"
		case strings.HasPrefix(release, "Windows Server 2016"), strings.HasPrefix(release, "Windows Server, Version 1709"), strings.HasPrefix(release, "Windows Server, Version 1809"), strings.HasPrefix(release, "Windows Server 2019"), strings.HasPrefix(release, "Windows Server, Version 1903"), strings.HasPrefix(release, "Windows Server, Version 1909"), strings.HasPrefix(release, "Windows Server, Version 2004"), strings.HasPrefix(release, "Windows Server, Version 20H2"), strings.HasPrefix(release, "Windows Server 2022"), strings.HasPrefix(release, "Windows Server 2025"):
			osver = strings.TrimSuffix(release, " (Server Core installation)")
		default:
			return models.WindowsKB{}, nil
		}

		verReleases, ok := windowsReleases[osver]
		if !ok {
			return models.WindowsKB{}, nil
		}

		rels, ok := verReleases[ss[2]]
		if !ok {
			return models.WindowsKB{}, nil
		}

		nMyRevision, err := strconv.Atoi(ss[3])
		if err != nil {
			return models.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
		}

		var index int
		for i, r := range rels.rollup {
			nRevision, err := strconv.Atoi(r.revision)
			if err != nil {
				return models.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
			}
			if nMyRevision < nRevision {
				break
			}
			index = i
		}

		var kbs models.WindowsKB
		for _, r := range rels.rollup[:index+1] {
			if r.kb != "" {
				kbs.Applied = append(kbs.Applied, r.kb)
			}
		}
		for _, r := range rels.rollup[index+1:] {
			if r.kb != "" {
				kbs.Unapplied = append(kbs.Unapplied, r.kb)
			}
		}

		return kbs, nil
	default:
		return models.WindowsKB{}, xerrors.Errorf("unexpected kernel version. expected: <major version>.<minor version>.<build>(.<revision>), actual: %s", kernelVersion)
	}
}

func (w *windows) detectPlatform() {
	if w.getServerInfo().Mode.IsOffline() {
		w.setPlatform(models.Platform{Name: "unknown"})
		return
	}

	ok, instanceID, err := w.detectRunningOnAws()
	if err != nil {
		w.setPlatform(models.Platform{Name: "other"})
		return
	}
	if ok {
		w.setPlatform(models.Platform{
			Name:       "aws",
			InstanceID: instanceID,
		})
		return
	}

	//TODO Azure, GCP...
	w.setPlatform(models.Platform{Name: "other"})
}

func (w *windows) detectRunningOnAws() (bool, string, error) {
	if r := w.exec(w.translateCmd("Invoke-WebRequest -MaximumRetryCount 3 -TimeoutSec 1 -NoProxy http://169.254.169.254/latest/meta-data/instance-id"), noSudo); r.isSuccess() {
		id := strings.TrimSpace(r.Stdout)
		if w.isAwsInstanceID(id) {
			return true, id, nil
		}
	}

	if r := w.exec(w.translateCmd(`Invoke-WebRequest -Method Put -MaximumRetryCount 3 -TimeoutSec 1 -NoProxy -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"="300"} http://169.254.169.254/latest/api/token`), noSudo); r.isSuccess() {
		r := w.exec(w.translateCmd(fmt.Sprintf(`Invoke-WebRequest -MaximumRetryCount 3 -TimeoutSec 1 -NoProxy -Headers @{"X-aws-ec2-metadata-token"="%s"} http://169.254.169.254/latest/meta-data/instance-id`, strings.TrimSpace(r.Stdout))), noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			if !w.isAwsInstanceID(id) {
				return false, "", nil
			}
			return true, id, nil
		}
	}

	if r := w.exec("where.exe curl.exe", noSudo); r.isSuccess() {
		if r := w.exec("curl.exe --max-time 1 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id", noSudo); r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			if w.isAwsInstanceID(id) {
				return true, id, nil
			}
		}

		if r := w.exec(`curl.exe -X PUT --max-time 1 --noproxy 169.254.169.254 -H "X-aws-ec2-metadata-token-ttl-seconds: 300" http://169.254.169.254/latest/api/token`, noSudo); r.isSuccess() {
			if r := w.exec(fmt.Sprintf(`curl.exe -H "X-aws-ec2-metadata-token: %s" --max-time 1 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id`, strings.TrimSpace(r.Stdout)), noSudo); r.isSuccess() {
				id := strings.TrimSpace(r.Stdout)
				if !w.isAwsInstanceID(id) {
					return false, "", nil
				}
				return true, id, nil
			}
		}
	}

	return false, "", xerrors.Errorf("Failed to Invoke-WebRequest or curl.exe to AWS instance metadata on %s. container: %s", w.ServerInfo.ServerName, w.ServerInfo.Container.Name)
}

func (w *windows) scanLibraries() (err error) {
	if len(w.LibraryScanners) > 0 {
		return nil
	}

	// library scan for servers need lockfiles
	if len(w.ServerInfo.Lockfiles) == 0 && !w.ServerInfo.FindLock {
		return nil
	}

	w.log.Info("Scanning Language-specific Packages...")

	trivyLoggerInit()

	detectFiles := w.ServerInfo.Lockfiles

	priv := noSudo
	if w.getServerInfo().Mode.IsFastRoot() || w.getServerInfo().Mode.IsDeep() {
		priv = sudo
	}

	// auto detect lockfile
	if w.ServerInfo.FindLock {
		cmd := func() string {
			switch w.shell {
			case "powershell":
				dir := func() string {
					if len(w.ServerInfo.FindLockDirs) == 0 {
						w.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under C:\\ will be searched, which may increase CPU load")
						return "C:\\"
					}

					ss := make([]string, 0, len(w.ServerInfo.FindLockDirs))
					for _, d := range w.ServerInfo.FindLockDirs {
						ss = append(ss, fmt.Sprintf("\"%s\"", d))
					}
					return strings.Join(ss, ",")
				}()

				findopt := func() string {
					ss := make([]string, 0, len(models.FindLockFiles))
					for _, filename := range models.FindLockFiles {
						ss = append(ss, fmt.Sprintf("\"%s\"", filename))
					}
					return strings.Join(ss, ", ")
				}()

				w.log.Infof("Finding files under %s", dir)

				// Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @("package-lock.json", "yarn.lock") } | Select-Object -ExpandProperty FullName
				return fmt.Sprintf("Get-ChildItem -Path %s -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(%s) } | Select-Object -ExpandProperty FullName", dir, findopt)
			default:
				dir := func() string {
					if len(w.ServerInfo.FindLockDirs) == 0 {
						w.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under C:\\ will be searched, which may increase CPU load")
						return "C:\\"
					}

					ss := make([]string, 0, len(w.ServerInfo.FindLockDirs))
					for _, d := range w.ServerInfo.FindLockDirs {
						if strings.HasSuffix(d, "\\") {
							d = fmt.Sprintf("%s\\", d)
						}
						ss = append(ss, fmt.Sprintf("\\\"%s\\\"", d))
					}
					return strings.Join(ss, ",")
				}()

				findopt := func() string {
					ss := make([]string, 0, len(models.FindLockFiles))
					for _, filename := range models.FindLockFiles {
						ss = append(ss, fmt.Sprintf("\\\"%s\\\"", filename))
					}
					return strings.Join(ss, ", ")
				}()

				w.log.Infof("Finding files under %s", dir)

				// powershell.exe -NoProfile -NonInteractive "Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(\"package-lock.json\", \"yarn.lock\") } | Select-Object -ExpandProperty FullName"
				return fmt.Sprintf("powershell.exe -NoProfile -NonInteractive \"%s\"", fmt.Sprintf("Get-ChildItem -Path %s -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(%s) } | Select-Object -ExpandProperty FullName", dir, findopt))
			}
		}()
		r := w.exec(cmd, priv)
		if r.ExitStatus != 0 && r.ExitStatus != 1 {
			return xerrors.Errorf("Failed to find lock files: %s", r)
		}

		scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
		for scanner.Scan() {
			detectFiles = append(detectFiles, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return xerrors.Errorf("Failed to reading find results. err: %w", err)
		}
	}

	found := make(map[string]bool)
	for _, path := range detectFiles {
		if path == "" {
			continue
		}

		abspath, err := func() (string, error) {
			if ufilepath.IsAbs(path) {
				return ufilepath.Clean(path), nil
			}

			r := w.exec(w.translateCmd("Get-Location | Select-object -ExpandProperty Path"), noSudo)
			if !r.isSuccess() {
				return "", xerrors.Errorf("Failed to get current directory. err: %w", err)
			}

			return ufilepath.Join(strings.TrimSuffix(strings.TrimSuffix(r.Stdout, "\n"), "\r"), path), nil
		}()
		if err != nil {
			return xerrors.Errorf("Failed to abs the lockfile. filepath: %s, err: %w", path, err)
		}

		if _, ok := found[abspath]; ok {
			continue
		}
		found[abspath] = true

		w.log.Debugf("Analyzing file: %s", abspath)
		filemode, contents, err := func() (os.FileMode, []byte, error) {
			// set dummy filemode because Windows file permission is complex and converting them to unix permission is difficult
			filemode := os.FileMode(0666)

			r := w.exec(w.translateCmd(fmt.Sprintf("[Convert]::ToBase64String([System.IO.File]::ReadAllBytes('%s'))", abspath)), priv)
			if !r.isSuccess() {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to read target file contents. filepath: %s, err: %w", abspath, err)
			}

			contents, err := func() ([]byte, error) {
				bs, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(r.Stdout)))
				if err != nil {
					return nil, xerrors.Errorf("Failed to decode base64 contents. err: %w", err)
				}
				return bs, nil
			}()
			if err != nil {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to read file contents from stdout. filepath: %s, err: %w", abspath, err)
			}

			return filemode, contents, nil
		}()
		if err != nil {
			w.log.Warn(err)
			continue
		}

		trivypath := w.cleanPath(abspath)
		libraryScanners, err := AnalyzeLibrary(context.Background(), trivypath, contents, filemode, w.ServerInfo.Mode.IsOffline())
		if err != nil {
			return xerrors.Errorf("Failed to analyze library. err: %w, filepath: %s", err, trivypath)
		}
		for _, libscanner := range libraryScanners {
			libscanner.LockfilePath = abspath
			w.LibraryScanners = append(w.LibraryScanners, libscanner)
		}
	}

	return nil
}

// https://github.com/aquasecurity/trivy/blob/35e88890c3c201b3eb11f95376172e57bf44df4b/pkg/mapfs/fs.go#L272-L283
func (w *windows) cleanPath(path string) string {
	// Convert the volume name like 'C:' into dir like 'C\'
	if vol := ufilepath.VolumeName(path); vol != "" {
		newVol := strings.TrimSuffix(vol, ":")
		newVol = fmt.Sprintf("%s%c", newVol, ufilepath.Separator)
		path = strings.Replace(path, vol, newVol, 1)
	}
	path = ufilepath.Clean(path)
	path = ufilepath.ToSlash(path)
	path = strings.TrimLeft(path, "/") // Remove the leading slash
	return path
}
