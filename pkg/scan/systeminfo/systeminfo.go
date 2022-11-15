package systeminfo

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/scan/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "systeminfo analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *types.AnalyzerHost) error {
	status, stdout, stderr, err := ah.Host.Exec(ctx, "systeminfo", false)
	if err != nil {
		return errors.Wrap(err, `exec "systeminfo"`)
	}
	if stderr != "" {
		return errors.New(stderr)
	}
	if status != 0 {
		return errors.Errorf("exit status is %d", status)
	}

	ah.Host.Family, ah.Host.Release, ah.Host.Packages.KB, err = ParseSysteminfo(stdout)
	if err != nil {
		return errors.Wrap(err, "parse systeminfo")
	}

	if ah.Host.Family == "" {
		return errors.New("family is unknown")
	}
	if ah.Host.Release == "" {
		return errors.New("release is unknown")
	}

	return nil
}

func ParseSysteminfo(stdout string) (string, string, []string, error) {
	var (
		o   osInfo
		kbs []string
	)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

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
			default:
				return "", "", nil, errors.Errorf(`installation type not found from "%s"`, line)
			}
		case strings.HasPrefix(line, "Hotfix(s):"):
			nKB, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "Hotfix(s):"), " Hotfix(s) Installed.")))
			if err != nil {
				return "", "", nil, errors.Errorf(`number of installed hotfix from "%s"`, line)
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
	release, err := detectOSName(o)
	if err != nil {
		return "", "", nil, errors.Wrap(err, "detect os name")
	}

	return "windows", release, kbs, nil
}

type osInfo struct {
	productName      string
	version          string
	build            string
	edition          string
	servicePack      string
	arch             string
	installationType string
}

func detectOSName(osInfo osInfo) (string, error) {
	osName, err := detectOSNameFromOSInfo(osInfo)
	if err != nil {
		return "", errors.Wrapf(err, "detect OS Name from OSInfo: %#v", osInfo)
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
		case "Server":
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
			switch osInfo.arch {
			case "x64":
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
			switch osInfo.arch {
			case "x64":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server":
			n := "Microsoft Windows Server 2003"
			if strings.Contains(osInfo.productName, "R2") {
				n = "Microsoft Windows Server 2003 R2"
			}
			switch osInfo.arch {
			case "x64":
				n = fmt.Sprintf("%s x64 Edition", n)
			case "IA64":
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
			switch osInfo.arch {
			case "x64":
				n = "Windows Vista x64 Editions"
			default:
				n = "Windows Vista"
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
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
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows 7 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows 7 for %s Systems", arch), nil
		case "Server":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
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
				return "", err
			}
			return fmt.Sprintf("Windows 8 for %s Systems", arch), nil
		case "Server":
			return "Windows Server 2012", nil
		case "Server Core":
			return "Windows Server 2012 (Server Core installation)", nil
		}
	case "6.3":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Windows 8.1 for %s Systems", arch), nil
		case "Server":
			return "Windows Server 2012 R2", nil
		case "Server Core":
			return "Windows Server 2012 R2 (Server Core installation)", nil
		}
	case "10.0":
		switch osInfo.installationType {
		case "Client":
			if strings.Contains(osInfo.productName, "Windows 10") {
				arch, err := formatArch(osInfo.arch)
				if err != nil {
					return "", err
				}
				name, err := formatNamebyBuild("10", osInfo.build)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s for %s Systems", name, arch), nil
			}
			if strings.Contains(osInfo.productName, "Windows 11") {
				arch, err := formatArch(osInfo.arch)
				if err != nil {
					return "", err
				}
				name, err := formatNamebyBuild("11", osInfo.build)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s for %s Systems", name, arch), nil
			}
		case "Server":
			return formatNamebyBuild("Server", osInfo.build)
		case "Server Core":
			name, err := formatNamebyBuild("Server", osInfo.build)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s (Server Core installation)", name), nil
		}
	}
	return "", errors.New("OS Name not found")
}

func formatArch(arch string) (string, error) {
	switch arch {
	case "x64-based":
		return "x64-based", nil
	case "ARM64-based":
		return "ARM64-based", nil
	case "Itanium-based":
		return "Itanium-based", nil
	case "X86-based":
		return "32-bit", nil
	default:
		return "", errors.New("CPU Architecture not found")
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
			// It seems that there are cases where the Product Name is Windows 10 even though it is Windows 11
			// ref: https://docs.microsoft.com/en-us/answers/questions/586548/in-the-official-version-of-windows-11-why-the-key.html
			{
				build: "22000",
				name:  "Windows 11",
			},
		},
		"11": {
			{
				build: "22000",
				name:  "Windows 11", // not "Windows 11 Version 21H2"
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
		},
	}
)

func formatNamebyBuild(osType string, mybuild string) (string, error) {
	builds, ok := winBuilds[osType]
	if !ok {
		return "", errors.New("OS Type not found")
	}

	v := builds[0].name
	for _, b := range builds {
		if mybuild == b.build {
			return b.name, nil
		}
		if mybuild < b.build {
			break
		}
		v = b.name
	}
	return v, nil
}
