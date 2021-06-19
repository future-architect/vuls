package config

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// PortScanConf is the setting for using an external port scanner
type PortScanConf struct {
	IsUseExternalScanner bool `toml:"-" json:"-"`

	// Path to external scanner
	ScannerBinPath string `toml:"scannerBinPath,omitempty" json:"scannerBinPath,omitempty"`

	// set user has privileged
	HasPrivileged bool `toml:"hasPrivileged,omitempty" json:"hasPrivileged,omitempty"`

	// set the ScanTechniques for ScannerBinPath
	ScanTechniques []string `toml:"scanTechniques,omitempty" json:"scanTechniques,omitempty"`

	// set the FIREWALL/IDS EVASION AND SPOOFING(Use given port number)
	SourcePort string `toml:"sourcePort,omitempty" json:"sourcePort,omitempty"`
}

// ScanTechnique is implemented to represent the supported ScanTechniques in an Enum.
type ScanTechnique int

const (
	// NotSupportTechnique is a ScanTechnique that is currently not supported.
	NotSupportTechnique ScanTechnique = iota
	// TCPSYN is SYN scan
	TCPSYN
	// TCPConnect is TCP connect scan
	TCPConnect
	// TCPACK is ACK scan
	TCPACK
	// TCPWindow is Window scan
	TCPWindow
	// TCPMaimon is Maimon scan
	TCPMaimon
	// TCPNull is Null scan
	TCPNull
	// TCPFIN is FIN scan
	TCPFIN
	// TCPXmas is Xmas scan
	TCPXmas
)

var scanTechniqueMap = map[ScanTechnique]string{
	TCPSYN:     "sS",
	TCPConnect: "sT",
	TCPACK:     "sA",
	TCPWindow:  "sW",
	TCPMaimon:  "sM",
	TCPNull:    "sN",
	TCPFIN:     "sF",
	TCPXmas:    "sX",
}

func (s ScanTechnique) String() string {
	switch s {
	case TCPSYN:
		return "TCPSYN"
	case TCPConnect:
		return "TCPConnect"
	case TCPACK:
		return "TCPACK"
	case TCPWindow:
		return "TCPWindow"
	case TCPMaimon:
		return "TCPMaimon"
	case TCPNull:
		return "TCPNull"
	case TCPFIN:
		return "TCPFIN"
	case TCPXmas:
		return "TCPXmas"
	default:
		return "NotSupportTechnique"
	}
}

// GetScanTechniques converts ScanTechniques loaded from config.toml to []scanTechniques.
func (c *PortScanConf) GetScanTechniques() []ScanTechnique {
	if len(c.ScanTechniques) == 0 {
		return []ScanTechnique{}
	}

	scanTechniques := []ScanTechnique{}
	for _, technique := range c.ScanTechniques {
		findScanTechniqueFlag := false
		for key, value := range scanTechniqueMap {
			if strings.EqualFold(value, technique) {
				scanTechniques = append(scanTechniques, key)
				findScanTechniqueFlag = true
				break
			}
		}

		if !findScanTechniqueFlag {
			scanTechniques = append(scanTechniques, NotSupportTechnique)
		}
	}

	if len(scanTechniques) == 0 {
		return []ScanTechnique{NotSupportTechnique}
	}
	return scanTechniques
}

// Validate validates configuration
func (c *PortScanConf) Validate() (errs []error) {
	if !c.IsUseExternalScanner {
		if c.IsZero() {
			return
		}
		errs = append(errs, xerrors.New("To enable the PortScan option, ScannerBinPath must be set."))
	}

	if _, err := os.Stat(c.ScannerBinPath); err != nil {
		errs = append(errs, xerrors.Errorf(
			"scanner is not found. ScannerBinPath: %s not exists", c.ScannerBinPath))
	}

	scanTechniques := c.GetScanTechniques()
	for _, scanTechnique := range scanTechniques {
		if scanTechnique == NotSupportTechnique {
			errs = append(errs, xerrors.New("There is an unsupported option in ScanTechniques."))
		}
	}

	// It does not currently support multiple ScanTechniques.
	// But if it supports UDP scanning, it will need to accept multiple ScanTechniques.
	if len(scanTechniques) > 1 {
		errs = append(errs, xerrors.New("Currently multiple ScanTechniques are not supported."))
	}

	if c.HasPrivileged {
		if os.Geteuid() != 0 {
			output, err := exec.Command("getcap", c.ScannerBinPath).Output()
			if err != nil {
				errs = append(errs, xerrors.Errorf("Failed to check capability of %s. error message: %w", c.ScannerBinPath, err))
			} else {
				parseOutput := strings.SplitN(string(output), "=", 2)
				if len(parseOutput) != 2 {
					errs = append(errs, xerrors.Errorf("Failed to parse getcap outputs. please execute this command: `$ getcap %s`. If the following string (`/usr/bin/nmap = ... `) is not displayed, you need to set the capability with the following command. `$ setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip %s`", c.ScannerBinPath, c.ScannerBinPath))
				} else {
					parseCapability := strings.Split(strings.TrimSpace(parseOutput[1]), "+")
					capabilities := strings.Split(parseCapability[0], ",")
					for _, needCap := range []string{"cap_net_bind_service", "cap_net_admin", "cap_net_raw"} {
						existCapFlag := false
						for _, cap := range capabilities {
							if needCap == cap {
								existCapFlag = true
								break
							}
						}

						if existCapFlag {
							continue
						}

						errs = append(errs, xerrors.Errorf("Not enough capability to execute. needs: ['cap_net_bind_service', 'cap_net_admin', 'cap_net_raw'], actual: %s. To fix this, run the following command. `$ setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip %s`", capabilities, c.ScannerBinPath))
						break
					}

					if parseCapability[1] != "eip" {
						errs = append(errs, xerrors.Errorf("Capability(`cap_net_bind_service,cap_net_admin,cap_net_raw`) must belong to the following capability set(need: eip, actual: %s). To fix this, run the following command. `$ setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip %s`", parseCapability[1], c.ScannerBinPath))
					}
				}
			}
		}
	}

	if !c.HasPrivileged {
		for _, scanTechnique := range scanTechniques {
			if scanTechnique != TCPConnect && scanTechnique != NotSupportTechnique {
				errs = append(errs, xerrors.New("If not privileged, only TCPConnect Scan(-sT) can be used."))
				break
			}
		}
	}

	if c.SourcePort != "" {
		for _, scanTechnique := range scanTechniques {
			if scanTechnique == TCPConnect {
				errs = append(errs, xerrors.New("SourcePort Option(-g/--source-port) is incompatible with the default TCPConnect Scan(-sT)."))
				break
			}
		}

		portNumber, err := strconv.Atoi(c.SourcePort)
		if err != nil {
			errs = append(errs, xerrors.Errorf("SourcePort conversion failed. %w", err))
		} else {
			if portNumber < 0 || 65535 < portNumber {
				errs = append(errs, xerrors.Errorf("SourcePort(%s) must be between 0 and 65535.", c.SourcePort))
			}

			if portNumber == 0 {
				errs = append(errs, xerrors.New("SourcePort(0) may not work on all systems."))
			}
		}
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	return
}

// IsZero return  whether this struct is not specified in config.toml
func (c PortScanConf) IsZero() bool {
	return c.ScannerBinPath == "" && !c.HasPrivileged && len(c.ScanTechniques) == 0 && c.SourcePort == ""
}
