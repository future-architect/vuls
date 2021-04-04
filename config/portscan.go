package config

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// PortScanConf is the setting for using an external port scanner
type PortScanConf struct {
	ExternalScannerMode bool `toml:"-" json:"-"`

	// Path to external scanner
	ScannerBinPath string `toml:"scannerBinPath,omitempty" json:"scannerBinPath,omitempty"`

	// set user has privileged (default: false)
	HasPrivileged bool `toml:"hasPrivileged,omitempty" json:"hasPrivileged,omitempty"`

	// set the ScanTechniques for ScannerBinPath
	ScanTechniques []string `toml:"scanTechniques,omitempty" json:"scanTechniques,omitempty"`

	// set the FIREWALL/IDS EVASION AND SPOOFING(Spoof source address)
	SourceAddress string `toml:"sourceAddress,omitempty" json:"sourceAddress,omitempty"`

	// set the FIREWALL/IDS EVASION AND SPOOFING(Use given port number)
	SourcePort string `toml:"sourcePort,omitempty" json:"sourcePort,omitempty"`
}

type scanTechnique int

const (
	unknown scanTechnique = iota
	tcpSYN
	tcpConnect
	tcpACK
	tcpWindow
	tcpMaimon
	tcpNull
	tcpFIN
	tcpXmas
)

var scanTechniqueMap = map[scanTechnique]string{
	tcpSYN:     "sS",
	tcpConnect: "sT",
	tcpACK:     "sA",
	tcpWindow:  "sW",
	tcpMaimon:  "sM",
	tcpNull:    "sN",
	tcpFIN:     "sF",
	tcpXmas:    "sX",
}

func (s scanTechnique) String() string {
	if s, ok := scanTechniqueMap[s]; ok {
		return s
	}
	return "unknown"
}

func (c *PortScanConf) getScanTechniques() []scanTechnique {
	if len(c.ScanTechniques) == 0 {
		return []scanTechnique{}
	}

	scanTechniques := []scanTechnique{}
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
			scanTechniques = append(scanTechniques, unknown)
		}
	}

	if len(scanTechniques) == 0 {
		return []scanTechnique{unknown}
	}
	return scanTechniques
}

// Validate validates configuration
func (c *PortScanConf) Validate() (errs []error) {
	if !c.ExternalScannerMode {
		if c.IsZero() {
			return
		}
		errs = append(errs, xerrors.New("To enable the PortScan option, ScannerBinPath must be set."))
	}

	if _, err := os.Stat(c.ScannerBinPath); err != nil {
		errs = append(errs, xerrors.Errorf(
			"scanner is not found. ScannerBinPath: %s not exists", c.ScannerBinPath))
	}

	scanTechniques := c.getScanTechniques()
	for _, technique := range scanTechniques {
		if technique == unknown {
			errs = append(errs, xerrors.New("There is an unsupported option in ScanTechniques."))
		}
	}

	// It does not currently support multiple ScanTechniques.
	// But if it supports UDP scanning, it will need to accept multiple ScanTechniques.
	if len(scanTechniques) > 1 {
		errs = append(errs, xerrors.New("Multiple ScanTechniques are not supported."))
	}

	if c.SourceAddress != "" && net.ParseIP(c.SourceAddress) == nil {
		errs = append(errs, xerrors.Errorf("Source Address(%s) is invalid.", c.SourceAddress))
	}

	if c.SourcePort != "" {
		portNumber, err := strconv.Atoi(c.SourcePort)
		if err != nil {
			errs = append(errs, xerrors.Errorf("SourcePort conversion failed. %s", err))
		}

		if portNumber < 0 || 65535 < portNumber {
			errs = append(errs, xerrors.Errorf("SourcePort(%s) must be between 0 and 65535.", c.SourcePort))
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
	return c.ScannerBinPath == "" && !c.HasPrivileged && len(c.ScanTechniques) == 0 && c.SourceAddress == "" && c.SourcePort == ""
}
