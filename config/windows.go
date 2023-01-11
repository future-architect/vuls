package config

import (
	"os"

	"golang.org/x/xerrors"
)

// WindowsConf used for Windows Update Setting
type WindowsConf struct {
	ServerSelection int    `toml:"serverSelection,omitempty" json:"serverSelection,omitempty"`
	CabPath         string `toml:"cabPath,omitempty" json:"cabPath,omitempty"`
}

// Validate validates configuration
func (c *WindowsConf) Validate() []error {
	switch c.ServerSelection {
	case 0, 1, 2:
	case 3:
		if _, err := os.Stat(c.CabPath); err != nil {
			return []error{xerrors.Errorf("%s does not exist. err: %w", c.CabPath, err)}
		}
	default:
		return []error{xerrors.Errorf("ServerSelection: %d does not support . Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/07e2bfa4-6795-4189-b007-cc50b476181a", c.ServerSelection)}
	}
	return nil
}
