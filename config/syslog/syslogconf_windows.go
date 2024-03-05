//go:build windows

package syslog

import "golang.org/x/xerrors"

// Validate validates configuration
func (c *Conf) Validate() (errs []error) {
	if !c.Enabled {
		return nil
	}
	return []error{xerrors.New("windows not support syslog")}
}
