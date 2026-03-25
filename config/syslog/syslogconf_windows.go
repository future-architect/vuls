//go:build windows

package syslog

import "errors"

// Validate validates configuration
func (c *Conf) Validate() (errs []error) {
	if !c.Enabled {
		return nil
	}
	return []error{errors.New("windows not support syslog")}
}
