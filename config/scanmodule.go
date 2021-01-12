package config

import (
	"strings"

	"golang.org/x/xerrors"
)

// ScanModule has a type of scan module
type ScanModule struct {
	flag byte
}

const (
	// OSPkg is scanmodule
	OSPkg = byte(1 << iota)
	// WordPress is scanmodule
	WordPress
	// Lockfile is scanmodule
	Lockfile
	// Port is scanmodule
	Port

	osPkgStr     = "ospkg"
	wordPressStr = "wordpress"
	lockfileStr  = "lockfile"
	portStr      = "port"
)

var allModules = []string{osPkgStr, wordPressStr, lockfileStr, portStr}

// Set module
func (s *ScanModule) Set(f byte) {
	s.flag |= f
}

// IsScanOSPkg return whether scanning os pkg
func (s ScanModule) IsScanOSPkg() bool {
	return s.flag&OSPkg == OSPkg
}

// IsScanWordPress return whether scanning wordpress
func (s ScanModule) IsScanWordPress() bool {
	return s.flag&WordPress == WordPress
}

// IsScanLockFile whether scanning lock file
func (s ScanModule) IsScanLockFile() bool {
	return s.flag&Lockfile == Lockfile
}

// IsScanPort whether scanning listening ports
func (s ScanModule) IsScanPort() bool {
	return s.flag&Port == Port
}

// IsZero return the struct value are all false
func (s ScanModule) IsZero() bool {
	return !(s.IsScanOSPkg() || s.IsScanWordPress() || s.IsScanLockFile() || s.IsScanPort())
}

func (s *ScanModule) ensure() error {
	if s.IsZero() {
		s.Set(OSPkg)
		s.Set(WordPress)
		s.Set(Lockfile)
		s.Set(Port)
	} else if !s.IsScanOSPkg() && s.IsScanPort() {
		return xerrors.New("When specifying the Port, Specify OSPkg as well")
	}
	return nil
}

func setScanModules(server *ServerInfo, d ServerInfo) error {
	if len(server.ScanModules) == 0 {
		server.ScanModules = d.ScanModules
	}
	for _, m := range server.ScanModules {
		switch strings.ToLower(m) {
		case osPkgStr:
			server.Module.Set(OSPkg)
		case wordPressStr:
			server.Module.Set(WordPress)
		case lockfileStr:
			server.Module.Set(Lockfile)
		case portStr:
			server.Module.Set(Port)
		default:
			return xerrors.Errorf("scanMode: %s of %s is invalid. Specify %s",
				m, server.ServerName, allModules)
		}
	}
	if err := server.Module.ensure(); err != nil {
		return xerrors.Errorf("%s in %s", err, server.ServerName)
	}
	return nil
}
