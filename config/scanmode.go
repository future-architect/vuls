package config

import (
	"strings"

	"golang.org/x/xerrors"
)

// ScanMode has a type of scan mode. fast, fast-root, deep and offline
type ScanMode struct {
	flag byte
}

const (
	// Fast is fast scan mode
	Fast = byte(1 << iota)
	// FastRoot is scanmode
	FastRoot
	// Deep is scanmode
	Deep
	// Offline is scanmode
	Offline

	fastStr     = "fast"
	fastRootStr = "fast-root"
	deepStr     = "deep"
	offlineStr  = "offline"
)

// Set mode
func (s *ScanMode) Set(f byte) {
	s.flag |= f
}

// IsFast return whether scan mode is fast
func (s ScanMode) IsFast() bool {
	return s.flag&Fast == Fast
}

// IsFastRoot return whether scan mode is fastroot
func (s ScanMode) IsFastRoot() bool {
	return s.flag&FastRoot == FastRoot
}

// IsDeep return whether scan mode is deep
func (s ScanMode) IsDeep() bool {
	return s.flag&Deep == Deep
}

// IsOffline return whether scan mode is offline
func (s ScanMode) IsOffline() bool {
	return s.flag&Offline == Offline
}

func (s *ScanMode) ensure() error {
	numTrue := 0
	for _, b := range []bool{s.IsFast(), s.IsFastRoot(), s.IsDeep()} {
		if b {
			numTrue++
		}
	}
	if numTrue == 0 {
		s.Set(Fast)
	} else if s.IsDeep() && s.IsOffline() {
		return xerrors.New("Don't specify both of deep and offline")
	} else if numTrue != 1 {
		return xerrors.New("Specify only one of offline, fast, fast-root or deep")
	}
	return nil
}

func (s ScanMode) String() string {
	ss := ""
	if s.IsFast() {
		ss = fastStr
	} else if s.IsFastRoot() {
		ss = fastRootStr
	} else if s.IsDeep() {
		ss = deepStr
	}
	if s.IsOffline() {
		ss += " " + offlineStr
	}
	return ss + " mode"
}

func setScanMode(server *ServerInfo) error {
	if len(server.ScanMode) == 0 {
		server.ScanMode = Conf.Default.ScanMode
	}
	for _, m := range server.ScanMode {
		switch strings.ToLower(m) {
		case fastStr:
			server.Mode.Set(Fast)
		case fastRootStr:
			server.Mode.Set(FastRoot)
		case deepStr:
			server.Mode.Set(Deep)
		case offlineStr:
			server.Mode.Set(Offline)
		default:
			return xerrors.Errorf("scanMode: %s of %s is invalid. Specify -fast, -fast-root, -deep or offline",
				m, server.ServerName)
		}
	}
	if err := server.Mode.ensure(); err != nil {
		return xerrors.Errorf("%s in %s", err, server.ServerName)
	}
	return nil
}
