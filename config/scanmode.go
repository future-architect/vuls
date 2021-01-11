package config

import "golang.org/x/xerrors"

// ScanMode has a type of scan mode. fast, fast-root, deep and offline
type ScanMode struct {
	flag byte
}

const (
	// Fast is fast scan mode
	Fast = byte(1 << iota)
	// FastRoot is fast-root scan mode
	FastRoot
	// Deep is deep scan mode
	Deep
	// Offline is offline scan mode
	Offline
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

func (s ScanMode) validate() error {
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
		ss = "fast"
	} else if s.IsFastRoot() {
		ss = "fast-root"
	} else if s.IsDeep() {
		ss = "deep"
	}
	if s.IsOffline() {
		ss += " offline"
	}
	return ss + " mode"
}
