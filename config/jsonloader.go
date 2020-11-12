package config

import "golang.org/x/xerrors"

// JSONLoader loads configuration
type JSONLoader struct {
}

// Load load the configuration JSON file specified by path arg.
func (c JSONLoader) Load(path, sudoPass, keyPass string) (err error) {
	return xerrors.New("Not implement yet")
}
