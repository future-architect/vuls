package config

import "errors"

// JSONLoader loads configuration
type JSONLoader struct {
}

// Load load the configuration JSON file specified by path arg.
func (c JSONLoader) Load(_, _, _ string) (err error) {
	return errors.New("Not implement yet")
}
