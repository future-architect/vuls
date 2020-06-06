package config

import (
	"encoding/json"
	"os"
)

// JSONLoader loads configuration
type JSONLoader struct {
}

// Load load the configuration JSON file specified by path arg.
func (c JSONLoader) Load(path, keyPass string) (err error) {
	var conf Config
	configFile, _ := os.Open(path)
	decoder := json.NewDecoder(configFile)
	if err := decoder.Decode(&conf); err != nil {
		return err
	}
	if err := ToConf(conf, keyPass); err != nil {
		return err
	}
	return nil
}
