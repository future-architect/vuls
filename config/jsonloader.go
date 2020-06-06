package config

import (
	"encoding/json"
	"os"
)

// JSONLoader loads configuration
type JSONLoader struct {
}

// Load load the configuration JSON file specified by path arg.
func (c JSONLoader) Load(pathToJSON, keyPass string) error {
	var conf Config
	configFile, err := os.Open(pathToJSON)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(configFile)
	if err := decoder.Decode(&conf); err != nil {
		return err
	}
	if err := toConf(conf, keyPass); err != nil {
		return err
	}
	return nil
}
