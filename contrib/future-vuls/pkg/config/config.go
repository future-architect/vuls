// Package config ...
package config

const (
	DiscoverTomlFileName        = "discover_list.toml"
	SnmpVersion                 = "v2c"
	FvulsDomain                 = "vuls.biz"
	Community                   = "public"
	DiscoverTomlTimeStampFormat = "20060102150405"
)

// DiscoverToml ...
type DiscoverToml map[string]ServerSetting

// ServerSetting ...
type ServerSetting struct {
	IP         string   `toml:"ip"`
	ServerName string   `toml:"server_name"`
	UUID       string   `toml:"uuid"`
	CpeURIs    []string `toml:"cpe_uris"`
	FvulsSync  bool     `toml:"fvuls_sync"`
	// use internal
	NewCpeURIs []string `toml:"-"`
}
