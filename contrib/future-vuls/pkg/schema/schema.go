package schema

// FileName ...
const FileName = "discover_list.toml"

// SnmpVersion ...
const SnmpVersion = "v2c"

// RestEndPoint ...
const RestEndPoint = "https://rest.vuls.biz/v1"

// TimeStampFormat ...
const TimeStampFormat = "20060102150405"

// ServerConf ...
type ServerConf struct {
	Server map[string]ServerDetail `toml:"server"`
}

// ServerDetail ...
type ServerDetail struct {
	IP         string   `toml:"ip"`
	ServerName string   `toml:"server_name"`
	UUID       string   `toml:"uuid"`
	CpeURI     []string `toml:"cpe_uri"`
	FvulsSync  bool     `toml:"fvuls_sync"`
}
