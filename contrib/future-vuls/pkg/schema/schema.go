package schema

const FILENAME = "discover_list.toml"
const SNMPVERSION = "v2c"
const RESTENDPOINT = "https://rest.vuls.biz/v1"
const TIMESTAMPFORMAT = "20060102150405"

type ServerConf struct {
	Server map[string]ServerDetail `toml:"server"`
}
type ServerDetail struct {
	IP         string   `toml:"ip"`
	ServerName string   `toml:"server_name"`
	UUID       string   `toml:"uuid"`
	CpeURI     []string `toml:"cpe_uri"`
	FvulsSync  bool     `toml:"fvuls_sync"`
}
