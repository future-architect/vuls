package schema

const FileName = "discover_list.toml"
const SnmpVersion = "v2c"
const RestEndPoint = "https://rest.vuls.biz/v1"
const TimeStampFormat = "20060102150405"

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
