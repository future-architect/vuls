package schema

const FILENAME = "./discover_list.toml"
const SNMPVERSION = "v2c"

type ServerConf struct {
	Server map[string]ServerDetail `toml:"server"`
}
type ServerDetail struct {
	IP        string   `toml:"ip"`
	UUID      string   `toml:"uuid"`
	CpeURI    []string `toml:"cpe_uri"`
	FvulsSync bool     `toml:"fvuls_sync"`
}
