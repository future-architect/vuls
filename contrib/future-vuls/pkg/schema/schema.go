package schema

// output filename
const FILENAME = "./discover_list.toml"

// snmp2cpe version
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
