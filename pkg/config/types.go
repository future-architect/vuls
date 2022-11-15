package config

type Config struct {
	Server *Server         `json:"server"`
	Hosts  map[string]Host `json:"hosts"`
}

type Scan struct {
	OSPkg     *scanOSPkg `json:"ospkg,omitempty"`
	CPE       []scanCPE  `json:"cpe,omitempty"`
	ResultDir string     `json:"result_dir,omitempty"`
}

type scanOSPkg struct {
	Root bool `json:"root"`
}

type scanCPE struct {
	CPE       string `json:"cpe,omitempty"`
	RunningOn string `json:"running_on,omitempty"`
}

type Detect struct {
	Path      string `json:"path"`
	ResultDir string `json:"result_dir"`
}

type Server struct {
	Listen string `json:"listen"`
	Path   string `json:"path"`
}
type Host struct {
	Type      string  `json:"type"`
	Host      *string `json:"host"`
	Port      *string `json:"port"`
	User      *string `json:"user"`
	SSHConfig *string `json:"ssh_config"`
	SSHKey    *string `json:"ssh_key"`
	Scan      Scan    `json:"scan"`
	Detect    Detect  `json:"detect"`
}
