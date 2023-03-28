package snmp

// Result ...
type Result struct {
	SysDescr0         string                   `json:"sysDescr0,omitempty"`
	EntPhysicalTables map[int]EntPhysicalTable `json:"entPhysicalTables,omitempty"`
}

// EntPhysicalTable ...
type EntPhysicalTable struct {
	EntPhysicalMfgName     string `json:"entPhysicalMfgName,omitempty"`
	EntPhysicalName        string `json:"entPhysicalName,omitempty"`
	EntPhysicalSoftwareRev string `json:"entPhysicalSoftwareRev,omitempty"`
}
