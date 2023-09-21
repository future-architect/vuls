// Package fvuls ...
package fvuls

// CreatePseudoServerInput ...
type CreatePseudoServerInput struct {
	ServerName string `json:"serverName"`
}

// AddCpeInput ...
type AddCpeInput struct {
	ServerID int64  `json:"serverID"`
	CpeName  string `json:"cpeName"`
	IsURI    bool   `json:"isURI"`
}

// AddCpeOutput ...
type AddCpeOutput struct {
	Server ServerChild `json:"server"`
}

// ListCpesInput ...
type ListCpesInput struct {
	Page     int   `json:"page"`
	Limit    int   `json:"limit"`
	ServerID int64 `json:"filterServerID"`
}

// ListCpesOutput ...
type ListCpesOutput struct {
	Paging  Paging    `json:"paging"`
	PkgCpes []PkgCpes `json:"pkgCpes"`
}

// Paging ...
type Paging struct {
	Page      int `json:"page"`
	Limit     int `json:"limit"`
	TotalPage int `json:"totalPage"`
}

// PkgCpes ...
type PkgCpes struct {
	CpeFS string `json:"cpeFS"`
}

// ServerChild ...
type ServerChild struct {
	ServerName string `json:"serverName"`
}

// ServerDetailOutput ...
type ServerDetailOutput struct {
	ServerID   int64  `json:"id"`
	ServerName string `json:"serverName"`
	ServerUUID string `json:"serverUuid"`
}
