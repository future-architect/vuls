package fvuls

type CreatePseudoServerInput struct {
	ServerName string `json:"serverName"`
}

type AddCpeInput struct {
	ServerID int64  `json:"serverID"`
	CpeName  string `json:"cpeName"`
	IsURI    bool   `json:"isURI"`
}

type AddCpeOutput struct {
	Server ServerChild `json:"server"`
}

type ListCpesInput struct {
	Page     int   `json:"page"`
	Limit    int   `json:"limit"`
	ServerID int64 `json:"filterServerID"`
}

type ListCpesOutput struct {
	Paging  Paging    `json:"paging"`
	PkgCpes []PkgCpes `json:"pkgCpes"`
}

type Paging struct {
	Page      int `json:"page"`
	Limit     int `json:"limit"`
	TotalPage int `json:"totalPage"`
}
type PkgCpes struct {
	CpeFS string `json:"cpeFS"`
}

type ServerChild struct {
	ServerName string `json:"serverName"`
}

type ServerDetailOutput struct {
	ServerID   int64  `json:"id"`
	ServerName string `json:"serverName"`
	ServerUUID string `json:"serverUuid"`
}
