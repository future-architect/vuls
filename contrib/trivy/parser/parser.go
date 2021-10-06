package parser

import (
	"encoding/json"

	v1 "github.com/future-architect/vuls/contrib/trivy/parser/v1"
	v2 "github.com/future-architect/vuls/contrib/trivy/parser/v2"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

type Parser interface {
	Parse(vulnJSON []byte, scanResult *models.ScanResult) (result *models.ScanResult, err error)
}

type Report struct {
	SchemaVersion int `json:",omitempty"`
}

func NewParser(vulnJSON []byte) (Parser, error) {
	r := Report{}
	if err := json.Unmarshal(vulnJSON, &r); err != nil {
		return v1.ParserV1{}, nil
	}
	switch r.SchemaVersion {
	case 2:
		return v2.ParserV2{}, nil
	default:
		return nil, xerrors.Errorf("Failed to parse trivy json. SchemeVersion %d is not supported yet. Please contact support", r.SchemaVersion)
	}
}
