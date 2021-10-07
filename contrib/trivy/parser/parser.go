package parser

import (
	"encoding/json"

	v1 "github.com/future-architect/vuls/contrib/trivy/parser/v1"
	v2 "github.com/future-architect/vuls/contrib/trivy/parser/v2"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

// Parser is a parser interface
type Parser interface {
	Parse(vulnJSON []byte) (result *models.ScanResult, err error)
}

// Report is used for judgeing the scheme version of trivy
type Report struct {
	SchemaVersion int `json:",omitempty"`
}

// NewParser make a parser for the schema version of trivy
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
