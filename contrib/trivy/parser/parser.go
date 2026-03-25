// Package parser ...
package parser

import (
	"encoding/json"
	"fmt"

	v2 "github.com/future-architect/vuls/contrib/trivy/parser/v2"
	"github.com/future-architect/vuls/models"
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
		return nil, fmt.Errorf("Failed to parse JSON. Please use the latest version of trivy, trivy-to-vuls and future-vuls")
	}
	switch r.SchemaVersion {
	case 2:
		return v2.ParserV2{}, nil
	default:
		return nil, fmt.Errorf("Failed to parse trivy json. SchemeVersion %d is not supported yet. Please contact support", r.SchemaVersion)
	}
}
