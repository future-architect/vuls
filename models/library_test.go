package models

import (
	"testing"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestScan(t *testing.T) {
	var tests = []struct {
		path string
		pkgs []godeptypes.Library
	}{
		{
			path: "app/package-lock.json",
			pkgs: []godeptypes.Library{
				{
					Name:    "jquery",
					Version: "2.2.4",
				},
				{
					Name:    "@babel/traverse",
					Version: "7.4.4",
				},
			},
		},
	}

	if err := log.InitLogger(false, false); err != nil {
		t.Errorf("trivy logger failed")
	}

	if err := db.Init(); err != nil {
		t.Errorf("trivy db.Init failed")
	}
	for _, v := range tests {
		lib := LibraryScanner{
			Path: v.path,
			Libs: v.pkgs,
		}
		actual, err := lib.Scan()
		if err != nil {
			t.Errorf("error occurred")
		}
		if len(actual) == 0 {
			t.Errorf("no vuln found : actual: %v\n", actual)
		}
	}
	db.Close()
}
