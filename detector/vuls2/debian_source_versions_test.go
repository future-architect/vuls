package vuls2_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scanner"
)

func TestDebianSourceVersionsReachDetector(t *testing.T) {
	const oldVersion = "8.5.0-2ubuntu10"
	const newVersion = "8.5.0-2ubuntu10.9"
	lines := []string{
		"curl,ii ," + newVersion + ",curl," + newVersion,
		"libcurl4t64:arm64,ii ," + newVersion + ",curl," + newVersion,
		"libcurl3t64-gnutls:arm64,hi ," + oldVersion + ",curl," + oldVersion,
	}
	for _, tt := range []struct {
		name  string
		order []int
	}{
		{name: "old first", order: []int{2, 0, 1}},
		{name: "old last", order: []int{0, 1, 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var input []string
			for _, i := range tt.order {
				input = append(input, lines[i])
			}
			distro := config.Distro{Family: "ubuntu", Release: "24.04"}
			bins, srcs, err := scanner.ParseInstalledPkgs(distro, models.Kernel{}, strings.Join(input, "\n"))
			if err != nil {
				t.Fatal(err)
			}
			// Detection may run after the scan result has been saved and reloaded.
			data, err := json.Marshal(models.ScanResult{Family: distro.Family, Release: distro.Release, Packages: bins, SrcPackages: srcs})
			if err != nil {
				t.Fatal(err)
			}
			var restored models.ScanResult
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			converted := vuls2.PreConvertPkgs(&restored)
			want := map[string]string{"curl": newVersion, "libcurl4t64": newVersion, "libcurl3t64-gnutls": oldVersion}
			if len(converted.OSPackages) != len(want) {
				t.Fatalf("got %d detector packages, want %d", len(converted.OSPackages), len(want))
			}
			for _, p := range converted.OSPackages {
				version, ok := want[p.Name]
				if !ok || p.SrcName != "curl" || p.SrcVersion != version || p.Version != version {
					t.Errorf("incorrect detector input for %s: %+v, want source curl %s", p.Name, p, version)
				}
				delete(want, p.Name)
			}
			if len(want) != 0 {
				t.Errorf("missing detector packages: %v", want)
			}
		})
	}
}
