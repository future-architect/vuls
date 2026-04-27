package vuls2_test

import (
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/db/session"

	vuls2 "github.com/future-architect/vuls/detector/vuls2"
	testutil "github.com/future-architect/vuls/detector/vuls2/internal/test"
	"github.com/future-architect/vuls/models"
)

func Test_enrichCTI(t *testing.T) {
	tests := []struct {
		name string
		vi   models.VulnInfo
		want models.VulnInfo
	}{
		{
			name: "cwe with capec+attack chain resolves all",
			vi: models.VulnInfo{
				CveID: "CVE-2024-TEST",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-TEST",
						CweIDs: []string{"CWE-306"},
					}},
				},
			},
			want: models.VulnInfo{
				CveID: "CVE-2024-TEST",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-TEST",
						CweIDs: []string{"CWE-306"},
					}},
				},
				Ctis: []string{"CAPEC-115", "CAPEC-36", "T1552"},
				CtiDetails: map[string]models.CTIDetail{
					"CAPEC-115": {ID: "CAPEC-115", Name: "Authentication Bypass", Type: "capec"},
					"CAPEC-36":  {ID: "CAPEC-36", Name: "Using Unpublished Interfaces or Functionality", Type: "capec"},
					"T1552": {
						ID:        "T1552",
						Name:      "Unsecured Credentials",
						Type:      "attack",
						Platforms: []string{"Linux", "Windows", "macOS"},
					},
				},
			},
		},
		{
			name: "no CWE leaves VulnInfo untouched",
			vi: models.VulnInfo{
				CveID: "CVE-2024-NOCWE",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:  models.RedHatAPI,
						CveID: "CVE-2024-NOCWE",
					}},
				},
			},
			want: models.VulnInfo{
				CveID: "CVE-2024-NOCWE",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:  models.RedHatAPI,
						CveID: "CVE-2024-NOCWE",
					}},
				},
			},
		},
		{
			name: "unknown CWE silently skipped",
			vi: models.VulnInfo{
				CveID: "CVE-2024-UNKNOWN",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-UNKNOWN",
						CweIDs: []string{"CWE-9999"},
					}},
				},
			},
			want: models.VulnInfo{
				CveID: "CVE-2024-UNKNOWN",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-UNKNOWN",
						CweIDs: []string{"CWE-9999"},
					}},
				},
			},
		},
	}

	c := session.Config{Type: "boltdb", Path: filepath.Join(t.TempDir(), "enrich-cti.db")}
	if err := testutil.PopulateDB(c, "testdata/fixtures/enrich"); err != nil {
		t.Fatalf("PopulateDB() err: %v", err)
	}
	sesh, err := c.New()
	if err != nil {
		t.Fatalf("session.Config.New() err: %v", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		t.Fatalf("Storage().Open() err: %v", err)
	}
	defer sesh.Storage().Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vi
			vuls2.EnrichCTI(&got, sesh)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("enrichCTI() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
