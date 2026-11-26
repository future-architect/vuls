package models

import (
	"reflect"
	"testing"
)

func TestCiscoAdvisoryScores(t *testing.T) {
	for _, version := range []CvssType{CVSS3, CVSS40} {
		t.Run(string(version), func(t *testing.T) {
			content := CveContent{Type: Cisco, Optional: map[string]string{"source": "Cisco advisory"}}
			vector := "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
			if version == CVSS3 {
				content.Cvss3Score, content.Cvss3Vector, content.Cvss3Severity = 7.7, vector, "high"
			} else {
				vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
				content.Cvss40Score, content.Cvss40Vector, content.Cvss40Severity = 7.7, vector, "high"
			}
			v := VulnInfo{CveContents: CveContents{Cisco: []CveContent{content}}}
			var scores []CveContentCvss
			var maximum CveContentCvss
			if version == CVSS3 {
				scores, maximum = v.Cvss3Scores(), v.MaxCvss3Score()
			} else {
				scores, maximum = v.Cvss40Scores(), v.MaxCvss40Score()
			}
			want := CveContentCvss{Type: Cisco, Source: "Cisco advisory", Value: Cvss{Type: version, Score: 7.7, Vector: vector, Severity: "HIGH"}}
			if !reflect.DeepEqual(scores, []CveContentCvss{want}) {
				t.Errorf("Cisco-only scores = %#v, want %#v", scores, want)
			}
			if !reflect.DeepEqual(maximum, want) {
				t.Errorf("maximum = %#v, want %#v", maximum, want)
			}
		})
	}
}

func TestCiscoScoresPreserveExistingSourcePrecedence(t *testing.T) {
	for _, version := range []CvssType{CVSS3, CVSS40} {
		t.Run(string(version), func(t *testing.T) {
			nvd := CveContent{Type: Nvd}
			cisco := CveContent{Type: Cisco}
			if version == CVSS3 {
				nvd.Cvss3Score, cisco.Cvss3Score = 7.7, 7.7
			} else {
				nvd.Cvss40Score, cisco.Cvss40Score = 7.7, 7.7
			}
			v := VulnInfo{CveContents: CveContents{Nvd: []CveContent{nvd}, Cisco: []CveContent{cisco}}}
			var scores []CveContentCvss
			var maximum CveContentCvss
			if version == CVSS3 {
				scores, maximum = v.Cvss3Scores(), v.MaxCvss3Score()
			} else {
				scores, maximum = v.Cvss40Scores(), v.MaxCvss40Score()
			}
			if len(scores) != 2 || scores[0].Type != Nvd || scores[1].Type != Cisco || maximum.Type != Nvd {
				t.Fatalf("existing tie precedence changed: scores=%#v max=%#v", scores, maximum)
			}
		})
	}
}

func TestCiscoScoreFilteringAndSeveritySummary(t *testing.T) {
	v3 := VulnInfo{CveID: "CVE-2019-1688", CveContents: CveContents{Cisco: []CveContent{{Type: Cisco, Cvss3Score: 7.7, Cvss3Severity: "HIGH"}}}}
	v4 := VulnInfo{CveID: "fixture-v4", CveContents: CveContents{Cisco: []CveContent{{Type: Cisco, Cvss40Score: 9.3, Cvss40Severity: "CRITICAL"}}}}
	infos := VulnInfos{v3.CveID: v3, v4.CveID: v4, "empty": {CveContents: CveContents{Cisco: []CveContent{{Type: Cisco}}}}}
	scored, filtered := infos.FindScoredVulns()
	if len(scored) != 2 || filtered != 1 {
		t.Fatalf("Cisco scores were filtered out: scored=%#v filtered=%d", scored, filtered)
	}
	if counts := infos.CountGroupBySeverity(); counts["High"] != 1 || counts["Critical"] != 1 {
		t.Fatalf("Cisco severity summary = %#v", counts)
	}
	if v3.MaxCvssScore().Type != Cisco || v4.MaxCvssScore().Value.Type != CVSS40 {
		t.Fatal("combined maximum lost Cisco score")
	}
}

func TestCiscoMultipleAndEmptyAdvisoryScores(t *testing.T) {
	v := VulnInfo{CveContents: CveContents{Cisco: []CveContent{
		{Type: Cisco},
		{Type: Cisco, Cvss3Score: 7.7, Cvss40Score: 7.7},
		{Type: Cisco, Cvss3Score: 9.8, Cvss40Score: 9.3},
	}}}
	if got := v.Cvss3Scores(); len(got) != 2 || got[0].Value.Score != 7.7 || got[1].Value.Score != 9.8 {
		t.Fatalf("v3 advisory scores = %#v", got)
	}
	if got := v.Cvss40Scores(); len(got) != 2 || got[0].Value.Score != 7.7 || got[1].Value.Score != 9.3 {
		t.Fatalf("v4 advisory scores = %#v", got)
	}
	if v.MaxCvss3Score().Value.Score != 9.8 || v.MaxCvss40Score().Value.Score != 9.3 {
		t.Fatal("maximum did not retain highest Cisco advisory score")
	}
	// Keep the existing severity-only and empty-score behavior of these APIs.
	v = VulnInfo{CveContents: CveContents{Cisco: []CveContent{{Type: Cisco, Cvss3Severity: "low", Cvss40Severity: "low"}}}}
	for _, got := range [][]CveContentCvss{v.Cvss3Scores(), v.Cvss40Scores()} {
		if len(got) != 1 || got[0].Value.Score != 0 || got[0].Value.Severity != "LOW" || got[0].Value.CalculatedBySeverity {
			t.Fatalf("severity-only behavior changed: %#v", got)
		}
	}
}
