package vuls2

import (
	"testing"

	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/future-architect/vuls/models"
)

func Test_advisoryReference_solaris(t *testing.T) {
	got, err := advisoryReference(ecosystemTypes.Ecosystem("solaris:11.4"), sourceTypes.SourceID("oracle-solaris"), models.DistroAdvisory{AdvisoryID: "bulletinjul2026"})
	if err != nil {
		t.Fatal(err)
	}
	want := models.Reference{Link: "https://www.oracle.com/security-alerts/bulletinjul2026.html", Source: "ORACLE", RefID: "bulletinjul2026"}
	if got != want {
		t.Errorf("advisoryReference() = %+v, want %+v", got, want)
	}
}

func Test_toCveContentType_solaris(t *testing.T) {
	if got := toCveContentType(ecosystemTypes.Ecosystem("solaris:10"), sourceTypes.SourceID("oracle-solaris")); got != models.Solaris {
		t.Errorf("toCveContentType() = %s, want %s", got, models.Solaris)
	}
}

func Test_toVuls0Confidence_solaris(t *testing.T) {
	if got := toVuls0Confidence(ecosystemTypes.Ecosystem("solaris:11.4"), sourceTypes.SourceID("oracle-solaris"), sourceData{}); got != models.OracleSolarisAdvisoryMatch {
		t.Errorf("toVuls0Confidence() = %+v, want %+v", got, models.OracleSolarisAdvisoryMatch)
	}
}

func Test_selectFixedIn_solarisIPS(t *testing.T) {
	tests := []struct {
		name  string
		fixed []string
		want  string
	}{
		{name: "branch order", fixed: []string{"11.4-11.4.93", "11.4-11.4.94", "11.4-11.4.9"}, want: "11.4-11.4.94"},
		{name: "prefix sorts first", fixed: []string{"11.4-11.4.94.0.1.113.1", "11.4-11.4.94"}, want: "11.4-11.4.94.0.1.113.1"},
		{name: "timestamp only", fixed: []string{"0.5.11:20151020T000000Z", "0.5.11:20160119T000000Z"}, want: "0.5.11:20160119T000000Z"},
		{name: "release only", fixed: []string{"1.8.0.471", "1.8.0.481"}, want: "1.8.0.481"},
		{name: "unparsable sorts first", fixed: []string{"not-a-version", "11.4-11.4.1"}, want: "11.4-11.4.1"},
		{name: "single", fixed: []string{"11.4-11.4.1"}, want: "11.4-11.4.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectFixedIn(vcAffectedRangeTypes.RangeTypeSolarisIPS, tt.fixed); got != tt.want {
				t.Errorf("selectFixedIn() = %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_comparePackStatus_solarisIPS(t *testing.T) {
	ps := func(fixedIn string, notFixed bool) packStatus {
		return packStatus{
			rangeType: vcAffectedRangeTypes.RangeTypeSolarisIPS,
			status:    models.PackageFixStatus{Name: "entire", FixedIn: fixedIn, NotFixedYet: notFixed},
		}
	}
	tests := []struct {
		name string
		a, b packStatus
		want int
	}{
		{name: "lower level first", a: ps("11.4-11.4.93", false), b: ps("11.4-11.4.94", false), want: -1},
		{name: "equal", a: ps("11.4-11.4.94", false), b: ps("11.4-11.4.94", false), want: 0},
		{name: "not fixed yet sorts after fixed", a: ps("", true), b: ps("11.4-11.4.94", false), want: +1},
		{name: "date bounds", a: ps("0.5.11:20160119T000000Z", false), b: ps("0.5.11:20151020T000000Z", false), want: +1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := comparePackStatus(tt.a, tt.b)
			if err != nil {
				t.Fatal(err)
			}
			if sign(got) != tt.want {
				t.Errorf("comparePackStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
