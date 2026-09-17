package vuls2

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/future-architect/vuls/models"
)

func Test_advisoryReference_solaris(t *testing.T) {
	got, err := advisoryReference(ecosystemTypes.Ecosystem("solaris:11.4"), sourceTypes.SourceID("oracle-solaris"), models.DistroAdvisory{AdvisoryID: "bulletinjul2026"})
	if err != nil {
		t.Fatal(err)
	}
	want := models.Reference{Link: "https://www.oracle.com/security-alerts/bulletinjul2026.html", Source: "ORACLE", RefID: "bulletinjul2026"}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("advisoryReference() (-want +got):\n%s", diff)
	}
}

func Test_toCveContentType_solaris(t *testing.T) {
	if got := toCveContentType(ecosystemTypes.Ecosystem("solaris:10"), sourceTypes.SourceID("oracle-solaris")); got != models.Solaris {
		t.Errorf("toCveContentType() = %s, want %s", got, models.Solaris)
	}
}

func Test_cveContentSourceLink_solaris(t *testing.T) {
	got := cveContentSourceLink(models.Solaris, vulnerabilityTypes.Vulnerability{}, dataTypes.RootID("bulletinjul2026"))
	if want := "https://www.oracle.com/security-alerts/bulletinjul2026.html"; got != want {
		t.Errorf("cveContentSourceLink() = %q, want %q", got, want)
	}
}

func Test_toVuls0Confidence_solaris(t *testing.T) {
	if got := toVuls0Confidence(ecosystemTypes.Ecosystem("solaris:11.4"), sourceTypes.SourceID("oracle-solaris"), sourceData{}); got != models.OracleSolarisAdvisoryMatch {
		t.Errorf("toVuls0Confidence() = %+v, want %+v", got, models.OracleSolarisAdvisoryMatch)
	}
}
