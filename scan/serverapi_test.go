package scan

import "testing"

func TestPackageCveInfosSetGet(t *testing.T) {
	var test = struct {
		in  []string
		out []string
	}{
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
			"CVE1",
			"CVE1",
			"CVE2",
			"CVE3",
		},
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
		},
	}

	//  var ps packageCveInfos
	var ps CvePacksList
	for _, cid := range test.in {
		ps = ps.set(cid, CvePacksInfo{CveID: cid})
	}

	if len(test.out) != len(ps) {
		t.Errorf("length: expected %d, actual %d", len(test.out), len(ps))
	}

	for i, expectedCid := range test.out {
		if expectedCid != ps[i].CveID {
			t.Errorf("expected %s, actual %s", expectedCid, ps[i].CveID)
		}
	}
	for _, cid := range test.in {
		p, _ := ps.FindByCveID(cid)
		if p.CveID != cid {
			t.Errorf("expected %s, actual %s", cid, p.CveID)
		}
	}
}
