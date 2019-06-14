package report

import (
	"testing"

	"github.com/future-architect/vuls/config"

	"github.com/future-architect/vuls/models"
)

const defaultUUID = "11111111-1111-1111-1111-111111111111"

func TestGetOrCreateServerUUID(t *testing.T) {

	cases := map[string]struct {
		scanResult models.ScanResult
		server     config.ServerInfo
		isDefault  bool
	}{
		"baseServer": {
			scanResult: models.ScanResult{
				ServerName: "hoge",
			},
			server: config.ServerInfo{
				UUIDs: map[string]string{
					"hoge": defaultUUID,
				},
			},
			isDefault: false,
		},
		"onlyContainers": {
			scanResult: models.ScanResult{
				ServerName: "hoge",
			},
			server: config.ServerInfo{
				UUIDs: map[string]string{
					"fuga": defaultUUID,
				},
			},
			isDefault: false,
		},
	}

	for testcase, v := range cases {
		uuid := getOrCreateServerUUID(v.scanResult, v.server)
		if (uuid == defaultUUID) != v.isDefault {
			t.Errorf("%s : expected isDefault %t got %s", testcase, v.isDefault, uuid)
		}
	}

}
