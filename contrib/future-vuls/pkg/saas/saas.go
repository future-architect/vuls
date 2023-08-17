package saas

import (
	"encoding/json"
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/saas"
)

func UploadToFvuls(serverUUID string, groupID int64, url string, token string, tags []string, scanResultJSON []byte) error {
	var scanResult models.ScanResult
	if err := json.Unmarshal(scanResultJSON, &scanResult); err != nil {
		return fmt.Errorf("failed to parse json. err: %v\nPlease check trivy scan results.\n", err)
	}
	scanResult.ServerUUID = serverUUID
	if 0 < len(tags) {
		if scanResult.Optional == nil {
			scanResult.Optional = map[string]interface{}{}
		}
		scanResult.Optional["VULS_TAGS"] = tags
	}

	config.Conf.Saas.GroupID = groupID
	config.Conf.Saas.Token = token
	config.Conf.Saas.URL = url
	if err := (saas.Writer{}).Write(scanResult); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}
