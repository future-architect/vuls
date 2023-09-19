package saas

import (
	"encoding/json"
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/saas"
)

// UploadToFvuls ...
func UploadToFvuls(serverUUID string, groupID int64, url string, token string, tags []string, scanResultJSON []byte) error {
	var scanResult models.ScanResult
	if err := json.Unmarshal(scanResultJSON, &scanResult); err != nil {
		fmt.Printf("failed to parse json. err: %v\nPerhaps scan has failed. Please check following scan results.\nResult: %s", err, fmt.Sprintf("%s", scanResultJSON))
		return err
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
		fmt.Printf("%v", err)
		return err
	}
	return nil
}
