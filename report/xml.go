package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/future-architect/vuls/models"
)

const (
	vulsOpenTag  = "<vulsreport>"
	vulsCloseTag = "</vulsreport>"
)

// XMLWriter writes results to file.
type XMLWriter struct {
	ScannedAt time.Time
}

func (w XMLWriter) Write(scanResults []models.ScanResult) (err error) {
	var path string
	if path, err = ensureResultDir(w.ScannedAt); err != nil {
		return fmt.Errorf("Failed to make direcotory/symlink : %s", err)
	}

	for _, scanResult := range scanResults {
		scanResult.ScannedAt = w.ScannedAt
	}

	var xmlBytes []byte
	for _, r := range scanResults {
		xmlPath := ""
		if len(r.Container.ContainerID) == 0 {
			xmlPath = filepath.Join(path, fmt.Sprintf("%s.xml", r.ServerName))
		} else {
			xmlPath = filepath.Join(path,
				fmt.Sprintf("%s_%s.xml", r.ServerName, r.Container.Name))
		}

		if xmlBytes, err = xml.Marshal(r); err != nil {
			return fmt.Errorf("Failed to Marshal to XML: %s", err)
		}

		allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), xmlBytes, []byte(vulsCloseTag)}, []byte{})
		if err := ioutil.WriteFile(xmlPath, allBytes, 0600); err != nil {
			return fmt.Errorf("Failed to write XML. path: %s, err: %s", xmlPath, err)
		}
	}
	return nil
}
