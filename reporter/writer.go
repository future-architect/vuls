package reporter

import (
	"bytes"
	"compress/gzip"

	"github.com/future-architect/vuls/models"
)

// ResultWriter Interface
type ResultWriter interface {
	Write(...models.ScanResult) error
}

func gz(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
