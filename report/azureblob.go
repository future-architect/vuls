package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	storage "github.com/Azure/azure-sdk-for-go/storage"
	"golang.org/x/xerrors"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// AzureBlobWriter writes results to AzureBlob
type AzureBlobWriter struct{}

// Write results to Azure Blob storage
func (w AzureBlobWriter) Write(rs ...models.ScanResult) (err error) {
	if len(rs) == 0 {
		return nil
	}

	cli, err := getBlobClient()
	if err != nil {
		return err
	}

	if c.Conf.FormatOneLineText {
		timestr := rs[0].ScannedAt.Format(time.RFC3339)
		k := fmt.Sprintf(timestr + "/summary.txt")
		text := formatOneLineSummary(rs...)
		b := []byte(text)
		if err := createBlockBlob(cli, k, b); err != nil {
			return err
		}
	}

	for _, r := range rs {
		key := r.ReportKeyName()
		if c.Conf.FormatJSON {
			k := key + ".json"
			var b []byte
			if b, err = json.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := createBlockBlob(cli, k, b); err != nil {
				return err
			}
		}

		if c.Conf.FormatList {
			k := key + "_short.txt"
			b := []byte(formatList(r))
			if err := createBlockBlob(cli, k, b); err != nil {
				return err
			}
		}

		if c.Conf.FormatFullText {
			k := key + "_full.txt"
			b := []byte(formatFullPlainText(r))
			if err := createBlockBlob(cli, k, b); err != nil {
				return err
			}
		}

		if c.Conf.FormatXML {
			k := key + ".xml"
			var b []byte
			if b, err = xml.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to XML: %w", err)
			}
			allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})
			if err := createBlockBlob(cli, k, allBytes); err != nil {
				return err
			}
		}
	}
	return
}

// CheckIfAzureContainerExists check the existence of Azure storage container
func CheckIfAzureContainerExists() error {
	cli, err := getBlobClient()
	if err != nil {
		return err
	}
	r, err := cli.ListContainers(storage.ListContainersParameters{})
	if err != nil {
		return err
	}

	found := false
	for _, con := range r.Containers {
		if con.Name == c.Conf.Azure.ContainerName {
			found = true
			break
		}
	}
	if !found {
		return xerrors.Errorf("Container not found. Container: %s", c.Conf.Azure.ContainerName)
	}
	return nil
}

func getBlobClient() (storage.BlobStorageClient, error) {
	api, err := storage.NewBasicClient(c.Conf.Azure.AccountName, c.Conf.Azure.AccountKey)
	if err != nil {
		return storage.BlobStorageClient{}, err
	}
	return api.GetBlobService(), nil
}

func createBlockBlob(cli storage.BlobStorageClient, k string, b []byte) error {
	var err error
	if c.Conf.GZIP {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	ref := cli.GetContainerReference(c.Conf.Azure.ContainerName)
	blob := ref.GetBlobReference(k)
	if err := blob.CreateBlockBlobFromReader(bytes.NewReader(b), nil); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
			c.Conf.Azure.ContainerName, k, err)
	}
	return nil
}
