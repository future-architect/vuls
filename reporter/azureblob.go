package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	storage "github.com/Azure/azure-sdk-for-go/storage"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// AzureBlobWriter writes results to AzureBlob
type AzureBlobWriter struct {
	FormatJSON        bool
	FormatFullText    bool
	FormatOneLineText bool
	FormatList        bool
	Gzip              bool

	config.AzureConf
}

// Write results to Azure Blob storage
func (w AzureBlobWriter) Write(rs ...models.ScanResult) (err error) {
	if len(rs) == 0 {
		return nil
	}

	cli, err := w.getBlobClient()
	if err != nil {
		return err
	}

	if w.FormatOneLineText {
		timestr := rs[0].ScannedAt.Format(time.RFC3339)
		k := fmt.Sprintf(timestr + "/summary.txt")
		text := formatOneLineSummary(rs...)
		b := []byte(text)
		if err := w.createBlockBlob(cli, k, b, w.Gzip); err != nil {
			return err
		}
	}

	for _, r := range rs {
		key := r.ReportKeyName()
		if w.FormatJSON {
			k := key + ".json"
			var b []byte
			if b, err = json.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := w.createBlockBlob(cli, k, b, w.Gzip); err != nil {
				return err
			}
		}

		if w.FormatList {
			k := key + "_short.txt"
			b := []byte(formatList(r))
			if err := w.createBlockBlob(cli, k, b, w.Gzip); err != nil {
				return err
			}
		}

		if w.FormatFullText {
			k := key + "_full.txt"
			b := []byte(formatFullPlainText(r))
			if err := w.createBlockBlob(cli, k, b, w.Gzip); err != nil {
				return err
			}
		}
	}
	return
}

// Validate check the existence of Azure storage container
func (w AzureBlobWriter) Validate() error {
	cli, err := w.getBlobClient()
	if err != nil {
		return err
	}
	r, err := cli.ListContainers(storage.ListContainersParameters{})
	if err != nil {
		return err
	}

	found := false
	for _, con := range r.Containers {
		if con.Name == w.ContainerName {
			found = true
			break
		}
	}
	if !found {
		return xerrors.Errorf("Container not found. Container: %s", w.ContainerName)
	}
	return nil
}

func (w AzureBlobWriter) getBlobClient() (storage.BlobStorageClient, error) {
	api, err := storage.NewBasicClient(w.AccountName, w.AccountKey)
	if err != nil {
		return storage.BlobStorageClient{}, err
	}
	return api.GetBlobService(), nil
}

func (w AzureBlobWriter) createBlockBlob(cli storage.BlobStorageClient, k string, b []byte, gzip bool) error {
	var err error
	if gzip {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	ref := cli.GetContainerReference(w.ContainerName)
	blob := ref.GetBlobReference(k)
	if err := blob.CreateBlockBlobFromReader(bytes.NewReader(b), nil); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
			w.ContainerName, k, err)
	}
	return nil
}
