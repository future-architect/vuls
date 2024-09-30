package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
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
		k := fmt.Sprintf("%s/summary.txt", rs[0].ScannedAt.Format(time.RFC3339))
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

	pager := cli.NewListContainersPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return xerrors.Errorf("Failed to next page. err: %w", err)
		}
		for _, con := range page.ContainerItems {
			if *con.Name == w.ContainerName {
				return nil
			}
		}
	}
	return xerrors.Errorf("Container not found. Container: %s", w.ContainerName)
}

func (w AzureBlobWriter) getBlobClient() (*azblob.Client, error) {
	cred, err := azblob.NewSharedKeyCredential(w.AccountName, w.AccountKey)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create SharedKeyCredential. err: %w", err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(w.Endpoint, cred, nil)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create Client. err: %w", err)
	}

	return client, nil
}

func (w AzureBlobWriter) createBlockBlob(cli *azblob.Client, k string, b []byte, gzip bool) error {
	var err error
	if gzip {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	if _, err := cli.UploadBuffer(context.TODO(), w.ContainerName, k, b, nil); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w", w.ContainerName, k, err)
	}
	return nil
}
