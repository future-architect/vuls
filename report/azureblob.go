/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/storage"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// AzureBlobWriter writes results to AzureBlob
type AzureBlobWriter struct{}

// CheckIfAzureContainerExists check the existence of Azure storage container
func CheckIfAzureContainerExists() error {
	cli, err := getBlobClient()
	if err != nil {
		return err
	}
	ok, err := cli.ContainerExists(c.Conf.AzureContainer)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Container not found. Container: %s", c.Conf.AzureContainer)
	}
	return nil
}

func getBlobClient() (storage.BlobStorageClient, error) {
	api, err := storage.NewBasicClient(c.Conf.AzureAccount, c.Conf.AzureKey)
	if err != nil {
		return storage.BlobStorageClient{}, err
	}
	return api.GetBlobService(), nil
}

// Write results to Azure Blob storage
func (w AzureBlobWriter) Write(scanResults []models.ScanResult) (err error) {
	reqChan := make(chan models.ScanResult, len(scanResults))
	resChan := make(chan bool)
	errChan := make(chan error, len(scanResults))
	defer close(resChan)
	defer close(errChan)
	defer close(reqChan)

	timeout := time.After(10 * 60 * time.Second)
	concurrency := 10
	tasks := util.GenWorkers(concurrency)

	go func() {
		for _, r := range scanResults {
			reqChan <- r
		}
	}()

	for range scanResults {
		tasks <- func() {
			select {
			case sresult := <-reqChan:
				func(r models.ScanResult) {
					err := w.upload(r)
					if err != nil {
						errChan <- err
					}
					resChan <- true
				}(sresult)
			}
		}
	}

	errs := []error{}
	for i := 0; i < len(scanResults); i++ {
		select {
		case <-resChan:
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			errs = append(errs, fmt.Errorf("Timeout while uploading to azure Blob"))
		}
	}

	if 0 < len(errs) {
		return fmt.Errorf("Failed to upload json to Azure Blob: %v", errs)
	}
	return nil
}

func (w AzureBlobWriter) upload(res models.ScanResult) (err error) {
	cli, err := getBlobClient()
	if err != nil {
		return err
	}
	timestr := time.Now().Format("20060102_1504")
	name := ""
	if len(res.Container.ContainerID) == 0 {
		name = fmt.Sprintf("%s/%s.json", timestr, res.ServerName)
	} else {
		name = fmt.Sprintf("%s/%s_%s.json", timestr, res.ServerName, res.Container.Name)
	}

	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("Failed to Marshal to JSON: %s", err)
	}

	if err = cli.CreateBlockBlobFromReader(
		c.Conf.AzureContainer,
		name,
		uint64(len(jsonBytes)),
		bytes.NewReader(jsonBytes),
		map[string]string{},
	); err != nil {
		return fmt.Errorf("%s/%s, %s",
			c.Conf.AzureContainer, name, err)
	}
	return
}
