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
	"fmt"
	"time"
	"strings"

	log "github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"gopkg.in/olivere/elastic.v3"
)

type document struct {
	ScanID     uint      `json:"scanid"`
	Hostname   string    `json:"hostname"`
	ScanTime   time.Time `json:"scantime"`
	CVE        string    `json:"cve"`
	Summary    string    `json:"summary"`
	Vector     string    `json:"vector"`
	Text       string    `json:"text"`
	Link       string    `json:"link"`
	ServerInfo string    `json:"serverinfo"`
	Family     string    `json:"family"`
	Release    string    `json:"release"`
    Candidate  []string  `json:"candidate"`
	Installed  []string  `json:"installed"`
	Score      float64   `json:"score"`
	Severity   string    `json:"severity"`
    Success    bool      `json:"success"`
}

var mapping = `{
  "mappings" : {
	"vulscan" : {
	  "dynamic_templates" : [ {
		"notanalyzed" : {
		  "mapping" : {
			"index" : "not_analyzed",
			"type" : "string",
			"doc_values" : "true"
		  },
		  "match" : "*",
		  "match_mapping_type" : "string"
		}
	  } ],
	  "properties" : {
		"candidate" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"cve" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"family" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"hostname" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"installed" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"link" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"release" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"scanid" : {
		  "type" : "integer"
		},
		"scantime" : {
		  "type" : "date",
		  "format" : "dateOptionalTime"
		},
		"serverinfo" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		},
		"score": {
			"type": "integer"
		},
		"text" : {
		  "type" : "string",
		  "index" : "not_analyzed"
		}
	  }
	}
  }
}`

type ElasticsearchWriter struct{
	ScannedAt time.Time
}

// Write is the report writer that handles writing scan results to elasticsearch.
func (w ElasticsearchWriter) Write(scanResults []models.ScanResult) error {
	index := fmt.Sprintf("%s-%d.%d.%d", c.Conf.ElasticsearchPrefix, w.ScannedAt.Year(), w.ScannedAt.Month(), w.ScannedAt.Day())

	log.Infof("Connecting to search servers, %s (index: %s)", c.Conf.ElasticsearchServers, index)
    servers := strings.Split(c.Conf.ElasticsearchServers, ",")

	client, err := elastic.NewClient(
		elastic.SetURL(servers...),
		elastic.SetSniff(c.Conf.ElasticsearchSniffing),
	)
	if err != nil {
		log.Errorf("Failed to connect to elasticsearch: %s", err)
		return err
	}

	exists, err := client.IndexExists(index).Do()
	if err != nil {
		log.Errorf("Error while checking if index exists, %s", err)
		return err
	}

	if !exists {
		_, err = client.CreateIndex(index).BodyString(mapping).Do()
		if err != nil {
			log.Errorf("Error while creating index, %s", err)
			return err
		}
	}

	// TODO Use BULK api and send more than one result per call.
	log.Infof("Sending %d scan results to elastic search.", len(scanResults))
	for idx := range scanResults {
		_ = writeResultToES(scanResults[idx], client, index)
	}

	return nil
}

func writeResultToES(scanResult models.ScanResult, client *elastic.Client, index string) (documents []*document) {

	cves := scanResult.KnownCves
	if !c.Conf.IgnoreUnscoredCves {
		cves = append(cves, scanResult.UnknownCves...)
	}

	for _, cveInfo := range cves {
		cveID := cveInfo.CveDetail.CveID

		curentPackages := []string{}
		for _, p := range cveInfo.Packages {
			curentPackages = append(curentPackages, p.ToStringCurrentVersion())
		}
		for _, cpename := range cveInfo.CpeNames {
			curentPackages = append(curentPackages, cpename.Name)
		}

		newPackages := []string{}
		for _, p := range cveInfo.Packages {
			newPackages = append(newPackages, p.ToStringNewVersion())
		}

		doc := document{
			Hostname:      scanResult.ServerName,
			ScanID:        scanResult.ScanHistoryID,
			ScanTime:      scanResult.ScannedAt,
			CVE:           cveID,
			Summary:       cveInfo.CveDetail.Nvd.CveSummary(),
			Vector:        cveInfo.CveDetail.Nvd.CvssVector(),
			Score:         cveInfo.CveDetail.Nvd.Score,
			Severity:      cveInfo.CveDetail.Nvd.CvssSeverity(),
			Link:          fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID),
			Installed:     curentPackages,
			Candidate:     newPackages,
			ServerInfo:    scanResult.ServerInfo(),
			Release:       scanResult.Release,
			Family:        scanResult.Family,
			Success:       true,
		}

		_, err := client.Index().Index(index).Type("vulscan").BodyJson(&doc).Refresh(true).Do()
		if err != nil {
			log.Errorf("Error writing document, %s", err)
		}
	}
	return
}
