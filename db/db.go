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

package db

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/future-architect/vuls/config"
	m "github.com/future-architect/vuls/models"
	"github.com/jinzhu/gorm"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
)

var db *gorm.DB

// OpenDB opens Database
func OpenDB() (err error) {
	db, err = gorm.Open("sqlite3", config.Conf.DBPath)
	if err != nil {
		err = fmt.Errorf("Failed to open DB. datafile: %s, err: %s", config.Conf.DBPath, err)
		return

	}
	db.LogMode(config.Conf.DebugSQL)
	return
}

// MigrateDB migrates Database
func MigrateDB() error {
	if err := db.AutoMigrate(
		&m.ScanHistory{},
		&m.ScanResult{},
		//  &m.NWLink{},
		&m.Container{},
		&m.CveInfo{},
		&m.CpeName{},
		&m.PackageInfo{},
		&m.DistroAdvisory{},
		&cve.CveDetail{},
		&cve.Jvn{},
		&cve.Nvd{},
		&cve.Reference{},
		&cve.Cpe{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	errMsg := "Failed to create index. err: %s"
	//  if err := db.Model(&m.NWLink{}).
	//      AddIndex("idx_n_w_links_scan_result_id", "scan_result_id").Error; err != nil {
	//      return fmt.Errorf(errMsg, err)
	//  }
	if err := db.Model(&m.Container{}).
		AddIndex("idx_containers_scan_result_id", "scan_result_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&m.CveInfo{}).
		AddIndex("idx_cve_infos_scan_result_id", "scan_result_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&m.CpeName{}).
		AddIndex("idx_cpe_names_cve_info_id", "cve_info_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&m.PackageInfo{}).
		AddIndex("idx_package_infos_cve_info_id", "cve_info_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&m.DistroAdvisory{}).
		//TODO check table name
		AddIndex("idx_distro_advisories_cve_info_id", "cve_info_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.CveDetail{}).
		AddIndex("idx_cve_details_cve_info_id", "cve_info_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.CveDetail{}).
		AddIndex("idx_cve_details_cveid", "cve_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Nvd{}).
		AddIndex("idx_nvds_cve_detail_id", "cve_detail_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Jvn{}).
		AddIndex("idx_jvns_cve_detail_id", "cve_detail_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Cpe{}).
		AddIndex("idx_cpes_jvn_id", "jvn_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Reference{}).
		AddIndex("idx_references_jvn_id", "jvn_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Cpe{}).
		AddIndex("idx_cpes_nvd_id", "nvd_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	if err := db.Model(&cve.Reference{}).
		AddIndex("idx_references_nvd_id", "nvd_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}

	return nil
}

// Insert inserts scan results into DB
func Insert(results []m.ScanResult) error {
	for _, r := range results {
		r.KnownCves = resetGormIDs(r.KnownCves)
		r.UnknownCves = resetGormIDs(r.UnknownCves)
	}

	history := m.ScanHistory{
		ScanResults: results,
		ScannedAt:   time.Now(),
	}

	db = db.Set("gorm:save_associations", false)
	if err := db.Create(&history).Error; err != nil {
		return err
	}
	for _, scanResult := range history.ScanResults {
		scanResult.ScanHistoryID = history.ID
		if err := db.Create(&scanResult).Error; err != nil {
			return err
		}
		scanResult.Container.ScanResultID = scanResult.ID
		if err := db.Create(&scanResult.Container).Error; err != nil {
			return err
		}
		if err := insertCveInfos(scanResult.ID, scanResult.KnownCves); err != nil {
			return err
		}
		if err := insertCveInfos(scanResult.ID, scanResult.UnknownCves); err != nil {
			return err
		}
	}
	return nil
}

func insertCveInfos(scanResultID uint, infos []m.CveInfo) error {
	for _, cveInfo := range infos {
		cveInfo.ScanResultID = scanResultID
		if err := db.Create(&cveInfo).Error; err != nil {
			return err
		}

		for _, pack := range cveInfo.Packages {
			pack.CveInfoID = cveInfo.ID
			if err := db.Create(&pack).Error; err != nil {
				return err
			}
		}

		for _, distroAdvisory := range cveInfo.DistroAdvisories {
			distroAdvisory.CveInfoID = cveInfo.ID
			if err := db.Create(&distroAdvisory).Error; err != nil {
				return err
			}
		}

		for _, cpeName := range cveInfo.CpeNames {
			cpeName.CveInfoID = cveInfo.ID
			if err := db.Create(&cpeName).Error; err != nil {
				return err
			}
		}

		db = db.Set("gorm:save_associations", true)
		cveDetail := cveInfo.CveDetail
		cveDetail.CveInfoID = cveInfo.ID
		if err := db.Create(&cveDetail).Error; err != nil {
			return err
		}
		db = db.Set("gorm:save_associations", false)
	}
	return nil
}

func resetGormIDs(infos []m.CveInfo) []m.CveInfo {
	for i := range infos {
		infos[i].CveDetail.ID = 0
		// NVD
		infos[i].CveDetail.Nvd.ID = 0
		for j := range infos[i].CveDetail.Nvd.Cpes {
			infos[i].CveDetail.Nvd.Cpes[j].ID = 0
		}
		for j := range infos[i].CveDetail.Nvd.References {
			infos[i].CveDetail.Nvd.References[j].ID = 0
		}

		// JVN
		infos[i].CveDetail.Jvn.ID = 0
		for j := range infos[i].CveDetail.Jvn.Cpes {
			infos[i].CveDetail.Jvn.Cpes[j].ID = 0
		}
		for j := range infos[i].CveDetail.Jvn.References {
			infos[i].CveDetail.Jvn.References[j].ID = 0
		}

		//Packages
		for j := range infos[i].Packages {
			infos[i].Packages[j].ID = 0
			infos[i].Packages[j].CveInfoID = 0
		}
	}
	return infos
}

// SelectScanHistory select scan history from DB
func SelectScanHistory(historyID string) (m.ScanHistory, error) {
	var err error

	scanHistory := m.ScanHistory{}
	if historyID == "" {
		// select latest
		db.Order("scanned_at desc").First(&scanHistory)
	} else {
		var id int
		if id, err = strconv.Atoi(historyID); err != nil {
			return m.ScanHistory{},
				fmt.Errorf("historyID have to be numeric number: %s", err)
		}
		db.First(&scanHistory, id)
	}

	if scanHistory.ID == 0 {
		return m.ScanHistory{}, fmt.Errorf("No scanHistory records")
	}

	//  results := []m.ScanResult{}
	results := m.ScanResults{}
	db.Model(&scanHistory).Related(&results, "ScanResults")
	scanHistory.ScanResults = results

	for i, r := range results {
		//  nw := []m.NWLink{}
		//  db.Model(&r).Related(&nw, "NWLinks")
		//  scanHistory.ScanResults[i].NWLinks = nw

		di := m.Container{}
		db.Model(&r).Related(&di, "Container")
		scanHistory.ScanResults[i].Container = di

		knownCves := selectCveInfos(&r, "KnownCves")
		sort.Sort(m.CveInfos(knownCves))
		scanHistory.ScanResults[i].KnownCves = knownCves
	}

	sort.Sort(scanHistory.ScanResults)
	return scanHistory, nil
}

func selectCveInfos(result *m.ScanResult, fieldName string) []m.CveInfo {
	cveInfos := []m.CveInfo{}
	db.Model(&result).Related(&cveInfos, fieldName)

	for i, cveInfo := range cveInfos {
		cveDetail := cve.CveDetail{}
		db.Model(&cveInfo).Related(&cveDetail, "CveDetail")
		id := cveDetail.CveID
		filledCveDetail := cvedb.Get(id, db)
		cveInfos[i].CveDetail = filledCveDetail

		packs := []m.PackageInfo{}
		db.Model(&cveInfo).Related(&packs, "Packages")
		cveInfos[i].Packages = packs

		advisories := []m.DistroAdvisory{}
		db.Model(&cveInfo).Related(&advisories, "DistroAdvisories")
		cveInfos[i].DistroAdvisories = advisories

		names := []m.CpeName{}
		db.Model(&cveInfo).Related(&names, "CpeNames")
		cveInfos[i].CpeNames = names
	}
	return cveInfos
}

// SelectScanHistories select latest scan history from DB
func SelectScanHistories() ([]m.ScanHistory, error) {
	scanHistories := []m.ScanHistory{}
	db.Order("scanned_at desc").Find(&scanHistories)

	if len(scanHistories) == 0 {
		return []m.ScanHistory{}, fmt.Errorf("No scanHistory records")
	}

	for i, history := range scanHistories {
		results := m.ScanResults{}
		db.Model(&history).Related(&results, "ScanResults")
		scanHistories[i].ScanResults = results

		for j, r := range results {
			di := m.Container{}
			db.Model(&r).Related(&di, "Container")
			scanHistories[i].ScanResults[j].Container = di
		}
	}
	return scanHistories, nil
}
