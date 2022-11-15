package windows

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/future-architect/vuls/pkg/db"
	dbTypes "github.com/future-architect/vuls/pkg/db/types"
	"github.com/future-architect/vuls/pkg/types"
	"github.com/future-architect/vuls/pkg/util"
)

type Detector struct{}

func (d Detector) Name() string {
	return "windows detector"
}

func (d Detector) Detect(ctx context.Context, host *types.Host) error {
	if host.ScannedCves == nil {
		host.ScannedCves = map[string]types.VulnInfo{}
	}

	vulndb, err := db.Open("boltdb", host.Config.Detect.Path, false)
	if err != nil {
		return errors.Wrapf(err, "open %s", host.Config.Detect.Path)
	}
	defer vulndb.Close()

	supercedences, err := vulndb.GetSupercedence(host.Packages.KB)
	if err != nil {
		return errors.Wrap(err, "get supercedence")
	}

	var unapplied []string
	for _, kbs := range supercedences {
		var applied bool
		for _, kb := range kbs {
			if slices.Contains(host.Packages.KB, kb) {
				applied = true
				break
			}
		}
		if !applied {
			unapplied = append(unapplied, kbs...)
		}
	}
	unapplied = util.Unique(unapplied)

	products, err := vulndb.GetKBtoProduct(host.Release, append(host.Packages.KB, unapplied...))
	if err != nil {
		return errors.Wrap(err, "get product from kb")
	}
	if !slices.Contains(products, host.Release) {
		products = append(products, host.Release)
	}

	for _, product := range util.Unique(products) {
		pkgs, err := vulndb.GetPackage(host.Family, host.Release, product)
		if err != nil {
			return errors.Wrap(err, "get package")
		}

		for cveid, datasrcs := range pkgs {
			for datasrc, ps := range datasrcs {
				for id, p := range ps {
					switch p.Status {
					case "fixed":
						for _, v := range p.Version {
							if slices.Contains(unapplied, v[0].Version) {
								vinfo, ok := host.ScannedCves[cveid]
								if !ok {
									host.ScannedCves[cveid] = types.VulnInfo{ID: cveid}
								}
								vinfo.AffectedPackages = append(vinfo.AffectedPackages, types.AffectedPackage{
									Name:   fmt.Sprintf("%s: KB%s", product, v[0].Version),
									Source: fmt.Sprintf("%s:%s", datasrc, id),
									Status: p.Status,
								})
								vinfo.AffectedPackages = util.Unique(vinfo.AffectedPackages)
								host.ScannedCves[cveid] = vinfo
							}
						}
					case "unfixed":
						vinfo, ok := host.ScannedCves[cveid]
						if !ok {
							host.ScannedCves[cveid] = types.VulnInfo{ID: cveid}
						}
						vinfo.AffectedPackages = append(vinfo.AffectedPackages, types.AffectedPackage{
							Name:   product,
							Source: fmt.Sprintf("%s:%s", datasrc, id),
							Status: p.Status,
						})
						vinfo.AffectedPackages = util.Unique(vinfo.AffectedPackages)
						host.ScannedCves[cveid] = vinfo
					}
				}
			}
		}
	}

	vulns, err := vulndb.GetVulnerability(maps.Keys(host.ScannedCves))
	if err != nil {
		return errors.Wrap(err, "get vulnerability")
	}
	for cveid, datasrcs := range vulns {
		vinfo := host.ScannedCves[cveid]
		vinfo.Content = map[string]dbTypes.Vulnerability{}
		for src, v := range datasrcs {
			vinfo.Content[src] = v
		}
		host.ScannedCves[cveid] = vinfo
	}

	return nil
}
