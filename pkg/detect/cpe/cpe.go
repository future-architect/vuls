package cpe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/future-architect/vuls/pkg/db"
	dbTypes "github.com/future-architect/vuls/pkg/db/types"
	"github.com/future-architect/vuls/pkg/types"
	"github.com/future-architect/vuls/pkg/util"
)

type Detector struct{}

func (d Detector) Name() string {
	return "cpe detector"
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

	for key, cpe := range host.Packages.CPE {
		installed, err := naming.UnbindFS(cpe.CPE)
		if err != nil {
			return errors.Wrapf(err, "unbind %s", cpe.CPE)
		}
		var runningOn common.WellFormedName
		if cpe.RunningOn != "" {
			runningOn, err = naming.UnbindFS(cpe.RunningOn)
			if err != nil {
				return errors.Wrapf(err, "unbind %s", cpe.RunningOn)
			}
		}

		cpes, err := vulndb.GetCPEConfiguration(fmt.Sprintf("%s:%s:%s", installed.GetString(common.AttributePart), installed.GetString(common.AttributeVendor), installed.GetString(common.AttributeProduct)))
		if err != nil {
			return errors.Wrap(err, "get cpe configuration")
		}

		for cveid, datasrcs := range cpes {
			for datasrc, orcs := range datasrcs {
				for id, andcs := range orcs {
					for _, c := range andcs {
						affected, err := compare(installed, &runningOn, c)
						if err != nil {
							return errors.Wrap(err, "compare")
						}
						if affected {
							vinfo, ok := host.ScannedCves[cveid]
							if !ok {
								host.ScannedCves[cveid] = types.VulnInfo{ID: cveid}
							}
							vinfo.AffectedPackages = append(vinfo.AffectedPackages, types.AffectedPackage{
								Name:   key,
								Source: fmt.Sprintf("%s:%s", datasrc, id),
							})
							vinfo.AffectedPackages = util.Unique(vinfo.AffectedPackages)
							host.ScannedCves[cveid] = vinfo
							break
						}
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

func compare(installedCPE common.WellFormedName, installedRunningOn *common.WellFormedName, target dbTypes.CPEConfiguration) (bool, error) {
	var (
		wfn common.WellFormedName
		err error
	)

	if target.Vulnerable.CPEVersion == "2.3" {
		wfn, err = naming.UnbindFS(target.Vulnerable.CPE)
	} else {
		wfn, err = naming.UnbindURI(target.Vulnerable.CPE)
	}
	if err != nil {
		return false, errors.Wrapf(err, "unbind %s", target.Vulnerable.CPE)
	}
	if !matching.IsEqual(installedCPE, wfn) && !matching.IsSubset(installedCPE, wfn) {
		return false, nil
	}

	for _, runningOn := range target.RunningOn {
		if runningOn.CPEVersion == "2.3" {
			wfn, err = naming.UnbindFS(runningOn.CPE)
		} else {
			wfn, err = naming.UnbindURI(runningOn.CPE)
		}
		if err != nil {
			return false, errors.Wrapf(err, "unbind %s", runningOn.CPE)
		}
		if !matching.IsEqual(*installedRunningOn, wfn) && !matching.IsSubset(*installedRunningOn, wfn) {
			return false, nil
		}
	}

	if len(target.Vulnerable.Version) == 0 {
		return true, nil
	}

	attrver := installedCPE.GetString(common.AttributeVersion)
	switch attrver {
	case "ANY":
		return true, nil
	case "NA":
		return false, nil
	default:
		v, err := version.NewVersion(strings.ReplaceAll(attrver, "\\", ""))
		if err != nil {
			return false, errors.Wrapf(err, "parse version in %s", installedCPE.GetString(common.AttributeVersion))
		}
		for _, vconf := range target.Vulnerable.Version {
			vconfv, err := version.NewVersion(vconf.Version)
			if err != nil {
				return false, errors.Wrapf(err, "parse version in %s", vconf.Version)
			}

			switch vconf.Operator {
			case "eq":
				if !v.Equal(vconfv) {
					return false, nil
				}
			case "lt":
				if !v.LessThan(vconfv) {
					return false, nil
				}
			case "le":
				if !v.LessThanOrEqual(vconfv) {
					return false, nil
				}
			case "gt":
				if !v.GreaterThan(vconfv) {
					return false, nil
				}
			case "ge":
				if !v.GreaterThanOrEqual(vconfv) {
					return false, nil
				}
			default:
				return false, errors.New("not supported operator")
			}
		}
		return true, nil
	}
}
