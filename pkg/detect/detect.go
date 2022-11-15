package detect

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/cmd/version"
	"github.com/future-architect/vuls/pkg/detect/cpe"
	"github.com/future-architect/vuls/pkg/detect/debian"
	detectTypes "github.com/future-architect/vuls/pkg/detect/types"
	"github.com/future-architect/vuls/pkg/detect/ubuntu"
	"github.com/future-architect/vuls/pkg/detect/windows"
	"github.com/future-architect/vuls/pkg/types"
)

func Detect(ctx context.Context, host *types.Host) error {
	if host.ScanError != "" {
		return nil
	}

	var detectors []detectTypes.Detector
	if len(host.Packages.OSPkg) > 0 {
		switch host.Family {
		case "debian":
			detectors = append(detectors, debian.Detector{})
		case "ubuntu":
			detectors = append(detectors, ubuntu.Detector{})
		default:
			return errors.New("not implemented")
		}
	}
	if len(host.Packages.KB) > 0 {
		detectors = append(detectors, windows.Detector{})
	}
	if len(host.Packages.CPE) > 0 {
		detectors = append(detectors, cpe.Detector{})
	}

	var err error
	for {
		if len(detectors) == 0 {
			break
		}
		d := detectors[0]
		if err = d.Detect(ctx, host); err != nil {
			break
		}
		detectors = detectors[1:]
	}

	t := time.Now()
	host.DetecteddAt = &t
	host.DetectedVersion = version.Version
	host.DetectedRevision = version.Revision

	if err != nil {
		return errors.Wrapf(err, "detect %s", host.Name)
	}

	return nil
}
