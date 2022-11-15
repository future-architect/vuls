package rpm

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"

	scanTypes "github.com/future-architect/vuls/pkg/scan/types"
	"github.com/future-architect/vuls/pkg/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "rpm analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *scanTypes.AnalyzerHost) error {
	status, stdout, stderr, err := ah.Host.Exec(ctx, `rpm --version`, false)
	if err != nil {
		return errors.Wrap(err, `exec "rpm --version"`)
	}
	if stderr != "" {
		return errors.New(stderr)
	}
	if status != 0 {
		return errors.Errorf("exit status is %d", status)
	}

	cmd := `rpm -qa --queryformat "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH} %{VENDOR}\n"`
	rpmver, err := version.NewVersion(strings.TrimPrefix(strings.TrimSpace(stdout), "RPM version "))
	rpmModukaritylabel, err := version.NewVersion("4.15.0")
	if err != nil {
		return errors.Wrap(err, "parse rpm version for modularitylabel")
	}
	rpmEpochNum, err := version.NewVersion("4.8.0")
	if err != nil {
		return errors.Wrap(err, "parse rpm version for epochnum")
	}
	if rpmver.GreaterThanOrEqual(rpmModukaritylabel) {
		cmd = `rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{VENDOR} %{MODULARITYLABEL}\n"`
	} else if rpmver.GreaterThanOrEqual(rpmEpochNum) {
		cmd = `rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{VENDOR}\n"`
	}

	status, stdout, stderr, err = ah.Host.Exec(ctx, cmd, false)
	if err != nil {
		return errors.Wrapf(err, `exec "%s"`, cmd)
	}
	if stderr != "" {
		return errors.New(stderr)
	}
	if status != 0 {
		return errors.Errorf("exit status is %d", status)
	}

	ah.Host.Packages.OSPkg, err = ParseInstalledPackage(stdout)
	if err != nil {
		return errors.Wrap(err, "parse installed package")
	}

	return nil
}

func ParseInstalledPackage(stdout string) (map[string]types.Package, error) {
	pkgs := map[string]types.Package{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, release, arch, vendor, modularitylabel, err := parseRpmQaLine(trimmed)
			if err != nil {
				return nil, errors.Wrap(err, "parse rpm -qa line")
			}

			pkgs[name] = types.Package{
				Name:            name,
				Version:         version,
				Release:         release,
				Arch:            arch,
				Vendor:          vendor,
				ModularityLabel: modularitylabel,
			}
		}
	}

	return pkgs, nil
}

func parseRpmQaLine(line string) (string, string, string, string, string, string, error) {
	ss := strings.Fields(line)
	if len(ss) < 6 {
		return "", "", "", "", "", "", errors.Errorf(`unexpected rpm -qa line format. accepts: "<name> <epoch> <version> <release> <arch> <vendor>( <modularitylabel>)", received: "%s"`, line)
	}

	ver := ss[2]
	epoch := ss[1]
	if epoch != "0" && epoch != "(none)" {
		ver = fmt.Sprintf("%s:%s", epoch, ss[2])
	}

	var modularitylabel string
	if len(ss) == 7 {
		modularitylabel = ss[5]
	}

	return ss[0], ver, ss[3], ss[4], ss[5], modularitylabel, nil
}
