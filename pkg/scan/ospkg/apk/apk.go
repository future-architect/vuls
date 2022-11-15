package apk

import (
	"bufio"
	"context"
	"strings"

	"github.com/pkg/errors"

	scanTypes "github.com/future-architect/vuls/pkg/scan/types"
	"github.com/future-architect/vuls/pkg/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "apk analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *scanTypes.AnalyzerHost) error {
	status, stdout, stderr, err := ah.Host.Exec(ctx, "apk info -v", false)
	if err != nil {
		return errors.Wrap(err, `exec "apk info -v"`)
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
		name, version, err := parseApkInfo(scanner.Text())
		if err != nil {
			return nil, errors.Wrap(err, "parse apk info line")
		}
		if name == "" || version == "" {
			continue
		}
		pkgs[name] = types.Package{
			Name:    name,
			Version: version,
		}
	}

	return pkgs, nil
}

func parseApkInfo(line string) (string, string, error) {
	ss := strings.Split(line, "-")
	if len(ss) < 3 {
		if strings.Contains(ss[0], "WARNING") {
			return "", "", nil
		}
		return "", "", errors.Errorf(`unexpected package line format. accepts: "<package name>-<version>-<release>", received: "%s"`, line)
	}
	return strings.Join(ss[:len(ss)-2], "-"), strings.Join(ss[len(ss)-2:], "-"), nil
}
