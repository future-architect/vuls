package dpkg

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
	return "dpkg analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *scanTypes.AnalyzerHost) error {
	status, stdout, stderr, err := ah.Host.Exec(ctx, `dpkg-query -W -f="\${binary:Package},\${db:Status-Abbrev},\${Version},\${Architecture},\${source:Package},\${source:Version}\n"`, false)
	if err != nil {
		return errors.Wrap(err, `exec "dpkg-query -W -f="\${binary:Package},\${db:Status-Abbrev},\${Version},\${Architecture},\${source:Package},\${source:Version}\n"`)
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
			name, status, version, arch, srcName, srcVersion, err := parseDPKGQueryLine(trimmed)
			if err != nil {
				return nil, errors.Wrap(err, "parse dpkq query line")
			}

			packageStatus := status[1]
			// Package status:
			//     n = Not-installed
			//     c = Config-files
			//     H = Half-installed
			//     U = Unpacked
			//     F = Half-configured
			//     W = Triggers-awaiting
			//     t = Triggers-pending
			//     i = Installed
			if packageStatus != 'i' {
				continue
			}
			pkgs[name] = types.Package{
				Name:       name,
				Version:    version,
				Arch:       arch,
				SrcName:    srcName,
				SrcVersion: srcVersion,
			}
		}
	}

	return pkgs, nil
}

func parseDPKGQueryLine(line string) (string, string, string, string, string, string, error) {
	ss := strings.Split(line, ",")
	if len(ss) == 6 {
		// remove :amd64, i386...
		name, _, _ := strings.Cut(ss[0], ":")
		status := strings.TrimSpace(ss[1])
		if len(status) < 2 {
			return "", "", "", "", "", "", errors.Errorf(`unexpected db:Status-Abbrev format. accepts: "ii", received: "%s"`, status)
		}
		version := ss[2]
		arch := ss[3]
		srcName, _, _ := strings.Cut(ss[4], " ")
		srcVersion := ss[5]
		return name, status, version, arch, srcName, srcVersion, nil
	}
	return "", "", "", "", "", "", errors.Errorf(`unexpected package line format. accepts: "<bin name>,<status>,<bin version>,<arch>,<src name>,<src version>", received: "%s"`, line)
}
