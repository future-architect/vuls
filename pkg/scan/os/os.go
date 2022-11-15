package os

import (
	"bufio"
	"context"
	"strings"

	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/scan/ospkg/apk"
	"github.com/future-architect/vuls/pkg/scan/ospkg/dpkg"
	"github.com/future-architect/vuls/pkg/scan/ospkg/rpm"
	"github.com/future-architect/vuls/pkg/scan/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "os analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *types.AnalyzerHost) error {
	status, stdout, stderr, err := ah.Host.Exec(ctx, "cat /etc/os-release", false)
	if err != nil {
		return errors.Wrap(err, `exec "cat /etc/os-release"`)
	}
	if stderr != "" {
		return errors.New(stderr)
	}
	if status != 0 {
		return errors.Errorf("exit status is %d", status)
	}

	ah.Host.Family, ah.Host.Release, err = ParseOSRelease(stdout)
	if err != nil {
		return errors.Wrap(err, "parse /etc/os-release")
	}

	switch ah.Host.Family {
	case "debian", "ubuntu":
		ah.Analyzers = append(ah.Analyzers, dpkg.Analyzer{})
	case "redhat", "centos", "alma", "rocky", "fedora", "opensuse", "opensuse.tumbleweed", "opensuse.leap", "suse.linux.enterprise.server", "suse.linux.enterprise.desktop":
		ah.Analyzers = append(ah.Analyzers, rpm.Analyzer{})
	case "alpine":
		ah.Analyzers = append(ah.Analyzers, apk.Analyzer{})
	case "":
		return errors.New("family is unknown")
	default:
		return errors.New("not supported OS")
	}

	return nil
}

func ParseOSRelease(stdout string) (string, string, error) {
	var family, versionID string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		ss := strings.SplitN(line, "=", 2)
		if len(ss) != 2 {
			continue
		}
		key, value := strings.TrimSpace(ss[0]), strings.TrimSpace(ss[1])

		switch key {
		case "ID":
			switch id := strings.Trim(value, `"'`); id {
			case "almalinux":
				family = "alma"
			case "opensuse-leap", "opensuse-tumbleweed":
				family = strings.ReplaceAll(id, "-", ".")
			case "sles":
				family = "suse.linux.enterprise.server"
			case "sled":
				family = "suse.linux.enterprise.desktop"
			default:
				family = strings.ToLower(id)
			}
		case "VERSION_ID":
			versionID = strings.Trim(value, `"'`)
		default:
			continue
		}
	}

	if family == "" {
		return "", "", errors.New("family is unknown")
	}
	return family, versionID, nil
}
