package scanner

import (
	"bufio"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type alpine struct {
	base
}

// NewAlpine is constructor
func newAlpine(c config.ServerInfo) *alpine {
	d := &alpine{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

// Alpine
// https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/alpine.rb
func detectAlpine(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/alpine-release", noSudo); !r.isSuccess() {
		return false, nil
	}
	if r := exec(c, "cat /etc/alpine-release", noSudo); r.isSuccess() {
		os := newAlpine(c)
		os.setDistro(constant.Alpine, strings.TrimSpace(r.Stdout))
		return true, os
	}
	return false, nil
}

func (o *alpine) checkScanMode() error {
	return nil
}

func (o *alpine) checkDeps() error {
	o.log.Infof("Dependencies... No need")
	return nil
}

func (o *alpine) checkIfSudoNoPasswd() error {
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *alpine) apkUpdate() error {
	if o.getServerInfo().Mode.IsOffline() {
		return nil
	}
	r := o.exec("apk update", noSudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %s", r)
	}
	return nil
}

func (o *alpine) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *alpine) postScan() error {
	return nil
}

func (o *alpine) detectIPAddr() (err error) {
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *alpine) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	if err := o.apkUpdate(); err != nil {
		return err
	}
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		err = xerrors.Errorf("Failed to scan updatable packages: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	} else {
		installed.MergeNewVersion(updatable)
	}

	o.Packages = installed
	return nil
}

func (o *alpine) scanInstalledPackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("apk info -v")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.parseApkInfo(r.Stdout)
}

func (o *alpine) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	installedPackages, err := o.parseApkInfo(stdout)
	return installedPackages, nil, err
}

func (o *alpine) parseApkInfo(stdout string) (models.Packages, error) {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		ss := strings.Split(line, "-")
		if len(ss) < 3 {
			if strings.Contains(ss[0], "WARNING") {
				continue
			}
			return nil, xerrors.Errorf("Failed to parse apk info -v: %s", line)
		}
		name := strings.Join(ss[:len(ss)-2], "-")
		packs[name] = models.Package{
			Name:    name,
			Version: strings.Join(ss[len(ss)-2:], "-"),
		}
	}
	return packs, nil
}

func (o *alpine) scanUpdatablePackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("apk version")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.parseApkVersion(r.Stdout)
}

func (o *alpine) parseApkVersion(stdout string) (models.Packages, error) {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "<") {
			continue
		}
		ss := strings.Split(line, "<")
		namever := strings.TrimSpace(ss[0])
		tt := strings.Split(namever, "-")
		name := strings.Join(tt[:len(tt)-2], "-")
		packs[name] = models.Package{
			Name:       name,
			NewVersion: strings.TrimSpace(ss[1]),
		}
	}
	return packs, nil
}
