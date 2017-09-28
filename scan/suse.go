package scan

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type suse struct {
	redhat
}

// NewRedhat is constructor
func newSUSE(c config.ServerInfo) *suse {
	r := &suse{
		redhat: redhat{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

// https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/suse.rb
func detectSUSE(c config.ServerInfo) (itsMe bool, suse osTypeInterface) {
	suse = newSUSE(c)

	if r := exec(c, "ls /etc/os-release", noSudo); r.isSuccess() {
		if r := exec(c, "zypper -V", noSudo); r.isSuccess() {
			if r := exec(c, "cat /etc/os-release", noSudo); r.isSuccess() {
				name := ""
				if strings.Contains(r.Stdout, "ID=opensuse") {
					//TODO check opensuse or opensuse.leap
					name = config.OpenSUSE
				} else if strings.Contains(r.Stdout, `NAME="SLES"`) {
					name = config.SUSEEnterpriseServer
				} else {
					util.Log.Warn("Failed to parse SUSE edition: %s", r)
					return true, suse
				}

				re := regexp.MustCompile(`VERSION_ID=\"(\d+\.\d+|\d+)\"`)
				result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
				if len(result) != 2 {
					util.Log.Warn("Failed to parse SUSE Linux version: %s", r)
					return true, suse
				}
				suse.setDistro(name, result[1])
				return true, suse
			}
		}
	} else if r := exec(c, "ls /etc/SuSE-release", noSudo); r.isSuccess() {
		if r := exec(c, "zypper -V", noSudo); r.isSuccess() {
			if r := exec(c, "cat /etc/SuSE-release", noSudo); r.isSuccess() {
				re := regexp.MustCompile(`openSUSE (\d+\.\d+|\d+)`)
				result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
				if len(result) == 2 {
					//TODO check opensuse or opensuse.leap
					suse.setDistro(config.OpenSUSE, result[1])
					return true, suse
				}

				re = regexp.MustCompile(`VERSION = (\d+)`)
				result = re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
				if len(result) == 2 {
					version := result[1]
					re = regexp.MustCompile(`PATCHLEVEL = (\d+)`)
					result = re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
					if len(result) == 2 {
						suse.setDistro(config.SUSEEnterpriseServer,
							fmt.Sprintf("%s.%s", version, result[1]))
						return true, suse
					}
				}
				util.Log.Warn("Failed to parse SUSE Linux version: %s", r)
				return true, suse
			}
		}
	}
	util.Log.Debugf("Not SUSE Linux. servername: %s", c.ServerName)
	return false, suse
}

func (o *suse) checkDependencies() error {
	o.log.Infof("Dependencies... No need")
	return nil
}

func (o *suse) checkIfSudoNoPasswd() error {
	// SUSE doesn't need root privilege
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *suse) scanPackages() error {
	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	rebootRequired, err := o.rebootRequired()
	if err != nil {
		o.log.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel.RebootRequired = rebootRequired

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		o.log.Errorf("Failed to scan updatable packages: %s", err)
		return err
	}
	installed.MergeNewVersion(updatable)
	o.Packages = installed

	return nil
}

func (o *suse) rebootRequired() (bool, error) {
	r := o.exec("rpm -q --last kernel-default | head -n1", noSudo)
	if !r.isSuccess() {
		return false, fmt.Errorf("Failed to detect the last installed kernel : %v", r)
	}
	stdout := strings.Fields(r.Stdout)[0]
	return !strings.Contains(stdout, strings.TrimSuffix(o.Kernel.Release, "-default")), nil
}

func (o *suse) scanUpdatablePackages() (models.Packages, error) {
	cmd := ""
	if v, _ := o.Distro.MajorVersion(); v < 12 {
		cmd = "zypper -q lu"
	} else {
		cmd = "zypper --no-color -q lu"
	}
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to scan updatable packages: %v", r)
	}
	return o.parseZypperLULines(r.Stdout)
}

func (o *suse) parseZypperLULines(stdout string) (models.Packages, error) {
	updatables := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "S | Repository") ||
			strings.HasPrefix(line, "--+----------------") {
			continue
		}
		pack, err := o.parseZypperLUOneLine(line)
		if err != nil {
			return nil, err
		}
		updatables[pack.Name] = *pack
	}
	return updatables, nil
}

func (o *suse) parseZypperLUOneLine(line string) (*models.Package, error) {
	fs := strings.Fields(line)
	if len(fs) != 11 {
		return nil, fmt.Errorf("zypper -q lu Unknown format: %s", line)
	}
	available := strings.Split(fs[8], "-")
	return &models.Package{
		Name:       fs[4],
		NewVersion: available[0],
		NewRelease: available[1],
		Arch:       fs[10],
	}, nil
}
