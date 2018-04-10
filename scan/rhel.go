package scan

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type rhel struct {
	redhatBase
}

// NewRHEL is constructor
func newRHEL(c config.ServerInfo) *rhel {
	r := &rhel{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivRHEL{},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

func (o *rhel) checkDeps() error {
	if config.Conf.Fast {
		return o.execCheckDeps(o.depsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckDeps(o.depsFastRoot())
	} else if config.Conf.Deep {
		return o.execCheckDeps(o.depsDeep())
	}
	return fmt.Errorf("Unknown scan mode")
}

func (o *rhel) depsFast() []string {
	return []string{}
}

func (o *rhel) depsFastRoot() []string {
	if config.Conf.Offline {
		return []string{}
	}

	majorVersion, _ := o.Distro.MajorVersion()
	switch majorVersion {
	case 5:
		return []string{
			"yum-utils",
			"yum-security",
		}
	case 6:
		return []string{
			"yum-utils",
			"yum-plugin-security",
		}
	default:
		return []string{
			"yum-utils",
		}
	}
}

func (o *rhel) depsDeep() []string {
	majorVersion, _ := o.Distro.MajorVersion()
	switch majorVersion {
	case 5:
		return []string{
			"yum-utils",
			"yum-security",
			"yum-changelog",
		}
	case 6:
		return []string{
			"yum-utils",
			"yum-plugin-security",
			"yum-plugin-changelog",
		}
	default:
		return []string{
			"yum-utils",
			"yum-plugin-changelog",
		}
	}
}

func (o *rhel) checkIfSudoNoPasswd() error {
	if config.Conf.Fast {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsDeep())
	}
}

func (o *rhel) nosudoCmdsFast() []cmd {
	return []cmd{}
}

func (o *rhel) nosudoCmdsFastRoot() []cmd {
	if config.Conf.Offline {
		return []cmd{}
	}

	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 6 {
		return []cmd{
			// {"needs-restarting", exitStatusZero},
			{"yum repolist --color=never", exitStatusZero},
			{"yum list-security --security --color=never", exitStatusZero},
			{"yum info-security --color=never", exitStatusZero},
			{"repoquery -h", exitStatusZero},
		}
	}
	return []cmd{
		{"yum repolist --color=never", exitStatusZero},
		{"yum updateinfo list updates --security --color=never", exitStatusZero},
		{"yum updateinfo updates --security --color=never ", exitStatusZero},
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *rhel) nosudoCmdsDeep() []cmd {
	return append(o.nosudoCmdsFastRoot(),
		cmd{"yum changelog all updates --color=never", exitStatusZero})
}

type rootPrivRHEL struct{}

func (o rootPrivRHEL) repoquery() bool {
	return true
}

func (o rootPrivRHEL) yumRepolist() bool {
	return true
}

func (o rootPrivRHEL) yumUpdateInfo() bool {
	return true
}

func (o rootPrivRHEL) yumChangelog() bool {
	return true
}
