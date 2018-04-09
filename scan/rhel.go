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

func (o *rhel) depsFast() []string {
	if config.Conf.Offline {
		return []string{}
	}
	// repoquery
	return []string{"yum-utils"}
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

func (o *rhel) depsFastRoot() []string {
	if config.Conf.Offline {
		// `needs-restarting` for online and offline
		return []string{"yum-utils"}
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
	cmds := []cmd{{"needs-restarting", exitStatusZero}}
	if config.Conf.Offline {
		return cmds
	}

	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 6 {
		return []cmd{
			{"yum --color=never repolist", exitStatusZero},
			{"yum --color=never list-security --security", exitStatusZero},
			{"yum --color=never info-security", exitStatusZero},
			{"repoquery -h", exitStatusZero},
		}
	}
	return append(cmds,
		cmd{"yum --color=never repolist", exitStatusZero},
		cmd{"yum --color=never --security updateinfo list updates", exitStatusZero},
		cmd{"yum --color=never --security updateinfo updates", exitStatusZero},
		cmd{"repoquery -h", exitStatusZero})
}

func (o *rhel) nosudoCmdsDeep() []cmd {
	return append(o.nosudoCmdsFastRoot(),
		cmd{"yum --color=never repolist", exitStatusZero},
		cmd{"yum changelog all updates", exitStatusZero})
}

type rootPrivRHEL struct{}

// TODO
func (o rootPrivRHEL) repoquery() bool {
	return true
}

func (o rootPrivRHEL) yumRepolist() bool {
	return false
}

func (o rootPrivRHEL) yumUpdateInfo() bool {
	return false
}

// TODO
func (o rootPrivRHEL) yumChangelog() bool {
	return false
}
