package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type oracle struct {
	redhatBase
}

// NewAmazon is constructor
func newOracle(c config.ServerInfo) *oracle {
	r := &oracle{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivOracle{},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

func (o *oracle) checkDeps() error {
	if config.Conf.Fast {
		return o.execCheckDeps(o.depsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckDeps(o.depsFastRoot())
	} else {
		return o.execCheckDeps(o.depsDeep())
	}
}

func (o *oracle) depsFast() []string {
	if config.Conf.Offline {
		return []string{}
	}
	// repoquery
	return []string{"yum-utils"}
}

func (o *oracle) depsFastRoot() []string {
	if config.Conf.Offline {
		//TODO
		// return []string{"yum-plugin-ps"}
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
			//TODO
			// return []string{"yum-plugin-ps"}
		}
	default:
		return []string{
			"yum-utils",
			//TODO
			// return []string{"yum-plugin-ps"}
		}
	}
}

func (o *oracle) depsDeep() []string {
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
			//TODO
			// return []string{"yum-plugin-ps"}
		}
	default:
		return []string{
			"yum-utils",
			"yum-plugin-changelog",
			//TODO
			// return []string{"yum-plugin-ps"}
		}
	}
}

func (o *oracle) checkIfSudoNoPasswd() error {
	if config.Conf.Fast {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsDeep())
	}
}

func (o *oracle) nosudoCmdsFast() []cmd {
	return []cmd{}
}

func (o *oracle) nosudoCmdsFastRoot() []cmd {
	cmds := []cmd{{"needs-restarting", exitStatusZero}}
	if config.Conf.Offline {
		return cmds
	}

	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 6 {
		return []cmd{
			{"yum repolist --color=never", exitStatusZero},
			{"yum list-security --security --color=never", exitStatusZero},
			{"yum info-security --color=never", exitStatusZero},
			{"repoquery -h", exitStatusZero},
		}
	}
	return append(cmds,
		cmd{"yum repolist --color=never", exitStatusZero},
		cmd{"yum updateinfo list updates --security --color=never", exitStatusZero},
		cmd{"yum updateinfo updates --security --color=never", exitStatusZero},
		cmd{"repoquery -h", exitStatusZero})
}

func (o *oracle) nosudoCmdsDeep() []cmd {
	return o.nosudoCmdsFastRoot()
}

type rootPrivOracle struct{}

func (o rootPrivOracle) repoquery() bool {
	return true
}

func (o rootPrivOracle) yumRepolist() bool {
	return true
}

func (o rootPrivOracle) yumUpdateInfo() bool {
	return true
}

// root privilege isn't needed
func (o rootPrivOracle) yumChangelog() bool {
	return false
}
