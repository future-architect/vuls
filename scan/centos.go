package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type centos struct {
	redhatBase
}

// NewAmazon is constructor
func newCentOS(c config.ServerInfo) *centos {
	r := &centos{
		redhatBase{
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

func (o *centos) checkDeps() error {
	if config.Conf.Fast {
		return o.execCheckDeps(o.depsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckDeps(o.depsFastRoot())
	} else {
		return o.execCheckDeps(o.depsDeep())
	}
}

func (o *centos) depsFastRoot() []string {
	if config.Conf.Offline {
		return []string{"yum-plugin-ps"}
	}
	return []string{
		"yum-utils",
		"yum-plugin-ps",
	}
}

func (o *centos) depsDeep() []string {
	return []string{
		"yum-utils",
		"yum-plugin-changelog",
		"yum-plugin-ps",
	}
}

func (o *centos) checkIfSudoNoPasswd() error {
	if config.Conf.Fast {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsDeep())
	}
}

func (o *centos) nosudoCmdsFast() []cmd {
	return []cmd{}
}

func (o *centos) nosudoCmdsFastRoot() []cmd {
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

func (o *centos) nosudoCmdsDeep() []cmd {
	return append(o.nosudoCmdsFastRoot(),
		cmd{"yum --color=never repolist", exitStatusZero},
		cmd{"yum changelog all updates", exitStatusZero})
}
