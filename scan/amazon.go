package scan

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type amazon struct {
	redhatBase
}

// NewAmazon is constructor
func newAmazon(c config.ServerInfo) *amazon {
	r := &amazon{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivAmazon{},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

func (o *amazon) checkDeps() error {
	if config.Conf.Fast {
		return o.execCheckDeps(o.depsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckDeps(o.depsFastRoot())
	} else if config.Conf.Deep {
		return o.execCheckDeps(o.depsDeep())
	}
	return fmt.Errorf("Unknown scan mode")
}

func (o *amazon) depsFast() []string {
	if config.Conf.Offline {
		return []string{}
	}
	// repoquery
	return []string{"yum-utils"}
}

func (o *amazon) depsFastRoot() []string {
	return []string{
		"yum-utils",
		"yum-plugin-ps",
	}
}

func (o *amazon) depsDeep() []string {
	return []string{
		"yum-utils",
		"yum-plugin-ps",
		"yum-plugin-changelog",
	}
}

func (o *amazon) checkIfSudoNoPasswd() error {
	if config.Conf.Fast {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFast())
	} else if config.Conf.FastRoot {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsDeep())
	}
}

func (o *amazon) nosudoCmdsFast() []cmd {
	return []cmd{}
}

func (o *amazon) nosudoCmdsFastRoot() []cmd {
	return []cmd{
		{"repoquery -h", exitStatusZero},
		{"yum updateinfo list updates --security --color=never", exitStatusZero},
		{"yum updateinfo updates --security --color=never", exitStatusZero},
		{"yum -q ps all --color=never", exitStatusZero},
		{"stat /proc/1/exe", exitStatusZero},
		{"needs-restarting", exitStatusZero},
		{"which which", exitStatusZero},
	}
}

func (o *amazon) nosudoCmdsDeep() []cmd {
	return o.nosudoCmdsFastRoot()
}

type rootPrivAmazon struct{}

func (o rootPrivAmazon) repoquery() bool {
	return false
}

func (o rootPrivAmazon) yumRepolist() bool {
	return false
}

func (o rootPrivAmazon) yumUpdateInfo() bool {
	return false
}

func (o rootPrivAmazon) yumChangelog() bool {
	return false
}
