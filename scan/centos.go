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
			sudo: rootPrivCentos{},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

func (o *centos) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	} else {
		return o.execCheckDeps(o.depsDeep())
	}
}

func (o *centos) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}
	// repoquery
	return []string{"yum-utils"}
}

func (o *centos) depsFastRoot() []string {
	return []string{
		"yum-utils",
		"yum-plugin-ps",
	}
}

func (o *centos) depsDeep() []string {
	return []string{
		"yum-utils",
		"yum-plugin-ps",
		"yum-plugin-changelog",
	}
}

func (o *centos) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.nosudoCmdsDeep())
	}
}

func (o *centos) nosudoCmdsFast() []cmd {
	return []cmd{}
}

func (o *centos) nosudoCmdsFastRoot() []cmd {
	if o.getServerInfo().Mode.IsOffline() {
		// yum ps needs internet connection
		return []cmd{
			{"stat /proc/1/exe", exitStatusZero},
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
		}
	}
	return []cmd{
		{"yum -q ps all --color=never", exitStatusZero},
		{"stat /proc/1/exe", exitStatusZero},
		{"needs-restarting", exitStatusZero},
		{"which which", exitStatusZero},
	}
}

func (o *centos) nosudoCmdsDeep() []cmd {
	return o.nosudoCmdsFastRoot()
}

type rootPrivCentos struct{}

func (o rootPrivCentos) repoquery() bool {
	return false
}

func (o rootPrivCentos) yumRepolist() bool {
	return false
}

func (o rootPrivCentos) yumUpdateInfo() bool {
	return false
}

func (o rootPrivCentos) yumChangelog() bool {
	return false
}
