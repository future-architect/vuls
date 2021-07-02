package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
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
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *centos) checkScanMode() error {
	return nil
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
	// `rpm -qa` shows dnf-utils as yum-utils on RHEL8, CentOS8, Rocky8
	return []string{"yum-utils"}
}

func (o *centos) depsFastRoot() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	// repoquery
	// `rpm -qa` shows dnf-utils as yum-utils on RHEL8, CentOS8, Rocky8
	return []string{"yum-utils"}
}

func (o *centos) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *centos) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
	}
}

func (o *centos) sudoNoPasswdCmdsFast() []cmd {
	return []cmd{}
}

func (o *centos) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"repoquery -h", exitStatusZero},
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P", exitStatusZero},
		}
	}
	return []cmd{
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *centos) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivCentos struct{}

func (o rootPrivCentos) repoquery() bool {
	return false
}

func (o rootPrivCentos) yumMakeCache() bool {
	return false
}

func (o rootPrivCentos) yumPS() bool {
	return false
}
