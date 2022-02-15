package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type alma struct {
	redhatBase
}

// NewAlma is constructor
func newAlma(c config.ServerInfo) *alma {
	r := &alma{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivAlma{},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *alma) checkScanMode() error {
	return nil
}

func (o *alma) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	} else {
		return o.execCheckDeps(o.depsDeep())
	}
}

func (o *alma) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	// repoquery
	// `rpm -qa` shows dnf-utils as yum-utils on RHEL8, CentOS8, Alma8, Rocky8
	return []string{"yum-utils"}
}

func (o *alma) depsFastRoot() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	// repoquery
	// `rpm -qa` shows dnf-utils as yum-utils on RHEL8, CentOS8, Alma8, Rocky8
	return []string{"yum-utils"}
}

func (o *alma) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *alma) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
	}
}

func (o *alma) sudoNoPasswdCmdsFast() []cmd {
	return []cmd{}
}

func (o *alma) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"repoquery -h", exitStatusZero},
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P -n", exitStatusZero},
		}
	}
	return []cmd{
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *alma) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

func (o *alma) checkEnabledRepoList(version string) {
	switch util.Major(version) {
	case "8":
		o.EnabledRepoList = []string{"rhel-8-for-x86_64-appstream-rpms", "rhel-8-for-x86_64-baseos-rpms"}
	}
}

type rootPrivAlma struct{}

func (o rootPrivAlma) repoquery() bool {
	return false
}

func (o rootPrivAlma) yumMakeCache() bool {
	return false
}

func (o rootPrivAlma) yumPS() bool {
	return false
}
