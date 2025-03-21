package scanner

import (
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type centos struct {
	redhatBase
}

// NewCentOS is constructor
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
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *centos) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() || strings.HasPrefix(o.getDistro().Release, "stream") {
		return []string{}
	}

	if v, _ := o.getDistro().MajorVersion(); v < 8 {
		return []string{"yum-utils"}
	}

	return []string{}
}

func (o *centos) depsFastRoot() []string {
	var deps []string

	if !o.getServerInfo().Mode.IsOffline() {
		deps = append(deps, "yum-utils")
	}

	v, _ := o.getDistro().MajorVersion()
	switch {
	case v < 7:
		deps = append(deps,
			"which",
			"lsof",
			"procps",
			"iproute",
		)
	default:
		deps = append(deps,
			"which",
			"lsof",
			"procps-ng",
			"iproute",
		)
	}

	return deps
}

func (o *centos) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *centos) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *centos) sudoNoPasswdCmdsFast() []cmd {
	if o.getServerInfo().Mode.IsOffline() {
		return []cmd{}
	}

	if strings.HasPrefix(o.getDistro().Release, "stream") {
		return []cmd{
			{"dnf repoquery -h", exitStatusZero},
		}
	}

	if v, _ := o.getDistro().MajorVersion(); v < 8 {
		return []cmd{
			{"repoquery -h", exitStatusZero},
		}
	}

	return []cmd{
		{"dnf repoquery -h", exitStatusZero},
	}
}

func (o *centos) sudoNoPasswdCmdsFastRoot() []cmd {
	var cs []cmd

	if !o.getServerInfo().Mode.IsOffline() {
		if v, _ := o.getDistro().MajorVersion(); v < 8 {
			cs = append(cs,
				cmd{"repoquery -h", exitStatusZero},
				cmd{"needs-restarting", exitStatusZero},
			)
		} else {
			cs = append(cs,
				cmd{"dnf repoquery -h", exitStatusZero},
				cmd{"needs-restarting", exitStatusZero},
			)
		}
	}

	if !o.getServerInfo().IsContainer() {
		cs = append(cs,
			cmd{"which which", exitStatusZero},
			cmd{"stat /proc/1/exe", exitStatusZero},
			cmd{"ls -l /proc/1/exe", exitStatusZero},
			cmd{"cat /proc/1/maps", exitStatusZero},
			cmd{"lsof -i -P -n", exitStatusZero},
		)
	}

	return cs
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
