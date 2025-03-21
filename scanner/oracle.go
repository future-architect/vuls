package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type oracle struct {
	redhatBase
}

// NewOracle is constructor
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
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *oracle) checkScanMode() error {
	return nil
}

func (o *oracle) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *oracle) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	if v, _ := o.getDistro().MajorVersion(); v < 8 {
		return []string{"yum-utils"}
	}

	return []string{}
}

func (o *oracle) depsFastRoot() []string {
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

func (o *oracle) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *oracle) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *oracle) sudoNoPasswdCmdsFast() []cmd {
	if o.getServerInfo().Mode.IsOffline() {
		return []cmd{}
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

func (o *oracle) sudoNoPasswdCmdsFastRoot() []cmd {
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

	if !o.ServerInfo.IsContainer() {
		cs = append(cs,
			cmd{"which which", exitStatusZero},
			cmd{"stat /proc/1/exe", exitStatusZero},
			cmd{"ls -l /proc/1/exe", exitStatusZero},
			cmd{"cat /proc/1/maps", exitStatusZero},
		)
	}

	return cs
}

func (o *oracle) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivOracle struct{}

func (o rootPrivOracle) repoquery() bool {
	return true
}

func (o rootPrivOracle) yumMakeCache() bool {
	return true
}

func (o rootPrivOracle) yumPS() bool {
	return true
}
