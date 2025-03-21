package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
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
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *alma) depsFast() []string {
	return []string{}
}

func (o *alma) depsFastRoot() []string {
	var deps []string

	if !o.getServerInfo().Mode.IsOffline() {
		deps = append(deps, "yum-utils")
	}

	deps = append(deps,
		"which",
		"lsof",
		"procps-ng",
		"iproute",
	)

	return deps
}

func (o *alma) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *alma) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *alma) sudoNoPasswdCmdsFast() []cmd {
	if !o.getServerInfo().Mode.IsOffline() {
		return []cmd{
			{"dnf repoquery -h", exitStatusZero},
		}
	}
	return []cmd{}
}

func (o *alma) sudoNoPasswdCmdsFastRoot() []cmd {
	var cs []cmd

	if !o.getServerInfo().Mode.IsOffline() {
		cs = append(cs,
			cmd{"dnf repoquery -h", exitStatusZero},
			cmd{"needs-restarting", exitStatusZero},
		)
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

func (o *alma) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
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
