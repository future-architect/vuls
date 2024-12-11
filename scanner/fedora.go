package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type fedora struct {
	redhatBase
}

// NewFedora is constructor
func newFedora(c config.ServerInfo) *fedora {
	r := &fedora{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivFedora{},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *fedora) checkScanMode() error {
	return nil
}

func (o *fedora) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *fedora) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	v, _ := o.getDistro().MajorVersion()
	switch {
	case v < 22:
		return []string{"yum-utils"}
	case v < 26:
		return []string{
			"dnf-plugins-core",
			"python3-dnf-plugins-core",
		}
	default:
		return []string{}
	}
}

func (o *fedora) depsFastRoot() []string {
	var deps []string

	v, _ := o.getDistro().MajorVersion()
	switch {
	case v < 22:
		if !o.getServerInfo().Mode.IsOffline() {
			deps = append(deps, "yum-utils")
		}
	case v < 26:
		if !o.getServerInfo().Mode.IsOffline() {
			deps = append(deps,
				"dnf-plugins-core",
				"python3-dnf-plugins-core",
			)
		}
	default:
	}

	return deps
}

func (o *fedora) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *fedora) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *fedora) sudoNoPasswdCmdsFast() []cmd {
	if o.getServerInfo().Mode.IsOffline() {
		return []cmd{}
	}

	v, _ := o.getDistro().MajorVersion()
	if v < 26 {
		return []cmd{
			{"repoquery -h", exitStatusZero},
		}
	}
	if v < 41 {
		return []cmd{
			{"dnf repoquery -h", exitStatusZero},
		}
	}
	return []cmd{
		{"dnf5 repoquery -h", exitStatusZero},
	}
}

func (o *fedora) sudoNoPasswdCmdsFastRoot() []cmd {
	var cs []cmd

	if !o.getServerInfo().Mode.IsOffline() {
		v, _ := o.getDistro().MajorVersion()
		switch {
		case v < 26:
			cs = append(cs,
				cmd{"repoquery -h", exitStatusZero},
				cmd{"needs-restarting", exitStatusZero},
			)
		case v < 41:
			cs = append(cs,
				cmd{"dnf repoquery -h", exitStatusZero},
				cmd{"dnf needs-restarting", exitStatusZero},
			)
		default:
			cs = append(cs,
				cmd{"dnf5 repoquery -h", exitStatusZero},
				cmd{"dnf5 needs-restarting", exitStatusZero},
			)
		}
	}

	if !o.ServerInfo.IsContainer() {
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

func (o *fedora) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivFedora struct{}

func (o rootPrivFedora) repoquery() bool {
	return false
}

func (o rootPrivFedora) yumMakeCache() bool {
	return false
}

func (o rootPrivFedora) yumPS() bool {
	return false
}
