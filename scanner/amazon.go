package scanner

import (
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
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
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *amazon) checkScanMode() error {
	return nil
}

func (o *amazon) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	if o.getServerInfo().Mode.IsDeep() {
		return o.execCheckDeps(o.depsDeep())
	}
	return xerrors.New("Unknown scan mode")
}

func (o *amazon) depsFast() []string {
	switch v, _ := o.Distro.MajorVersion(); v {
	case 1:
		if !o.getServerInfo().Mode.IsOffline() {
			return []string{"yum-utils"}
		}
		return []string{}
	case 2:
		return []string{"yum-utils"}
	default:
		return []string{}
	}
}

func (o *amazon) depsFastRoot() []string {
	var deps []string

	switch v, _ := o.Distro.MajorVersion(); v {
	case 1:
		if !o.getServerInfo().Mode.IsOffline() {
			deps = append(deps, "yum-utils")
		}
		deps = append(deps,
			"which",
			"lsof",
			"procps",
			"iproute",
		)
	case 2:
		deps = append(deps,
			"yum-utils",
			"which",
			"lsof",
			"procps-ng",
			"iproute",
		)
	default:
		if !o.getServerInfo().Mode.IsOffline() {
			deps = append(deps, "dnf-utils")
		}
		deps = append(deps,
			"which",
			"lsof",
			"procps-ng",
			"iproute",
		)
	}

	return deps
}

func (o *amazon) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *amazon) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *amazon) sudoNoPasswdCmdsFast() []cmd {
	switch v, _ := o.getDistro().MajorVersion(); v {
	case 1:
		if !o.getServerInfo().Mode.IsOffline() {
			return []cmd{
				{"repoquery -h", exitStatusZero},
			}
		}
		return []cmd{}
	case 2:
		return []cmd{
			{"repoquery -h", exitStatusZero},
		}
	default:
		if !o.getServerInfo().Mode.IsOffline() {
			return []cmd{
				{"dnf repoquery -h", exitStatusZero},
			}
		}
		return []cmd{}
	}
}

func (o *amazon) sudoNoPasswdCmdsFastRoot() []cmd {
	var cs []cmd

	switch v, _ := o.getDistro().MajorVersion(); v {
	case 1:
		if !o.getServerInfo().Mode.IsOffline() {
			cs = append(cs,
				cmd{"repoquery -h", exitStatusZero},
				cmd{"needs-restarting", exitStatusZero},
			)
		}
	case 2:
		cs = append(cs, cmd{"repoquery -h", exitStatusZero})
		if !o.getServerInfo().Mode.IsOffline() {
			cs = append(cs,
				cmd{"needs-restarting", exitStatusZero},
			)
		}
	default:
		if !o.getServerInfo().Mode.IsOffline() {
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

func (o *amazon) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivAmazon struct{}

func (o rootPrivAmazon) repoquery() bool {
	return false
}

func (o rootPrivAmazon) yumMakeCache() bool {
	return false
}

func (o rootPrivAmazon) yumPS() bool {
	return false
}
