package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type rocky struct {
	redhatBase
}

// NewRocky is constructor
func newRocky(c config.ServerInfo) *rocky {
	r := &rocky{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivRocky{},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *rocky) checkScanMode() error {
	return nil
}

func (o *rocky) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *rocky) depsFast() []string {
	return []string{}
}

func (o *rocky) depsFastRoot() []string {
	return []string{}
}

func (o *rocky) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *rocky) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *rocky) sudoNoPasswdCmdsFast() []cmd {
	return []cmd{}
}

func (o *rocky) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P -n", exitStatusZero},
		}
	}
	return []cmd{
		{"needs-restarting", exitStatusZero},
	}
}

func (o *rocky) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivRocky struct{}

func (o rootPrivRocky) repoquery() bool {
	return false
}

func (o rootPrivRocky) yumMakeCache() bool {
	return false
}

func (o rootPrivRocky) yumPS() bool {
	return false
}
