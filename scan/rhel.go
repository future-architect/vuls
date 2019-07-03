package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type rhel struct {
	redhatBase
}

// NewRHEL is constructor
func newRHEL(c config.ServerInfo) *rhel {
	r := &rhel{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivRHEL{},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

func (o *rhel) checkScanMode() error {
	return nil
}

func (o *rhel) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	} else if o.getServerInfo().Mode.IsDeep() {
		return o.execCheckDeps(o.depsDeep())
	}
	return xerrors.New("Unknown scan mode")
}

func (o *rhel) depsFast() []string {
	return []string{}
}

func (o *rhel) depsFastRoot() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}

	// repoquery
	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 8 {
		return []string{"yum-utils"}
	}
	return []string{"dnf-utils"}
}

func (o *rhel) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *rhel) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
	}
}

func (o *rhel) sudoNoPasswdCmdsFast() []cmd {
	return []cmd{}
}

func (o *rhel) sudoNoPasswdCmdsFastRoot() []cmd {
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

func (o *rhel) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

type rootPrivRHEL struct{}

func (o rootPrivRHEL) repoquery() bool {
	return true
}

func (o rootPrivRHEL) yumMakeCache() bool {
	return true
}

func (o rootPrivRHEL) yumPS() bool {
	return true
}
