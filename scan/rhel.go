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

	majorVersion, _ := o.Distro.MajorVersion()
	switch majorVersion {
	case 5:
		return []string{
			"yum-utils",
			"yum-security",
		}
	case 6:
		return []string{
			"yum-utils",
			"yum-plugin-security",
		}
	default:
		return []string{
			"yum-utils",
		}
	}
}

func (o *rhel) depsDeep() []string {
	majorVersion, _ := o.Distro.MajorVersion()
	switch majorVersion {
	case 5:
		return []string{
			"yum-utils",
			"yum-security",
			"yum-changelog",
		}
	case 6:
		return []string{
			"yum-utils",
			"yum-plugin-security",
			"yum-plugin-changelog",
		}
	default:
		return []string{
			"yum-utils",
			"yum-plugin-changelog",
		}
	}
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
	if o.getServerInfo().Mode.IsOffline() {
		return []cmd{}
	}

	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 6 {
		return []cmd{
			// {"needs-restarting", exitStatusZero},
			{"yum repolist --color=never", exitStatusZero},
			{"yum list-security --security --color=never", exitStatusZero},
			{"yum info-security --color=never", exitStatusZero},
			{"repoquery -h", exitStatusZero},
		}
	}
	return []cmd{
		{"yum repolist --color=never", exitStatusZero},
		{"yum updateinfo list updates --security --color=never", exitStatusZero},
		{"yum updateinfo updates --security --color=never ", exitStatusZero},
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *rhel) sudoNoPasswdCmdsDeep() []cmd {
	return append(o.sudoNoPasswdCmdsFastRoot(),
		cmd{"yum changelog all updates --color=never", exitStatusZero})
}

type rootPrivRHEL struct{}

func (o rootPrivRHEL) repoquery() bool {
	return true
}

func (o rootPrivRHEL) yumRepolist() bool {
	return true
}

func (o rootPrivRHEL) yumUpdateInfo() bool {
	return true
}

func (o rootPrivRHEL) yumChangelog() bool {
	return true
}
