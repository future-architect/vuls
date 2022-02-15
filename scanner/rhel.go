package scanner

import (
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
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
	r.log = logging.NewNormalLogger()
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
	// `rpm -qa` shows dnf-utils as yum-utils on RHEL8, CentOS8, Alma8, Rocky8
	return []string{"yum-utils"}
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
			{"lsof -i -P -n", exitStatusZero},
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

func (o *rhel) checkEnabledRepoList(version string) {
	ss := strings.Split(version, ".")
	if len(ss) < 2 {
		o.setErrs([]error{xerrors.Errorf("Failed to detect repository name. err: expected version format: major.minor, actual version: %s", version)})
		return
	}

	major, minor := ss[0], ss[1]
	if major == "5" {
		o.EnabledRepoList = []string{"rhel-5-desktop-rpms", "rhel-5-server-rpms"}
		return
	}

	r := o.exec(`yum repolist enabled 2>/dev/null`, noSudo)
	if !r.isSuccess() {
		o.setErrs([]error{xerrors.Errorf("Failed to check enable repository list. err: %w", r.Error)})
		return
	}
	for _, l := range strings.Split(r.Stdout, "\n")[1:] {
		repo := strings.Split(l, " ")[0]
		if strings.Contains(repo, "-eus-") || strings.Contains(repo, "-aus-") {
			repo = fmt.Sprintf("%s__%s_DOT_%s", repo, major, minor)
		}
		o.EnabledRepoList = append(o.EnabledRepoList, repo)
	}
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
