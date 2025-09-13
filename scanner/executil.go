package scanner

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	ex "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
)

type execResult struct {
	Servername string
	Container  config.Container
	Host       string
	Port       string
	Cmd        string
	Stdout     string
	Stderr     string
	ExitStatus int
	Error      error
}

func (s execResult) String() string {
	sname := ""
	if s.Container.ContainerID == "" {
		sname = s.Servername
	} else {
		sname = s.Container.Name + "@" + s.Servername
	}

	return fmt.Sprintf(
		"execResult: servername: %s\n  cmd: %s\n  exitstatus: %d\n  stdout: %s\n  stderr: %s\n  err: %s",
		sname, s.Cmd, s.ExitStatus, s.Stdout, s.Stderr, s.Error)
}

func (s execResult) isSuccess(expectedStatusCodes ...int) bool {
	if len(expectedStatusCodes) == 0 {
		return s.ExitStatus == 0
	}
	for _, code := range expectedStatusCodes {
		if code == s.ExitStatus {
			return true
		}
	}
	if s.Error != nil {
		return false
	}
	return false
}

// sudo is Const value for sudo mode
const sudo = true

// noSudo is Const value for normal user mode
const noSudo = false

// Issue commands to the target servers in parallel via SSH or local execution.  If execution fails, the server will be excluded from the target server list(servers) and added to the error server list(errServers).
func parallelExec(fn func(osTypeInterface) error, timeoutSec ...int) {
	resChan := make(chan osTypeInterface, len(servers))
	defer close(resChan)

	for _, s := range servers {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					logging.Log.Debugf("Panic: %s on %s",
						p, s.getServerInfo().GetServerName())
				}
			}()
			if err := fn(s); err != nil {
				s.setErrs([]error{err})
				resChan <- s
			} else {
				resChan <- s
			}
		}(s)
	}

	var timeout int
	if len(timeoutSec) == 0 {
		timeout = 10 * 60
	} else {
		timeout = timeoutSec[0]
	}

	var successes []osTypeInterface
	isTimedout := false
	for i := 0; i < len(servers); i++ {
		select {
		case s := <-resChan:
			if len(s.getErrs()) == 0 {
				successes = append(successes, s)
			} else {
				logging.Log.Errorf("Error on %s, err: %+v",
					s.getServerInfo().GetServerName(), s.getErrs())
				errServers = append(errServers, s)
			}
		case <-time.After(time.Duration(timeout) * time.Second):
			isTimedout = true
		}
	}

	if isTimedout {
		// set timed out error and append to errServers
		for _, s := range servers {
			name := s.getServerInfo().GetServerName()
			found := false
			for _, ss := range successes {
				if name == ss.getServerInfo().GetServerName() {
					found = true
					break
				}
			}
			if !found {
				err := xerrors.Errorf("Timed out: %s", s.getServerInfo().GetServerName())
				logging.Log.Errorf("%+v", err)
				s.setErrs([]error{err})
				errServers = append(errServers, s)
			}
		}
	}
	servers = successes
}

func exec(c config.ServerInfo, cmd string, sudo bool, log ...logging.Logger) (result execResult) {
	logger := getSSHLogger(log...)
	logger.Debugf("Executing... %s", strings.ReplaceAll(cmd, "\n", ""))

	if isLocalExec(c.Port, c.Host) {
		result = localExec(c, cmd, sudo)
	} else {
		result = sshExecExternal(c, cmd, sudo)
	}

	logger.Debugf("%+v", result)
	return
}

func isLocalExec(port, host string) bool {
	return port == "local" && (host == "127.0.0.1" || host == "localhost")
}

func localExec(c config.ServerInfo, cmdstr string, sudo bool) (result execResult) {
	cmdstr = decorateCmd(c, cmdstr, sudo)
	var cmd *ex.Cmd
	switch c.Distro.Family {
	case constant.Windows:
		cmd = ex.Command("powershell.exe", "-NoProfile", "-NonInteractive", cmdstr)
	default:
		cmd = ex.Command("/bin/sh", "-c", cmdstr)
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		result.Error = err
		if exitError, ok := err.(*ex.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			result.ExitStatus = waitStatus.ExitStatus()
		} else {
			result.ExitStatus = 999
		}
	} else {
		result.ExitStatus = 0
	}
	result.Stdout = toUTF8(stdoutBuf.String())
	result.Stderr = toUTF8(stderrBuf.String())
	result.Cmd = cmd.String()
	return
}

func sshExecExternal(c config.ServerInfo, cmdstr string, sudo bool) (result execResult) {
	sshBinaryPath, err := ex.LookPath("ssh")
	if err != nil {
		return execResult{Error: err}
	}
	if runtime.GOOS == "windows" {
		sshBinaryPath = "ssh.exe"
	}

	var args []string

	if c.SSHConfigPath != "" {
		args = append(args, "-F", c.SSHConfigPath)
	} else {
		args = append(args,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "LogLevel=quiet",
			"-o", "ConnectionAttempts=3",
			"-o", "ConnectTimeout=10",
		)
		if runtime.GOOS != "windows" {
			home, err := homedir.Dir()
			if err != nil {
				msg := fmt.Sprintf("Failed to get HOME directory: %s", err)
				result.Stderr = msg
				result.ExitStatus = 997
				return
			}

			controlPath := filepath.Join(home, ".vuls", "cm-%C")
			h := fnv.New32()
			if _, err := h.Write([]byte(c.ServerName)); err == nil {
				controlPath = filepath.Join(home, ".vuls", fmt.Sprintf("cm-%x-%%C", h.Sum32()))
			}

			args = append(args,
				"-o", "ControlMaster=auto",
				"-o", fmt.Sprintf("ControlPath=%s", controlPath),
				"-o", "Controlpersist=10m")
		}
	}

	if config.Conf.Vvv {
		args = append(args, "-vvv")
	}
	if len(c.JumpServer) != 0 {
		args = append(args, "-J", strings.Join(c.JumpServer, ","))
	}
	if c.User != "" {
		args = append(args, "-l", c.User)
	}
	if c.Port != "" {
		args = append(args, "-p", c.Port)
	}
	if c.KeyPath != "" {
		args = append(args, "-i", c.KeyPath)
		args = append(args, "-o", "PasswordAuthentication=no")
	}
	args = append(args, c.Host)

	cmdstr = decorateCmd(c, cmdstr, sudo)
	var cmd *ex.Cmd
	switch c.Distro.Family {
	case constant.Windows:
		cmd = ex.Command(sshBinaryPath, append(args, cmdstr)...)
	default:
		cmd = ex.Command(sshBinaryPath, append(args, fmt.Sprintf("stty cols 1000; %s", cmdstr))...)
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		if e, ok := err.(*ex.ExitError); ok {
			if s, ok := e.Sys().(syscall.WaitStatus); ok {
				result.ExitStatus = s.ExitStatus()
			} else {
				result.ExitStatus = 998
			}
		} else {
			result.ExitStatus = 999
		}
	} else {
		result.ExitStatus = 0
	}
	result.Stdout = toUTF8(stdoutBuf.String())
	result.Stderr = toUTF8(stderrBuf.String())
	result.Servername = c.ServerName
	result.Container = c.Container
	result.Host = c.Host
	result.Port = c.Port
	result.Cmd = cmd.String()
	return
}

func getSSHLogger(log ...logging.Logger) logging.Logger {
	if len(log) == 0 {
		return logging.Log
	}
	return log[0]
}

func dockerShell(family string) string {
	switch family {
	// case conf.Alpine, conf.Debian:
	// return "/bin/sh"
	default:
		// return "/bin/bash"
		return "/bin/sh"
	}
}

func decorateCmd(c config.ServerInfo, cmd string, sudo bool) string {
	if sudo && c.User != "root" && !c.IsContainer() {
		cmd = fmt.Sprintf("sudo %s", cmd)
	}

	// If you are using pipe and you want to detect preprocessing errors, remove comment out
	//  switch c.Distro.Family {
	//  case "FreeBSD", "ubuntu", "debian", "raspbian":
	//  default:
	//      // set pipefail option. Bash only
	//      // http://unix.stackexchange.com/questions/14270/get-exit-status-of-process-thats-piped-to-another
	//      cmd = fmt.Sprintf("set -o pipefail; %s", cmd)
	//  }

	if c.IsContainer() {
		switch c.ContainerType {
		case "", "docker":
			cmd = fmt.Sprintf(`docker exec --user 0 %s %s -c '%s'`,
				c.Container.ContainerID, dockerShell(c.Distro.Family), cmd)
		case "lxd":
			// If the user belong to the "lxd" group, root privilege is not required.
			cmd = fmt.Sprintf(`lxc exec %s -- %s -c '%s'`,
				c.Container.Name, dockerShell(c.Distro.Family), cmd)
		case "lxc":
			cmd = fmt.Sprintf(`lxc-attach -n %s 2>/dev/null -- %s -c '%s'`,
				c.Container.Name, dockerShell(c.Distro.Family), cmd)
			// LXC required root privilege
			if c.User != "root" {
				cmd = fmt.Sprintf("sudo %s", cmd)
			}
		}
	}
	//  cmd = fmt.Sprintf("set -x; %s", cmd)
	return cmd
}

func toUTF8(s string) string {
	d := chardet.NewTextDetector()
	res, err := d.DetectBest([]byte(s))
	if err != nil {
		return s
	}

	var bs []byte
	switch res.Charset {
	case "UTF-8":
		bs, err = []byte(s), nil
	case "UTF-16LE":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()))
	case "UTF-16BE":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewDecoder()))
	case "Shift_JIS":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.ShiftJIS.NewDecoder()))
	case "EUC-JP":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.EUCJP.NewDecoder()))
	case "ISO-2022-JP":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.ISO2022JP.NewDecoder()))
	default:
		bs, err = []byte(s), nil
	}
	if err != nil {
		return s
	}
	return string(bs)
}
