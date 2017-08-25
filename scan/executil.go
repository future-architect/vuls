/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	ex "os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/cenkalti/backoff"
	conf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/util"
	"github.com/sirupsen/logrus"
)

type execResult struct {
	Servername string
	Host       string
	Port       string
	Cmd        string
	Stdout     string
	Stderr     string
	ExitStatus int
	Error      error
}

func (s execResult) String() string {
	return fmt.Sprintf(
		"execResult: servername: %s\n  cmd: %s\n  exitstatus: %d\n  stdout: %s\n  stderr: %s\n  err: %s",
		s.Servername, s.Cmd, s.ExitStatus, s.Stdout, s.Stderr, s.Error)
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

//  Issue commands to the target servers in parallel via SSH or local execution.  If execution fails, the server will be excluded from the target server list(servers) and added to the error server list(errServers).
func parallelExec(fn func(osTypeInterface) error, timeoutSec ...int) {
	resChan := make(chan osTypeInterface, len(servers))
	defer close(resChan)

	for _, s := range servers {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s",
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
				util.Log.Errorf("Error: %s, err: %s",
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
				msg := fmt.Sprintf("Timed out: %s",
					s.getServerInfo().GetServerName())
				util.Log.Errorf(msg)
				s.setErrs([]error{fmt.Errorf(msg)})
				errServers = append(errServers, s)
			}
		}
	}
	servers = successes
	return
}

func exec(c conf.ServerInfo, cmd string, sudo bool, log ...*logrus.Entry) (result execResult) {
	logger := getSSHLogger(log...)
	logger.Debugf("Executing... %s", strings.Replace(cmd, "\n", "", -1))

	if c.Port == "local" &&
		(c.Host == "127.0.0.1" || c.Host == "localhost") {
		result = localExec(c, cmd, sudo)
	} else if conf.Conf.SSHNative {
		result = sshExecNative(c, cmd, sudo)
	} else {
		result = sshExecExternal(c, cmd, sudo)
	}

	logger.Debug(result)
	return
}

func localExec(c conf.ServerInfo, cmdstr string, sudo bool) (result execResult) {
	cmdstr = decorateCmd(c, cmdstr, sudo)
	var cmd *ex.Cmd
	if c.Distro.Family == conf.FreeBSD {
		cmd = ex.Command("/bin/sh", "-c", cmdstr)
	} else {
		cmd = ex.Command("/bin/bash", "-c", cmdstr)
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

	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	result.Cmd = strings.Replace(cmdstr, "\n", "", -1)
	return
}

func sshExecNative(c conf.ServerInfo, cmd string, sudo bool) (result execResult) {
	result.Servername = c.ServerName
	result.Host = c.Host
	result.Port = c.Port

	var client *ssh.Client
	var err error
	if client, err = sshConnect(c); err != nil {
		result.Error = err
		result.ExitStatus = 999
		return
	}
	defer client.Close()

	var session *ssh.Session
	if session, err = client.NewSession(); err != nil {
		result.Error = fmt.Errorf(
			"Failed to create a new session. servername: %s, err: %s",
			c.ServerName, err)
		result.ExitStatus = 999
		return
	}
	defer session.Close()

	// http://blog.ralch.com/tutorial/golang-ssh-connection/
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err = session.RequestPty("xterm", 400, 1000, modes); err != nil {
		result.Error = fmt.Errorf(
			"Failed to request for pseudo terminal. servername: %s, err: %s",
			c.ServerName, err)
		result.ExitStatus = 999
		return
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	cmd = decorateCmd(c, cmd, sudo)
	if err := session.Run(cmd); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			result.ExitStatus = exitErr.ExitStatus()
		} else {
			result.ExitStatus = 999
		}
	} else {
		result.ExitStatus = 0
	}

	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	result.Cmd = strings.Replace(cmd, "\n", "", -1)
	return
}

func sshExecExternal(c conf.ServerInfo, cmd string, sudo bool) (result execResult) {
	sshBinaryPath, err := ex.LookPath("ssh")
	if err != nil {
		return sshExecNative(c, cmd, sudo)
	}

	defaultSSHArgs := []string{
		"-tt",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "LogLevel=quiet",
		"-o", "ConnectionAttempts=3",
		"-o", "ConnectTimeout=10",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",

		// TODO ssh session multiplexing
		//  "-o", "ControlMaster=auto",
		//  "-o", `ControlPath=~/.ssh/controlmaster-%r-%h.%p`,
		//  "-o", "Controlpersist=30m",
	}
	args := append(defaultSSHArgs, fmt.Sprintf("%s@%s", c.User, c.Host))
	args = append(args, "-p", c.Port)

	//  if conf.Conf.Debug {
	//      args = append(args, "-v")
	//  }

	if 0 < len(c.KeyPath) {
		args = append(args, "-i", c.KeyPath)
		args = append(args, "-o", "PasswordAuthentication=no")
	}

	cmd = decorateCmd(c, cmd, sudo)
	cmd = fmt.Sprintf("stty cols 1000; %s", cmd)

	args = append(args, cmd)
	execCmd := ex.Command(sshBinaryPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	execCmd.Stdout = &stdoutBuf
	execCmd.Stderr = &stderrBuf
	if err := execCmd.Run(); err != nil {
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

	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	result.Servername = c.ServerName
	result.Host = c.Host
	result.Port = c.Port
	result.Cmd = fmt.Sprintf("%s %s", sshBinaryPath, strings.Join(args, " "))
	return
}

func getSSHLogger(log ...*logrus.Entry) *logrus.Entry {
	if len(log) == 0 {
		return util.NewCustomLogger(conf.ServerInfo{})
	}
	return log[0]
}

func decorateCmd(c conf.ServerInfo, cmd string, sudo bool) string {
	if sudo && c.User != "root" && !c.IsContainer() {
		cmd = fmt.Sprintf("sudo -S %s", cmd)
		cmd = strings.Replace(cmd, "|", "| sudo ", -1)
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
		switch c.Containers.Type {
		case "", "docker":
			cmd = fmt.Sprintf(`docker exec --user 0 %s /bin/bash -c "%s"`, c.Container.ContainerID, cmd)
		case "lxd":
			cmd = fmt.Sprintf(`lxc exec %s -- /bin/bash -c "%s"`, c.Container.Name, cmd)
		}
	}
	//  cmd = fmt.Sprintf("set -x; %s", cmd)
	return cmd
}

func getAgentAuth() (auth ssh.AuthMethod, ok bool) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); 0 < len(sock) {
		if agconn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(agconn)
			auth = ssh.PublicKeysCallback(ag.Signers)
			ok = true
		}
	}
	return
}

func tryAgentConnect(c conf.ServerInfo) *ssh.Client {
	if auth, ok := getAgentAuth(); ok {
		config := &ssh.ClientConfig{
			User:            c.User,
			Auth:            []ssh.AuthMethod{auth},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		client, _ := ssh.Dial("tcp", c.Host+":"+c.Port, config)
		return client
	}
	return nil
}

func sshConnect(c conf.ServerInfo) (client *ssh.Client, err error) {
	if client = tryAgentConnect(c); client != nil {
		return client, nil
	}

	var auths = []ssh.AuthMethod{}
	if auths, err = addKeyAuth(auths, c.KeyPath, c.KeyPassword); err != nil {
		return nil, err
	}

	// http://blog.ralch.com/tutorial/golang-ssh-connection/
	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	notifyFunc := func(e error, t time.Duration) {
		logger := getSSHLogger()
		logger.Debugf("Failed to Dial to %s, err: %s, Retrying in %s...",
			c.ServerName, e, t)
	}
	err = backoff.RetryNotify(func() error {
		if client, err = ssh.Dial("tcp", c.Host+":"+c.Port, config); err != nil {
			return err
		}
		return nil
	}, backoff.NewExponentialBackOff(), notifyFunc)

	return
}

// https://github.com/rapidloop/rtop/blob/ba5b35e964135d50e0babedf0bd69b2fcb5dbcb4/src/sshhelper.go#L100
func addKeyAuth(auths []ssh.AuthMethod, keypath string, keypassword string) ([]ssh.AuthMethod, error) {
	if len(keypath) == 0 {
		return auths, nil
	}

	// read the file
	pemBytes, err := ioutil.ReadFile(keypath)
	if err != nil {
		return auths, err
	}

	// get first pem block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return auths, fmt.Errorf("no key found in %s", keypath)
	}

	// handle plain and encrypted keyfiles
	if x509.IsEncryptedPEMBlock(block) {
		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(keypassword))
		if err != nil {
			return auths, err
		}
		key, err := parsePemBlock(block)
		if err != nil {
			return auths, err
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return auths, err
		}
		return append(auths, ssh.PublicKeys(signer)), nil
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return auths, err
	}
	return append(auths, ssh.PublicKeys(signer)), nil
}

// ref golang.org/x/crypto/ssh/keys.go#ParseRawPrivateKey.
func parsePemBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "DSA PRIVATE KEY":
		return ssh.ParseDSAPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}
}
