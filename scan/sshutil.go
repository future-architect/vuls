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
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	conf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/util"
)

type sshResult struct {
	Servername string
	Host       string
	Port       string
	Cmd        string
	Stdout     string
	Stderr     string
	ExitStatus int
	Error      error
}

func (s sshResult) String() string {
	return fmt.Sprintf(
		"SSHResult: servername: %s, cmd: %s, exitstatus: %d, stdout: %s, stderr: %s, err: %s",
		s.Servername, s.Cmd, s.ExitStatus, s.Stdout, s.Stderr, s.Error)
}

func (s sshResult) isSuccess(expectedStatusCodes ...int) bool {
	if s.Error != nil {
		return false
	}
	if len(expectedStatusCodes) == 0 {
		return s.ExitStatus == 0
	}
	for _, code := range expectedStatusCodes {
		if code == s.ExitStatus {
			return true
		}
	}
	return false
}

// Sudo is Const value for sudo mode
const sudo = true

// NoSudo is Const value for normal user mode
const noSudo = false

func parallelSSHExec(fn func(osTypeInterface) error, timeoutSec ...int) (errs []error) {
	resChan := make(chan string, len(servers))
	errChan := make(chan error, len(servers))
	defer close(errChan)
	defer close(resChan)

	for _, s := range servers {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					logrus.Debugf("Panic: %s on %s",
						p, s.getServerInfo().ServerName)
				}
			}()
			if err := fn(s); err != nil {
				errChan <- fmt.Errorf("%s@%s:%s: %s",
					s.getServerInfo().User,
					s.getServerInfo().Host,
					s.getServerInfo().Port,
					err,
				)
			} else {
				resChan <- s.getServerInfo().ServerName
			}
		}(s)
	}

	var timeout int
	if len(timeoutSec) == 0 {
		timeout = 10 * 60
	} else {
		timeout = timeoutSec[0]
	}

	var snames []string
	isTimedout := false
	for i := 0; i < len(servers); i++ {
		select {
		case s := <-resChan:
			snames = append(snames, s)
		case err := <-errChan:
			errs = append(errs, err)
		case <-time.After(time.Duration(timeout) * time.Second):
			isTimedout = true
		}
	}

	// collect timed out servernames
	var timedoutSnames []string
	if isTimedout {
		for _, s := range servers {
			name := s.getServerInfo().ServerName
			found := false
			for _, t := range snames {
				if name == t {
					found = true
					break
				}
			}
			if !found {
				timedoutSnames = append(timedoutSnames, name)
			}
		}
	}
	if isTimedout {
		errs = append(errs, fmt.Errorf(
			"Timed out: %s", timedoutSnames))
	}
	return
}

func sshExec(c conf.ServerInfo, cmd string, sudo bool, log ...*logrus.Entry) (result sshResult) {
	if isSSHExecNative() {
		result = sshExecNative(c, cmd, sudo)
	} else {
		result = sshExecExternal(c, cmd, sudo)
	}

	logger := getSSHLogger(log...)
	logger.Debug(result)
	return
}

func isSSHExecNative() bool {
	return runtime.GOOS == "windows" || !conf.Conf.SSHExternal
}

func sshExecNative(c conf.ServerInfo, cmd string, sudo bool) (result sshResult) {
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
	if err = session.RequestPty("xterm", 400, 256, modes); err != nil {
		result.Error = fmt.Errorf(
			"Failed to request for pseudo terminal. servername: %s, err: %s",
			c.ServerName, err)
		result.ExitStatus = 999
		return
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	cmd = decolateCmd(c, cmd, sudo)
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

func sshExecExternal(c conf.ServerInfo, cmd string, sudo bool) (result sshResult) {
	sshBinaryPath, err := exec.LookPath("ssh")
	if err != nil {
		return sshExecNative(c, cmd, sudo)
	}

	defaultSSHArgs := []string{
		"-t",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
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

	cmd = decolateCmd(c, cmd, sudo)
	//  cmd = fmt.Sprintf("stty cols 256; set -o pipefail; %s", cmd)

	args = append(args, cmd)
	execCmd := exec.Command(sshBinaryPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	execCmd.Stdout = &stdoutBuf
	execCmd.Stderr = &stderrBuf
	if err := execCmd.Run(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
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

func decolateCmd(c conf.ServerInfo, cmd string, sudo bool) string {
	if sudo && c.User != "root" && !c.IsContainer() {
		cmd = fmt.Sprintf("sudo -S %s", cmd)
		cmd = strings.Replace(cmd, "|", "| sudo ", -1)
	}

	if c.Family != "FreeBSD" {
		// set pipefail option. Bash only
		// http://unix.stackexchange.com/questions/14270/get-exit-status-of-process-thats-piped-to-another
		cmd = fmt.Sprintf("set -o pipefail; %s", cmd)
	}

	if c.IsContainer() {
		switch c.Container.Type {
		case "", "docker":
			cmd = fmt.Sprintf(`docker exec %s /bin/bash -c "%s"`, c.Container.ContainerID, cmd)
		}
	}
	//  cmd = fmt.Sprintf("set -x; %s", cmd)
	return cmd
}

func getAgentAuth() (auth ssh.AuthMethod, ok bool) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); len(sock) > 0 {
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
			User: c.User,
			Auth: []ssh.AuthMethod{auth},
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
		User: c.User,
		Auth: auths,
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
