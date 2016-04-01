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
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	conf "github.com/future-architect/vuls/config"
	"github.com/k0kubun/pp"
)

type sshResult struct {
	Host       string
	Port       string
	Stdout     string
	Stderr     string
	ExitStatus int
}

func (s sshResult) isSuccess(expectedStatusCodes ...int) bool {
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
	errChan := make(chan error, len(servers))
	defer close(errChan)
	for _, s := range servers {
		go func(s osTypeInterface) {
			if err := fn(s); err != nil {
				errChan <- fmt.Errorf("%s@%s:%s: %s",
					s.getServerInfo().User,
					s.getServerInfo().Host,
					s.getServerInfo().Port,
					err,
				)
			} else {
				errChan <- nil
			}
		}(s)
	}

	var timeout int
	if len(timeoutSec) == 0 {
		timeout = 10 * 60
	} else {
		timeout = timeoutSec[0]
	}

	for i := 0; i < len(servers); i++ {
		select {
		case err := <-errChan:
			if err != nil {
				errs = append(errs, err)
			} else {
				logrus.Debug("Parallel SSH Success.")
			}
		case <-time.After(time.Duration(timeout) * time.Second):
			logrus.Errorf("Parallel SSH Timeout.")
			errs = append(errs, fmt.Errorf("Timed out!"))
		}
	}
	return
}

func sshExec(c conf.ServerInfo, cmd string, sudo bool, log ...*logrus.Entry) (result sshResult) {
	// Setup Logger
	var logger *logrus.Entry
	if len(log) == 0 {
		level := logrus.InfoLevel
		if conf.Conf.Debug == true {
			level = logrus.DebugLevel
		}
		l := &logrus.Logger{
			Out:       os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Hooks:     make(logrus.LevelHooks),
			Level:     level,
		}
		logger = logrus.NewEntry(l)
	} else {
		logger = log[0]
	}

	var err error
	if sudo && c.User != "root" {
		switch {
		case c.SudoOpt.ExecBySudo:
			cmd = fmt.Sprintf("echo %s | sudo -S %s", c.Password, cmd)
		case c.SudoOpt.ExecBySudoSh:
			cmd = fmt.Sprintf("echo %s | sudo sh -c '%s'", c.Password, cmd)
		default:
			logger.Panicf("sudoOpt is invalid. SudoOpt: %v", c.SudoOpt)
		}
	}
	// set pipefail option.
	// http://unix.stackexchange.com/questions/14270/get-exit-status-of-process-thats-piped-to-another
	cmd = fmt.Sprintf("set -o pipefail; %s", cmd)
	logger.Debugf("Command: %s", strings.Replace(cmd, "\n", "", -1))

	var client *ssh.Client
	client, err = sshConnect(c)
	defer client.Close()

	var session *ssh.Session
	if session, err = client.NewSession(); err != nil {
		logger.Errorf("Failed to new session. err: %s, c: %s",
			err,
			pp.Sprintf("%v", c))
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
	if err = session.RequestPty("xterm", 400, 120, modes); err != nil {
		logger.Errorf("Failed to request for pseudo terminal. err: %s, c: %s",
			err,
			pp.Sprintf("%v", c))

		result.ExitStatus = 999
		return
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

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
	result.Host = c.Host
	result.Port = c.Port

	logger.Debugf(
		"SSH executed. cmd: %s, status: %#v\nstdout: \n%s\nstderr: \n%s",
		cmd, err, result.Stdout, result.Stderr)

	return
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
		logrus.Fatalf("Faild to add keyAuth. err: %s", err)
	}

	if c.Password != "" {
		auths = append(auths, ssh.Password(c.Password))
	}

	// http://blog.ralch.com/tutorial/golang-ssh-connection/
	config := &ssh.ClientConfig{
		User: c.User,
		Auth: auths,
	}
	//  log.Debugf("config: %s", pp.Sprintf("%v", config))

	notifyFunc := func(e error, t time.Duration) {
		logrus.Warnf("Faild to ssh %s@%s:%s. err: %s, Retrying in %s...",
			c.User, c.Host, c.Port, e, t)
		logrus.Debugf("sshConInfo: %s", pp.Sprintf("%v", c))
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
		return nil, fmt.Errorf("rtop: unsupported key type %q", block.Type)
	}
}
