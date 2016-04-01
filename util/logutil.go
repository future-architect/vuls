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

package util

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/rifflock/lfshook"

	"github.com/future-architect/vuls/config"
	formatter "github.com/kotakanbe/logrus-prefixed-formatter"
)

// NewCustomLogger creates logrus
func NewCustomLogger(c config.ServerInfo) *logrus.Entry {
	log := logrus.New()
	log.Formatter = &formatter.TextFormatter{MsgAnsiColor: c.LogMsgAnsiColor}
	log.Out = os.Stderr
	log.Level = logrus.InfoLevel
	if config.Conf.Debug {
		log.Level = logrus.DebugLevel
	}

	// File output
	logDir := "/var/log/vuls"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.Mkdir(logDir, 0666); err != nil {
			logrus.Errorf("Failed to create log directory: %s", err)
		}
	}

	whereami := "localhost"
	if 0 < len(c.ServerName) {
		whereami = fmt.Sprintf("%s:%s", c.ServerName, c.Port)

	}
	if _, err := os.Stat(logDir); err == nil {
		path := fmt.Sprintf("%s/%s.log", logDir, whereami)
		log.Hooks.Add(lfshook.NewHook(lfshook.PathMap{
			logrus.DebugLevel: path,
			logrus.InfoLevel:  path,
			logrus.WarnLevel:  path,
			logrus.ErrorLevel: path,
			logrus.FatalLevel: path,
			logrus.PanicLevel: path,
		}))
	}

	fields := logrus.Fields{"prefix": whereami}
	return log.WithFields(fields)
}
