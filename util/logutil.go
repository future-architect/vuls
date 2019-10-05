package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"

	"github.com/future-architect/vuls/config"
	formatter "github.com/kotakanbe/logrus-prefixed-formatter"
)

// Log for localhsot
var Log *logrus.Entry

func init() {
	log := logrus.New()
	log.Out = ioutil.Discard
	fields := logrus.Fields{"prefix": ""}
	Log = log.WithFields(fields)
}

// NewCustomLogger creates logrus
func NewCustomLogger(c config.ServerInfo) *logrus.Entry {
	log := logrus.New()
	log.Formatter = &formatter.TextFormatter{MsgAnsiColor: c.LogMsgAnsiColor}
	log.Level = logrus.InfoLevel
	if config.Conf.Debug {
		log.Level = logrus.DebugLevel
	}

	// File output
	logDir := GetDefaultLogDir()
	if 0 < len(config.Conf.LogDir) {
		logDir = config.Conf.LogDir
	}

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.Mkdir(logDir, 0700); err != nil {
			log.Errorf("Failed to create log directory. path: %s, err: %s", logDir, err)
		}
	}

	// Only log to a file if quiet mode enabled
	if config.Conf.Quiet {
		logFile := logDir + "/vuls.log"
		if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			log.Out = file
		} else {
			log.Errorf("Failed to create log file. path: %s, err: %s", logFile, err)
		}
	} else {
		log.Out = os.Stderr
	}

	whereami := "localhost"
	if 0 < len(c.ServerName) {
		whereami = c.GetServerName()
	}

	if _, err := os.Stat(logDir); err == nil {
		path := filepath.Join(logDir, fmt.Sprintf("%s.log", whereami))
		log.Hooks.Add(lfshook.NewHook(lfshook.PathMap{
			logrus.DebugLevel: path,
			logrus.InfoLevel:  path,
			logrus.WarnLevel:  path,
			logrus.ErrorLevel: path,
			logrus.FatalLevel: path,
			logrus.PanicLevel: path,
		}, nil))
	}

	fields := logrus.Fields{"prefix": whereami}
	return log.WithFields(fields)
}

// GetDefaultLogDir returns default log directory
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/vuls"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "vuls")
	}
	return defaultLogDir
}
