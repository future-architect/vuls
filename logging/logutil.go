package logging

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/k0kubun/pp"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"

	formatter "github.com/kotakanbe/logrus-prefixed-formatter"
)

//LogOpts has options for logging
type LogOpts struct {
	Debug     bool   `json:"debug,omitempty"`
	DebugSQL  bool   `json:"debugSQL,omitempty"`
	LogToFile bool   `json:"logToFile,omitempty"`
	LogDir    string `json:"logDir,omitempty"`
	Quiet     bool   `json:"quiet,omitempty"`
}

// Log for localhost
var Log Logger

// Logger has logrus entry
type Logger struct {
	logrus.Entry
}

func init() {
	log := logrus.New()
	log.Out = ioutil.Discard
	fields := logrus.Fields{"prefix": ""}
	Log = Logger{Entry: *log.WithFields(fields)}
}

// NewNormalLogger creates normal logger
func NewNormalLogger() Logger {
	return Logger{Entry: logrus.Entry{Logger: logrus.New()}}
}

// NewCustomLogger creates logrus
func NewCustomLogger(debug, quiet, logToFile bool, logDir, logMsgAnsiColor, serverName string) Logger {
	log := logrus.New()
	log.Formatter = &formatter.TextFormatter{MsgAnsiColor: logMsgAnsiColor}
	log.Level = logrus.InfoLevel
	if debug {
		log.Level = logrus.DebugLevel
		pp.ColoringEnabled = false
	}

	if flag.Lookup("test.v") != nil {
		return Logger{Entry: *logrus.NewEntry(log)}
	}

	whereami := "localhost"
	if serverName != "" {
		whereami = serverName
	}

	if logToFile {
		dir := GetDefaultLogDir()
		if logDir != "" {
			dir = logDir
		}

		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.Mkdir(dir, 0700); err != nil {
				log.Errorf("Failed to create log directory. path: %s, err: %+v", dir, err)
			}
		}

		logFile := dir + "/vuls.log"
		if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			log.Out = io.MultiWriter(os.Stderr, file)
		} else {
			log.Out = os.Stderr
			log.Errorf("Failed to create log file. path: %s, err: %+v", logFile, err)
		}

		if _, err := os.Stat(dir); err == nil {
			path := filepath.Join(dir, fmt.Sprintf("%s.log", whereami))
			if _, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				log.Hooks.Add(lfshook.NewHook(lfshook.PathMap{
					logrus.DebugLevel: path,
					logrus.InfoLevel:  path,
					logrus.WarnLevel:  path,
					logrus.ErrorLevel: path,
					logrus.FatalLevel: path,
					logrus.PanicLevel: path,
				}, nil))
			} else {
				log.Errorf("Failed to create log file. path: %s, err: %+v", path, err)
			}
		}
	} else if quiet {
		log.Out = ioutil.Discard
	} else {
		log.Out = os.Stderr
	}

	entry := log.WithFields(logrus.Fields{"prefix": whereami})
	return Logger{Entry: *entry}
}

// GetDefaultLogDir returns default log directory
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/vuls"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "vuls")
	}
	return defaultLogDir
}
