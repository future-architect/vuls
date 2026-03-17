package logging

import (
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestFileHookLevels(t *testing.T) {
	h := &fileHook{
		path:      "/dev/null",
		formatter: &logrus.TextFormatter{},
	}
	got := h.Levels()
	if len(got) != len(logrus.AllLevels) {
		t.Errorf("Levels() returned %d levels, want %d", len(got), len(logrus.AllLevels))
	}
	for i, l := range logrus.AllLevels {
		if got[i] != l {
			t.Errorf("Levels()[%d] = %v, want %v", i, got[i], l)
		}
	}
}

func TestFileHookFire(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "filehook-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	h := &fileHook{
		path:      tmpFile.Name(),
		formatter: &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true},
	}

	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Level:   logrus.InfoLevel,
		Message: "hello from fire",
		Data:    logrus.Fields{},
	}

	if err := h.Fire(entry); err != nil {
		t.Fatalf("Fire() returned error: %v", err)
	}

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(content), "hello from fire") {
		t.Errorf("log file does not contain expected message, got: %q", string(content))
	}
}

func TestFileHookFireAppends(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "filehook-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	h := &fileHook{
		path:      tmpFile.Name(),
		formatter: &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true},
	}

	for i, msg := range []string{"first message", "second message", "third message"} {
		entry := &logrus.Entry{
			Logger:  logrus.New(),
			Level:   logrus.InfoLevel,
			Message: msg,
			Data:    logrus.Fields{},
		}
		if err := h.Fire(entry); err != nil {
			t.Fatalf("Fire() call %d returned error: %v", i, err)
		}
	}

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	s := string(content)
	for _, msg := range []string{"first message", "second message", "third message"} {
		if !strings.Contains(s, msg) {
			t.Errorf("log file missing %q, got: %q", msg, s)
		}
	}
}

func TestFileHookIntegration(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "filehook-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	logger := logrus.New()
	logger.Out = os.Stderr
	logger.Level = logrus.DebugLevel

	logger.Hooks.Add(&fileHook{
		path:      tmpFile.Name(),
		formatter: &logrus.TextFormatter{DisableColors: true, DisableTimestamp: true},
	})

	logger.Info("integration info message")
	logger.Warn("integration warn message")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "integration info message") {
		t.Errorf("log file missing info message, got: %q", s)
	}
	if !strings.Contains(s, "integration warn message") {
		t.Errorf("log file missing warn message, got: %q", s)
	}
}
