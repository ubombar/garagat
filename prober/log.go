package prober

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log level.
type Level int

// Log levels, as in caracal (spdlog).
const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarning
	LevelError
	LevelFatal
	LevelOff
)

var levelNames = [...]string{"trace", "debug", "info", "warning", "error", "critical", "off"}

func (l Level) String() string { return levelNames[l] }

// ParseLevel parses trace, debug, info, warning (warn), error, fatal
// (critical) or off.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warning", "warn":
		return LevelWarning, nil
	case "error", "err":
		return LevelError, nil
	case "fatal", "critical":
		return LevelFatal, nil
	case "off":
		return LevelOff, nil
	}
	return 0, fmt.Errorf("invalid log level: %s", s)
}

// Logger writes spdlog-like lines: "[2006-01-02 15:04:05.000] [info] msg".
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	level Level
}

// NewLogger returns a logger writing to w.
func NewLogger(w io.Writer, level Level) *Logger {
	return &Logger{w: w, level: level}
}

// DefaultLogger logs at info level to stderr.
func DefaultLogger() *Logger { return NewLogger(os.Stderr, LevelInfo) }

// Enabled reports whether messages at this level are logged.
func (l *Logger) Enabled(level Level) bool { return l != nil && level >= l.level }

// Logf logs a message.
func (l *Logger) Logf(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), level, msg)
}

func (l *Logger) Tracef(format string, args ...any) { l.Logf(LevelTrace, format, args...) }
func (l *Logger) Debugf(format string, args ...any) { l.Logf(LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.Logf(LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.Logf(LevelWarning, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.Logf(LevelError, format, args...) }
