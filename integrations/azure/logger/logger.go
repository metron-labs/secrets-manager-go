package logger

import (
	"log"
	"os"
	"time"
)

// Logger interface defines the methods for logging at different levels.
type Logger interface {
	Info(message string, meta ...interface{})
	Warn(message string, meta ...interface{})
	Error(message string, meta ...interface{})
	Errorf(format string, args ...interface{})
	Debug(message string, meta ...interface{})
	Debugf(message string, meta ...interface{})
}

// DefaultLogger is the default implementation of the Logger interface.
type DefaultLogger struct {
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
}

// NewDefaultLogger creates a new instance of DefaultLogger.
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		infoLogger:  newCustomLogger(os.Stdout),
		warnLogger:  newCustomLogger(os.Stdout),
		errorLogger: newCustomLogger(os.Stderr),
		debugLogger: newCustomLogger(os.Stdout),
	}
}

func newCustomLogger(out *os.File) *log.Logger {
	return log.New(out, "", 0)
}

func formatLog(level, message string) string {
	timestamp := time.Now().Format("2006/01/02 15:04:05.000000")
	return timestamp + " " + level + ": " + message
}

// Info logs an informational message.
func (l *DefaultLogger) Info(message string, meta ...interface{}) {
	l.infoLogger.Println(formatLog("INFO", message))
}

// Warn logs a warning message.
func (l *DefaultLogger) Warn(message string, meta ...interface{}) {
	l.warnLogger.Println(formatLog("WARNING", message))
}

// Error logs an error message.
func (l *DefaultLogger) Error(message string, meta ...interface{}) {
	l.errorLogger.Println(formatLog("ERROR", message))
}

// Errorf logs a formatted error message.
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	l.errorLogger.Println(formatLog("ERROR", format))
}

// Debug logs a debug message.
func (l *DefaultLogger) Debug(message string, meta ...interface{}) {
	l.debugLogger.Println(formatLog("DEBUG", message))
}

// Debugf logs a debug message.
func (l *DefaultLogger) Debugf(message string, meta ...interface{}) {
	l.debugLogger.Println(formatLog("DEBUG", message))
}
