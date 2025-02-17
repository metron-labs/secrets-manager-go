package logger

import (
	"fmt"
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

// Global default logger instance
var defaultLogger = NewDefaultLogger()

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
func Info(message string, meta ...interface{}) {
	defaultLogger.infoLogger.Println(formatLog("INFO", fmt.Sprintf(message, meta...)))
}

// Warn logs a warning message.
func Warn(message string, meta ...interface{}) {
	defaultLogger.warnLogger.Println(formatLog("WARNING", message))
}

// Error logs an error message.
func Error(message string, meta ...interface{}) {
	defaultLogger.errorLogger.Println(formatLog("ERROR", message))
}

// Errorf logs a formatted error message.
func Errorf(message string, args ...interface{}) {
	defaultLogger.errorLogger.Println(formatLog("ERROR", fmt.Sprintf(message, args...)))
}

// Debug logs a debug message.
func Debug(message string, meta ...interface{}) {
	defaultLogger.debugLogger.Println(formatLog("DEBUG", message))
}

// Debugf logs a debug message.
func Debugf(message string, meta ...interface{}) {
	defaultLogger.debugLogger.Println(formatLog("DEBUG", message))
}
