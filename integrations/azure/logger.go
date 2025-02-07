package keyvault_azure

import (
	"log"
	"os"
)

type Logger interface {
	Info(message string, meta ...interface{})
	Warn(message string, meta ...interface{})
	Error(message string, meta ...interface{})
	Debug(message string, meta ...interface{})
}

type defaultLogger struct {
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
}

func (l *defaultLogger) Info(message string, meta ...interface{}) {
	l.infoLogger.Printf("[INFO] "+message, meta...)
}

func (l *defaultLogger) Warn(message string, meta ...interface{}) {
	l.warnLogger.Printf("[WARN] "+message, meta...)
}

func (l *defaultLogger) Error(message string, meta ...interface{}) {
	l.errorLogger.Printf("[ERROR] "+message, meta...)
}

func (l *defaultLogger) Debug(message string, meta ...interface{}) {
	l.debugLogger.Printf("[DEBUG] "+message, meta...)
}

var DefaultLogger Logger = &defaultLogger{
	infoLogger:  log.New(os.Stdout, "", log.LstdFlags),
	warnLogger:  log.New(os.Stdout, "", log.LstdFlags),
	errorLogger: log.New(os.Stderr, "", log.LstdFlags),
	debugLogger: log.New(os.Stderr, "", log.LstdFlags),
}
