/*
File: logger.go
Description: Simple leveled logging implementation for dproxy.
*/

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	currentLogLevel LogLevel = LevelInfo
	logMu           sync.Mutex
)

// SetLogLevel sets the global logging level based on a string (debug, info, warn, error)
func SetLogLevel(level string) {
	logMu.Lock()
	defer logMu.Unlock()

	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		currentLogLevel = LevelDebug
	case "INFO":
		currentLogLevel = LevelInfo
	case "WARN":
		currentLogLevel = LevelWarn
	case "ERROR":
		currentLogLevel = LevelError
	default:
		// Default to INFO if unknown
		currentLogLevel = LevelInfo
	}
	// Use standard log package for this system message
	log.Printf("[SYSTEM] Log level set to %v", strings.ToUpper(level))
}

func LogDebug(format string, v ...interface{}) {
	if currentLogLevel <= LevelDebug {
		output("DEBUG", format, v...)
	}
}

func LogInfo(format string, v ...interface{}) {
	if currentLogLevel <= LevelInfo {
		output("INFO", format, v...)
	}
}

func LogWarn(format string, v ...interface{}) {
	if currentLogLevel <= LevelWarn {
		output("WARN", format, v...)
	}
}

func LogError(format string, v ...interface{}) {
	if currentLogLevel <= LevelError {
		output("ERROR", format, v...)
	}
}

func LogFatal(format string, v ...interface{}) {
	output("FATAL", format, v...)
	os.Exit(1)
}

func output(level, format string, v ...interface{}) {
	// The standard "log" package handles timestamp and thread safety for the write itself.
	// We just format the message with the level prefix.
	msg := fmt.Sprintf(format, v...)
	log.Printf("[%s] %s", level, msg)
}

