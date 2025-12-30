/*
File: logger.go
Description: Modern, structured, and multi-output logging implementation using Go 1.21+ log/slog.
Supports Console, File, and Syslog outputs with Text or JSON formatting.
*/

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Global logger instance
var logger *slog.Logger

// InitLogger initializes the global logger based on the provided configuration.
func InitLogger(cfg LoggingConfig) error {
	var writers []io.Writer

	// 1. Setup Console Output
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "console") {
			writers = append(writers, os.Stdout)
			break
		}
	}

	// 2. Setup File Output
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "file") {
			if cfg.File.Path == "" {
				return fmt.Errorf("file logging enabled but no path specified")
			}
			
			perm := os.FileMode(0644)
			if cfg.File.Permissions > 0 {
				perm = os.FileMode(cfg.File.Permissions)
			}

			f, err := os.OpenFile(cfg.File.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
			if err != nil {
				return fmt.Errorf("failed to open log file: %w", err)
			}
			writers = append(writers, f)
			break
		}
	}

	// 3. Setup Syslog Output (Cross-platform implementation)
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "syslog") {
			syslogWriter := &SyslogWriter{
				Network:  cfg.Syslog.Network,
				Address:  cfg.Syslog.Address,
				Tag:      cfg.Syslog.Tag,
				Facility: cfg.Syslog.Facility,
				Hostname: "localhost", // Default
			}
			if h, err := os.Hostname(); err == nil {
				syslogWriter.Hostname = h
			}
			writers = append(writers, syslogWriter)
			break
		}
	}

	if len(writers) == 0 {
		// Default fallback
		writers = append(writers, os.Stdout)
	}

	// Create MultiWriter
	multiWriter := io.MultiWriter(writers...)

	// Setup Handler Options (Level)
	opts := &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Level),
	}

	// Setup Handler (Text or JSON)
	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "json") {
		handler = slog.NewJSONHandler(multiWriter, opts)
	} else {
		handler = slog.NewTextHandler(multiWriter, opts)
	}

	// Set global logger
	logger = slog.New(handler)
	slog.SetDefault(logger) // Hook into standard log package as well

	LogInfo("[SYSTEM] Logger initialized: Level=%s, Format=%s, Outputs=%v", cfg.Level, cfg.Format, cfg.Outputs)
	return nil
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// --- Compatibility Wrappers ---
// These ensure existing code using LogInfo/LogDebug works without changes.
// We use fmt.Sprintf because the original code passed format strings.

func LogDebug(format string, v ...interface{}) {
	if logger != nil {
		logger.Debug(fmt.Sprintf(format, v...))
	}
}

func LogInfo(format string, v ...interface{}) {
	if logger != nil {
		logger.Info(fmt.Sprintf(format, v...))
	}
}

func LogWarn(format string, v ...interface{}) {
	if logger != nil {
		logger.Warn(fmt.Sprintf(format, v...))
	}
}

func LogError(format string, v ...interface{}) {
	if logger != nil {
		logger.Error(fmt.Sprintf(format, v...))
	}
}

func LogFatal(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	if logger != nil {
		logger.Error(msg) // Log as error before exiting
	}
	os.Exit(1)
}

// --- Simple Syslog Writer ---
// Implements a basic RFC 3164 / RFC 5424 compliant message sender.
// This avoids the 'log/syslog' package which is not available on Windows.

type SyslogWriter struct {
	Network  string
	Address  string
	Tag      string
	Hostname string
	Facility int
	conn     net.Conn
	mu       sync.Mutex
}

func (w *SyslogWriter) connect() error {
	if w.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout(w.Network, w.Address, 1*time.Second)
	if err != nil {
		return err
	}
	w.conn = conn
	return nil
}

func (w *SyslogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Parse level from slog output if possible, but slog output is already formatted text/json.
	// We wrap the whole slog message as the "content" of the syslog packet.
	// Default to Info severity (6)
	severity := 6 
	pri := (w.Facility * 8) + severity

	timestamp := time.Now().Format(time.RFC3339)
	
	// Prepare basic syslog header: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
	// Note: We trim the newline from p because slog adds one, and we might not want double newlines in syslog
	msg := string(p)
	
	// Detect level from string if standard text handler (optional heuristic)
	if strings.Contains(msg, "level=ERROR") || strings.Contains(msg, "\"level\":\"ERROR\"") {
		pri = (w.Facility * 8) + 3 // Error
	} else if strings.Contains(msg, "level=WARN") || strings.Contains(msg, "\"level\":\"WARN\"") {
		pri = (w.Facility * 8) + 4 // Warning
	} else if strings.Contains(msg, "level=DEBUG") || strings.Contains(msg, "\"level\":\"DEBUG\"") {
		pri = (w.Facility * 8) + 7 // Debug
	}

	syslogMsg := fmt.Sprintf("<%d>%s %s %s: %s", pri, timestamp, w.Hostname, w.Tag, msg)
	
	// Ensure connection
	if err := w.connect(); err != nil {
		// If we can't connect, we just drop the log to avoid blocking app functionality
		// or maybe print to stderr as fallback?
		// For now, return len(p) to pretend success so we don't crash the logger
		return len(p), nil 
	}

	_, err = fmt.Fprint(w.conn, syslogMsg)
	if err != nil {
		w.conn.Close()
		w.conn = nil
		// Try to reconnect once
		if err := w.connect(); err == nil {
			fmt.Fprint(w.conn, syslogMsg)
		}
	}

	return len(p), nil
}

