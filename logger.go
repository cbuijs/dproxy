/*
File: logger.go
Description: Modern, structured, and multi-output logging implementation using Go 1.21+ log/slog.
Supports Console, File, and Syslog outputs.
UPDATED: Removed unused 'io' import.
*/

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Global logger instance
// Initialize with a default stderr logger so calls before InitLogger are not lost.
var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

// InitLogger initializes the global logger based on the provided configuration.
func InitLogger(cfg LoggingConfig) error {
	var handlers []slog.Handler

	// Common Options (Level)
	opts := &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Level),
	}

	// 1. Setup Console Output (Always Text)
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "console") {
			handlers = append(handlers, slog.NewTextHandler(os.Stderr, opts))
			break
		}
	}

	// 2. Setup File Output (JSON if configured, otherwise Text)
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

			if strings.EqualFold(cfg.Format, "json") {
				handlers = append(handlers, slog.NewJSONHandler(f, opts))
			} else {
				handlers = append(handlers, slog.NewTextHandler(f, opts))
			}
			break
		}
	}

	// 3. Setup Syslog Output (Always Text)
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
			// Syslog expects text lines, so we enforce TextHandler
			handlers = append(handlers, slog.NewTextHandler(syslogWriter, opts))
			break
		}
	}

	if len(handlers) == 0 {
		// Default fallback
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, opts))
	}

	// Create the final logger
	// If multiple handlers, wrap in MultiHandler
	var finalHandler slog.Handler
	if len(handlers) > 1 {
		finalHandler = &MultiHandler{handlers: handlers}
	} else {
		finalHandler = handlers[0]
	}

	logger = slog.New(finalHandler)
	slog.SetDefault(logger) // Hook into standard log package as well

	LogInfo("[SYSTEM] Logger initialized: Level=%s, FileFormat=%s, Outputs=%v", cfg.Level, cfg.Format, cfg.Outputs)
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

// --- MultiHandler Implementation ---
// Allows dispatching log records to multiple handlers (e.g. JSON to file, Text to console)

type MultiHandler struct {
	handlers []slog.Handler
}

func (m *MultiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return errs[0] // Return first error, though we try to run all
	}
	return nil
}

func (m *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: handlers}
}

func (m *MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &MultiHandler{handlers: handlers}
}

// --- Compatibility Wrappers ---

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
	// Support "unixgram" for /dev/log
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

	severity := 6 // Info
	pri := (w.Facility * 8) + severity

	timestamp := time.Now().Format(time.RFC3339)
	
	// Trim newline from slog text handler to avoid double spacing in syslog
	msg := strings.TrimSuffix(string(p), "\n")
	
	if strings.Contains(msg, "level=ERROR") || strings.Contains(msg, "\"level\":\"ERROR\"") {
		pri = (w.Facility * 8) + 3 // Error
	} else if strings.Contains(msg, "level=WARN") || strings.Contains(msg, "\"level\":\"WARN\"") {
		pri = (w.Facility * 8) + 4 // Warning
	} else if strings.Contains(msg, "level=DEBUG") || strings.Contains(msg, "\"level\":\"DEBUG\"") {
		pri = (w.Facility * 8) + 7 // Debug
	}

	syslogMsg := fmt.Sprintf("<%d>%s %s %s: %s", pri, timestamp, w.Hostname, w.Tag, msg)
	
	if err := w.connect(); err != nil {
		return len(p), nil 
	}

	_, err = fmt.Fprint(w.conn, syslogMsg)
	if err != nil {
		w.conn.Close()
		w.conn = nil
		if err := w.connect(); err == nil {
			fmt.Fprint(w.conn, syslogMsg)
		}
	}

	return len(p), nil
}

