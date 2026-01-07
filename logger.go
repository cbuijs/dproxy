/*
File: logger.go
Version: 1.4.0
Last Update: 2026-01-07
Description: Modern, structured, and multi-output logging implementation using Go 1.21+ log/slog.
             OPTIMIZED: Implemented Asynchronous Buffered Logging to remove I/O blocking from the hot path.
             OPTIMIZED: Added IsLevelEnabled helpers to prevent expensive string formatting in hot paths when logging is disabled.
             UPDATED: Log entries are now processed by a background worker.
*/

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Global logger instance
// Initialize with a default stderr logger so calls before InitLogger are not lost.
var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

// Cached level for fast checks
var currentLevel slog.Level = slog.LevelInfo

// Async Logger Internals
var (
	logBuffer  chan slog.Record
	logWg      sync.WaitGroup
	logDone    chan struct{}
	asyncReady bool
)

const logBufferSize = 4096 // Buffer up to 4k logs before blocking/dropping

// InitLogger initializes the global logger based on the provided configuration.
func InitLogger(cfg LoggingConfig) error {
	var handlers []slog.Handler

	lvl := parseLogLevel(cfg.Level)
	currentLevel = lvl

	// Common Options (Level)
	opts := &slog.HandlerOptions{
		Level: lvl,
	}

	// Syslog Options
	syslogOpts := &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{} // Drop the time key for syslog as it adds its own
			}
			return a
		},
	}

	// 1. Setup Console Output
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "console") {
			handlers = append(handlers, slog.NewTextHandler(os.Stderr, opts))
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

			if strings.EqualFold(cfg.Format, "json") {
				handlers = append(handlers, slog.NewJSONHandler(f, opts))
			} else {
				handlers = append(handlers, slog.NewTextHandler(f, opts))
			}
			break
		}
	}

	// 3. Setup Syslog Output
	for _, output := range cfg.Outputs {
		if strings.EqualFold(output, "syslog") {
			syslogWriter := &SyslogWriter{
				Network:  cfg.Syslog.Network,
				Address:  cfg.Syslog.Address,
				Tag:      cfg.Syslog.Tag,
				Facility: cfg.Syslog.Facility,
				Hostname: "localhost",
			}
			if h, err := os.Hostname(); err == nil {
				syslogWriter.Hostname = h
			}
			handlers = append(handlers, slog.NewTextHandler(syslogWriter, syslogOpts))
			break
		}
	}

	if len(handlers) == 0 {
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, opts))
	}

	// Create the underlying handler (MultiHandler)
	var finalHandler slog.Handler
	if len(handlers) > 1 {
		finalHandler = &MultiHandler{handlers: handlers}
	} else {
		finalHandler = handlers[0]
	}

	// Wrap in AsyncHandler
	logBuffer = make(chan slog.Record, logBufferSize)
	logDone = make(chan struct{})
	asyncHandler := &AsyncHandler{
		handler: finalHandler,
		buffer:  logBuffer,
	}

	// Start Background Worker
	logWg.Add(1)
	go func() {
		defer logWg.Done()
		processLogs(finalHandler)
	}()
	asyncReady = true

	logger = slog.New(asyncHandler)
	slog.SetDefault(logger)

	// We can't log using the system yet inside init essentially, but we try
	// Use direct fmt to ensure visibility during startup
	fmt.Printf("[SYSTEM] Logger initialized: Level=%s, Buffer=%d\n", cfg.Level, logBufferSize)
	return nil
}

// processLogs runs in a background goroutine to consume logs
func processLogs(h slog.Handler) {
	ctx := context.Background()
	for {
		select {
		case record := <-logBuffer:
			_ = h.Handle(ctx, record)
		case <-logDone:
			// Drain buffer
			close(logBuffer)
			for record := range logBuffer {
				_ = h.Handle(ctx, record)
			}
			return
		}
	}
}

// ShutdownLogger flushes remaining logs
func ShutdownLogger() {
	if asyncReady {
		close(logDone)
		logWg.Wait()
	}
}

// AsyncHandler wraps a slog.Handler and pushes to a channel
type AsyncHandler struct {
	handler slog.Handler
	buffer  chan slog.Record
}

func (h *AsyncHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.handler.Enabled(ctx, l)
}

func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	select {
	case h.buffer <- r:
		return nil
	default:
		// Buffer full - drop log to prevent blocking the DNS server
		// In a real production system, you might increment a "dropped_logs" metric
		return nil
	}
}

func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AsyncHandler{handler: h.handler.WithAttrs(attrs), buffer: h.buffer}
}

func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &AsyncHandler{handler: h.handler.WithGroup(name), buffer: h.buffer}
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
	// Loop handles all outputs serially (but in background goroutine now)
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return errs[0]
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

// --- Level Checks (Performance Optimization) ---

func IsDebugEnabled() bool {
	return currentLevel <= slog.LevelDebug
}

func IsInfoEnabled() bool {
	return currentLevel <= slog.LevelInfo
}

// --- Compatibility Wrappers ---

// Helper to get PC for caller
func logWithCaller(level slog.Level, format string, v ...interface{}) {
	if logger == nil {
		return
	}
	// Fast check to avoid expensive Sprintf if disabled
	if !logger.Enabled(context.Background(), level) {
		return
	}
	
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // Skip logWithCaller, Wrapper, Caller
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, v...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

func LogDebug(format string, v ...interface{}) {
	logWithCaller(slog.LevelDebug, format, v...)
}

func LogInfo(format string, v ...interface{}) {
	logWithCaller(slog.LevelInfo, format, v...)
}

func LogWarn(format string, v ...interface{}) {
	logWithCaller(slog.LevelWarn, format, v...)
}

func LogError(format string, v ...interface{}) {
	logWithCaller(slog.LevelError, format, v...)
}

func LogFatal(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	if logger != nil {
		logger.Error(msg)
		// Ensure flush on fatal
		ShutdownLogger()
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

	severity := 6 
	timestamp := time.Now().Format(time.RFC3339)
	msg := strings.TrimSuffix(string(p), "\n")

	if strings.Contains(msg, "level=ERROR") {
		severity = 3
		msg = strings.Replace(msg, "level=ERROR", "", 1)
	} else if strings.Contains(msg, "level=WARN") {
		severity = 4
		msg = strings.Replace(msg, "level=WARN", "", 1)
	} else if strings.Contains(msg, "level=DEBUG") {
		severity = 7
		msg = strings.Replace(msg, "level=DEBUG", "", 1)
	} else if strings.Contains(msg, "level=INFO") {
		severity = 6
		msg = strings.Replace(msg, "level=INFO", "", 1)
	}
	
	msg = strings.TrimSpace(msg)
	pri := (w.Facility * 8) + severity
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

