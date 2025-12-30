/*
File: main.go
Description: Entry point for the dproxy application. Initializes globals, parses flags, and starts the system.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// --- Globals & Pools ---

var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}

// OPTIMIZATION: Message pool to reduce GC pressure
var msgPool = sync.Pool{
	New: func() any {
		return new(dns.Msg)
	},
}

// Helper to get a clean message
func getMsg() *dns.Msg {
	m := msgPool.Get().(*dns.Msg)
	// Completely reset the message to reuse the struct
	// We preserve the underlying slice capacity to reduce future allocations
	m.MsgHdr = dns.MsgHdr{}
	m.Compress = false
	m.Question = m.Question[:0]
	m.Answer = m.Answer[:0]
	m.Ns = m.Ns[:0]
	m.Extra = m.Extra[:0]
	return m
}

// Helper to free a message
func putMsg(m *dns.Msg) {
	if m == nil {
		return
	}
	// Clear potential references to help GC before pooling
	// Note: We don't nil the slices, just reset length in getMsg
	msgPool.Put(m)
}

// Global configuration instance
var config *Config

// Bootstrap DNS servers used for resolving upstream hostnames
var bootstrapServers []string

// Round-robin counter for load balancing
var rrCounter atomic.Uint64

// Singleflight group for coalescing identical requests
var requestGroup singleflight.Group

// Shutdown coordination
var (
	shutdownContext context.Context
	shutdownCancel  context.CancelFunc
	shutdownWg      sync.WaitGroup
)

// --- Flags ---

var (
	configFile = flag.String("config", "", "Path to configuration file (YAML)")
)

// --- Main ---

func main() {
	flag.Usage = func() {
		const usage = `High-Performance Multi-Protocol DNS Proxy

Usage: %s -config <config.yaml>
`
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *configFile == "" {
		log.Fatal("Error: -config flag is required.")
	}

	// Load configuration
	if err := LoadConfig(*configFile); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Initialize Logger with modern configuration
	if err := InitLogger(config.Logging); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Log configuration summary after logger is ready
	// We also log the loaded rules which happens inside LoadConfig, 
	// but since InitLogger is called after, we might miss the very first messages from LoadConfig.
	// To fix this cleanly without circular deps, we just re-log critical start info here.
	LogInfo("Configuration loaded successfully from %s", *configFile)

	// Initialize shutdown context
	shutdownContext, shutdownCancel = context.WithCancel(context.Background())

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start background maintenance routines
	startBackgroundTasks()

	// Setup TLS
	tlsConfig, err := getTLSConfig(config.Server.TLS.CertFile, config.Server.TLS.KeyFile, config.Server.ListenAddr)
	if err != nil {
		LogFatal("Failed to setup TLS: %v", err)
	}

	// Start Servers
	serverWg := &sync.WaitGroup{}
	servers := startServers(serverWg, tlsConfig)

	// Wait for shutdown signal
	sig := <-sigChan
	LogInfo("Received signal: %v - initiating graceful shutdown...", sig)

	// Trigger graceful shutdown
	gracefulShutdown(servers)

	// Wait for all servers to stop
	serverWg.Wait()
	LogInfo("All servers stopped")

	// Cancel background tasks
	shutdownCancel()

	// Wait for background tasks to finish
	shutdownWg.Wait()
	LogInfo("All background tasks stopped")

	LogInfo("Shutdown complete")
}

// startBackgroundTasks starts all background maintenance routines
func startBackgroundTasks() {
	// ARP cache maintenance
	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		maintainARPCache(shutdownContext)
	}()

	// DoQ connection pool cleanup
	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		doqPool.cleanup(shutdownContext)
	}()

	// DNS cache maintenance
	if config.Cache.Enabled {
		LogInfo("Caching: Enabled")
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			maintainDNSCache(shutdownContext)
		}()
	} else {
		LogInfo("Caching: Disabled")
	}
}

// gracefulShutdown performs graceful shutdown of all servers
func gracefulShutdown(servers []ServerShutdowner) {
	LogInfo("Stopping all listeners...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Shutdown all servers concurrently
	for i, srv := range servers {
		if srv != nil {
			wg.Add(1)
			go func(index int, server ServerShutdowner) {
				defer wg.Done()
				if err := server.Shutdown(ctx); err != nil {
					LogError("Error shutting down server %d: %v", index, err)
				} else {
					LogInfo("Server %d shut down successfully", index)
				}
			}(i, srv)
		}
	}

	// Wait for all servers to shutdown or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		LogInfo("All servers shut down gracefully")
	case <-ctx.Done():
		LogInfo("Shutdown timeout reached - forcing exit")
	}
}

