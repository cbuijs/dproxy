/*
File: main.go
Version: 1.8.1
Description: Entry point for the dproxy application. Initializes globals, parses flags, and starts the system.
             UPDATED: Removed duplicate requestGroup declaration (moved to process.go).
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// --- Globals & Pools ---

// OPTIMIZATION: Buffer pool resized to 65535 (Max DNS size over TCP) to prevent
// truncation or packing errors for large responses (DNSSEC, TXT, etc).
var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 65535)
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
	msgPool.Put(m)
}

// Global configuration instance
var config *Config

// Bootstrap DNS servers used for resolving upstream hostnames
var bootstrapServers []string

// Round-robin counter for load balancing
var rrCounter atomic.Uint64

// Note: requestGroup is now defined in process.go as a ShardedGroup

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

	LogInfo("Configuration loaded successfully from %s", *configFile)

	// Initialize shutdown context
	shutdownContext, shutdownCancel = context.WithCancel(context.Background())

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize Rate Limiter
	InitLimiter(config.RateLimit)

	// Start background maintenance routines
	startBackgroundTasks()

	// --- START HOSTS FILE REFRESHERS ---

	// Helper to determine interval
	getInterval := func(configured time.Duration, hasRemote bool) time.Duration {
		if configured > 0 {
			return configured
		}
		if hasRemote {
			return 1 * time.Hour
		}
		return 30 * time.Second
	}

	// Check Default Rule
	if config.Routing.DefaultRule.parsedHosts != nil {
		hc := config.Routing.DefaultRule.parsedHosts
		// Assign cache dir to the instance so it can be used for reloading
		hc.cacheDir = config.Cache.HostsCacheDir

		interval := getInterval(config.Routing.DefaultRule.parsedRefresh, hc.HasRemote())

		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			hc.StartAutoRefresh(shutdownContext, interval)
		}()
	}

	// Check specific Routing Rules
	for i := range config.Routing.RoutingRules {
		rule := &config.Routing.RoutingRules[i]
		if rule.parsedHosts != nil {
			hc := rule.parsedHosts
			hc.cacheDir = config.Cache.HostsCacheDir

			interval := getInterval(rule.parsedRefresh, hc.HasRemote())

			shutdownWg.Add(1)
			go func(h *HostsCache) {
				defer shutdownWg.Done()
				h.StartAutoRefresh(shutdownContext, interval)
			}(hc)
		}
	}

	// Collect all listener IPs for TLS certificate generation
	var listenIPs []string
	for _, l := range config.Server.Listeners {
		// Flatten the slice of addresses
		listenIPs = append(listenIPs, l.Address...)
	}

	// Setup TLS
	tlsConfig, err := getTLSConfig(config.Server.TLS.CertFile, config.Server.TLS.KeyFile, listenIPs)
	if err != nil {
		LogFatal("Failed to setup TLS: %v", err)
	}

	// --- DDR Hostname Auto-Detection ---
	if config.Server.DDR.Enabled && config.Server.DDR.HostName == "" && len(tlsConfig.Certificates) > 0 {
		extracted := ExtractDNSNameFromCert(&tlsConfig.Certificates[0])
		if extracted != "" {
			config.Server.DDR.HostName = extracted
			LogInfo("[DDR] Auto-detected hostname from certificate: %s", extracted)
		}
	}

	// Ensure DDR hostname is fully qualified (ends with a dot)
	if config.Server.DDR.HostName != "" && !strings.HasSuffix(config.Server.DDR.HostName, ".") {
		config.Server.DDR.HostName += "."
	}

	// Start Servers
	serverWg := &sync.WaitGroup{}
	servers := startServers(serverWg, tlsConfig)

	// Wait for shutdown signal
	sig := <-sigChan
	LogInfo("Received signal: %v - initiating graceful shutdown...", sig)

	// Cancel context first to signal all background tasks
	shutdownCancel()

	// Trigger graceful shutdown
	gracefulShutdown(servers)

	// Wait for all servers to stop
	serverWg.Wait()
	LogInfo("All servers stopped")

	// Wait for background tasks to finish
	shutdownWg.Wait()
	LogInfo("All background tasks stopped")

	LogInfo("Shutdown complete")
}

// startBackgroundTasks starts all background maintenance routines
func startBackgroundTasks() {
	// Rate Limiter Cleanup
	if config.RateLimit.Enabled {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			GlobalLimiter.StartCleanupRoutine(shutdownContext)
		}()
	}

	// ARP cache maintenance
	if isARPRequired() {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			maintainARPCache(shutdownContext)
		}()
	} else {
		LogInfo("[ARP] Maintenance disabled (Mode: %s or not required by rules)", config.ARP.Mode)
	}

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

	// ML Guard Dynamic Tuner
	if config.MLGuard.Enabled && strings.ToLower(config.MLGuard.AutoThreshold) == "on" {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			GlobalMLGuard.StartDynamicTuner(shutdownContext)
		}()
	}
}

// isARPRequired checks if ARP is actually needed by the configuration.
func isARPRequired() bool {
	if config.ARP.Mode == "none" {
		return false
	}

	macMode := config.Server.EDNS0.MAC.Mode
	if macMode == "add" || macMode == "replace" || macMode == "prefer-arp" {
		return true
	}

	for _, rule := range config.Routing.RoutingRules {
		if len(rule.Match.ClientMAC) > 0 {
			return true
		}
	}

	return false
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
					LogError("Error shutting down server [%s]: %v", server.String(), err)
				} else {
					LogInfo("Server [%s] shut down successfully", server.String())
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

