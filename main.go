/*
File: main.go
Description: Entry point for the dproxy application. Initializes globals, parses flags, and starts the system.
             UPDATED: Starts auto-refresh routines for all configured HOSTS files.
             UPDATED: Smart ARP maintenance (skips if configured "none" or not required by any rules).
             UPDATED: Correctly flattens multiple listener IPs for TLS certificate generation.
             UPDATED: Auto-detects DDR hostname from certificate if not configured.
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

	LogInfo("Configuration loaded successfully from %s", *configFile)

	// Initialize shutdown context
	shutdownContext, shutdownCancel = context.WithCancel(context.Background())

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start background maintenance routines
	startBackgroundTasks()

	// --- START HOSTS FILE REFRESHERS ---
	// Strategy: If URLs are present, use a long interval (1h) to be polite.
	// If only local files are used, use a short interval (30s) for rapid dev feedback.
	
	// Check Default Rule
	if config.Routing.DefaultRule.parsedHosts != nil {
		interval := 30 * time.Second
		if config.Routing.DefaultRule.parsedHosts.HasRemote() {
			interval = 1 * time.Hour
		}
		
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			config.Routing.DefaultRule.parsedHosts.StartAutoRefresh(shutdownContext, interval)
		}()
	}
	
	// Check specific Routing Rules
	for i := range config.Routing.RoutingRules {
		rule := &config.Routing.RoutingRules[i]
		if rule.parsedHosts != nil {
			interval := 30 * time.Second
			if rule.parsedHosts.HasRemote() {
				interval = 1 * time.Hour
			}

			shutdownWg.Add(1)
			go func(hc *HostsCache) {
				defer shutdownWg.Done()
				hc.StartAutoRefresh(shutdownContext, interval)
			}(rule.parsedHosts)
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
	// If DDR is enabled but no hostname is configured, try to extract it from the certificate.
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
}

// isARPRequired checks if ARP is actually needed by the configuration.
// It returns true if ARP is enabled AND at least one rule uses MAC matching
// OR if EDNS0 MAC addition is enabled.
func isARPRequired() bool {
	if config.ARP.Mode == "none" {
		return false
	}

	// Check EDNS0 MAC settings
	// If mode is 'add', 'replace', or 'prefer-arp', we need ARP data to add it to the packet.
	macMode := config.Server.EDNS0.MAC.Mode
	if macMode == "add" || macMode == "replace" || macMode == "prefer-arp" {
		return true
	}

	// Check Routing Rules
	for _, rule := range config.Routing.RoutingRules {
		if len(rule.Match.ClientMAC) > 0 {
			return true
		}
		if len(rule.Match.ClientEDNSMAC) > 0 {
			// EDNS0 MAC is inside the packet, but we might want ARP to verify? 
			// Actually ClientEDNSMAC matching relies on the packet, not ARP.
			// But for safety, let's assume strict ARP isn't needed *just* for EDNS0 MAC matching
			// unless we are validating it against ARP (which we don't do explicitly here).
			// So this case alone doesn't strictly require ARP.
		}
	}

	// Default to false if no specific need found
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

