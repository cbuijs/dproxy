/*
File: main.go
Description: Entry point for the dproxy application. Initializes globals, parses flags, and starts the system.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

// --- Globals & Pools ---

var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}

// Global configuration instance
var config *Config

// Bootstrap DNS servers used for resolving upstream hostnames
var bootstrapServers []string

// Round-robin counter for load balancing
var rrCounter atomic.Uint64

// Request Group for singleflight (coalescing identical requests)
var requestGroup RequestGroup

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

	// Start background maintenance routines
	go maintainARPCache()
	go doqPool.cleanup()

	if config.Cache.Enabled {
		log.Println("Caching: Enabled")
		go maintainDNSCache()
	} else {
		log.Println("Caching: Disabled")
	}

	// Setup TLS
	tlsConfig, err := getTLSConfig(config.Server.TLS.CertFile, config.Server.TLS.KeyFile, config.Server.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	// Start Servers
	var wg sync.WaitGroup
	startServers(&wg, tlsConfig)
	wg.Wait()
}

