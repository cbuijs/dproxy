/*
File: arp.go
Version: 3.0.0 (Common)
Description: Common definitions, structs, and helpers for ARP/NDP management.
             Platform-specific implementations (maintainARPCache) are in arp_linux.go and arp_others.go.
*/

package main

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// --- Constants & Regex ---

var (
	// Windows: 192.168.1.1   00-11-22-33-44-55   dynamic
	windowsARPRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})`)

	// macOS/BSD: ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
	darwinARPRegex = regexp.MustCompile(`\((.*?)\) at ([0-9a-fA-F:]+)`)
)

// --- Structs ---

type ARPCache struct {
	sync.RWMutex
	table map[string]net.HardwareAddr
}

// --- Globals ---

var (
	arpCache      = &ARPCache{table: make(map[string]net.HardwareAddr)}
	lastARPAccess atomic.Int64 // Unix nano timestamp of last cache access
)

// --- Shared Public API ---

// getMacFromCache retrieves the MAC address for a given IP from the cache.
// It is thread-safe and non-blocking (RLock only).
// OPTIMIZED: Returns nil immediately for invalid candidates (localhost, etc).
func getMacFromCache(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}

	// Fast Path: Skip IPs that never have MACs
	if !IsValidARPCandidate(ip) {
		return nil
	}

	// Update access timestamp for smart refresh logic (mostly used by polling impl)
	lastARPAccess.Store(time.Now().UnixNano())

	arpCache.RLock()
	defer arpCache.RUnlock()
	return arpCache.table[ip.String()]
}

// --- Helpers ---

// runCommand executes a command with a strict timeout context
// Used by Windows/Darwin implementations
func runCommand(parentCtx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

