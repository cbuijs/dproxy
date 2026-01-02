/*
File: arp.go
Version: 2.7.4
Description: Thread-safe, non-blocking ARP and NDP table manager.
             Handles resolving IPv4 and IPv6 addresses to MAC addresses by parsing system command output.
             Uses concurrent execution for separate IPv4/IPv6 commands and enforces timeouts.
             UPDATED: Configurable IP versions (v4/v6/both/none).
             OPTIMIZED: Skips lookups for invalid ARP candidates (localhost, multicast, etc).
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Constants & Regex ---

var (
	// Windows: 192.168.1.1   00-11-22-33-44-55   dynamic
	windowsARPRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})`)
	
	// macOS/BSD: ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
	darwinARPRegex  = regexp.MustCompile(`\((.*?)\) at ([0-9a-fA-F:]+)`)
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

// --- Public API ---

// maintainARPCache runs the background loop to keep the ARP table fresh.
// It uses a "smart refresh" strategy to avoid wasting CPU when the proxy is idle.
func maintainARPCache(ctx context.Context) {
	// Parse timeout from config
	timeoutStr := config.ARP.Timeout
	if timeoutStr == "" {
		timeoutStr = "2s"
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		timeout = 2 * time.Second
	}

	LogInfo("[ARP] Starting background ARP/NDP maintenance (Mode: %s, Timeout: %v)", config.ARP.Mode, timeout)
	
	// Initial population
	refreshARP(ctx, timeout)
	lastRefresh := time.Now()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			LogInfo("[ARP] Stopping background ARP/NDP table maintenance")
			return
		case <-ticker.C:
			// Check if cache was accessed since last refresh
			lastAccess := time.Unix(0, lastARPAccess.Load())
			
			if lastAccess.After(lastRefresh) {
				refreshARP(ctx, timeout)
				lastRefresh = time.Now()
			} else {
				LogDebug("[ARP] Skipping refresh - Idle (Last access: %v)", lastAccess.Format(time.TimeOnly))
			}
		}
	}
}

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

	// Update access timestamp for smart refresh logic
	lastARPAccess.Store(time.Now().UnixNano())

	arpCache.RLock()
	defer arpCache.RUnlock()
	return arpCache.table[ip.String()]
}

// --- Internal Logic ---

// refreshARP orchestrates the fetching of ARP/NDP data.
// It spawns platform-specific collectors and merges their results.
func refreshARP(ctx context.Context, timeout time.Duration) {
	if config.ARP.Mode == "none" {
		return
	}

	start := time.Now()
	
	// Temporary map for collection to avoid locking the main cache during fetch
	tempTable := make(map[string]net.HardwareAddr)
	var mu sync.Mutex // Protects tempTable during concurrent writes
	var wg sync.WaitGroup

	// Helper to safely add to temp map
	addToTable := func(ip string, mac net.HardwareAddr) {
		mu.Lock()
		tempTable[ip] = mac
		mu.Unlock()
	}

	doV4 := config.ARP.Mode == "v4" || config.ARP.Mode == "both"
	doV6 := config.ARP.Mode == "v6" || config.ARP.Mode == "both"

	// Define collectors based on OS
	switch runtime.GOOS {
	case "linux":
		if doV4 || doV6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectLinuxNeigh(ctx, addToTable, timeout, doV4, doV6)
			}()
		}

	case "windows":
		if doV4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectWindowsARP(ctx, addToTable, timeout)
			}()
		}
		if doV6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectWindowsNDP(ctx, addToTable, timeout)
			}()
		}

	case "darwin":
		if doV4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectDarwinARP(ctx, addToTable, timeout)
			}()
		}
		if doV6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectDarwinNDP(ctx, addToTable, timeout)
			}()
		}

	default:
		// Fallback to basic ARP for unknown *nix (usually v4)
		if doV4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectDarwinARP(ctx, addToTable, timeout)
			}()
		}
	}

	wg.Wait()

	// Atomic Swap: Replace the global table with the new one
	arpCache.Lock()
	countBefore := len(arpCache.table)
	arpCache.table = tempTable
	arpCache.Unlock()

	// Logging changes
	if len(tempTable) != countBefore {
		LogDebug("[ARP] Table refreshed in %v. Entries: %d (Delta: %d)", 
			time.Since(start), len(tempTable), len(tempTable)-countBefore)
	} else {
		// LogDebug will handle level checking internally
		LogDebug("[ARP] Table refreshed in %v. No changes. Entries: %d", 
			time.Since(start), len(tempTable))
	}
}

// --- Collectors ---

func collectLinuxNeigh(ctx context.Context, addFunc func(string, net.HardwareAddr), timeout time.Duration, doV4, doV6 bool) {
	// Linux `ip neigh` can filter by version
	// but running `ip neigh show` gets both, so we can filter in user space or run twice.
	// Running once is more efficient.
	
	args := []string{"neigh", "show"}
	if doV4 && !doV6 {
		args = []string{"-4", "neigh", "show"}
	} else if doV6 && !doV4 {
		args = []string{"-6", "neigh", "show"}
	}

	out, err := runCommand(ctx, timeout, "ip", args...)
	if err != nil {
		LogDebug("[ARP] Linux fetch failed: %v", err)
		return
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}

		// Find "lladdr" token
		for i, field := range fields {
			if field == "lladdr" && i+1 < len(fields) {
				macStr := fields[i+1]
				ipStr := fields[0]

				if mac, err := net.ParseMAC(macStr); err == nil {
					addFunc(ipStr, mac)
				}
				break
			}
		}
	}
}

func collectWindowsARP(ctx context.Context, addFunc func(string, net.HardwareAddr), timeout time.Duration) {
	out, err := runCommand(ctx, timeout, "arp", "-a")
	if err != nil {
		LogDebug("[ARP] Windows ARP failed: %v", err)
		return
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		matches := windowsARPRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			ipStr := matches[1]
			macStr := strings.ReplaceAll(matches[2], "-", ":")
			
			if mac, err := net.ParseMAC(macStr); err == nil {
				addFunc(ipStr, mac)
			}
		}
	}
}

func collectWindowsNDP(ctx context.Context, addFunc func(string, net.HardwareAddr), timeout time.Duration) {
	out, err := runCommand(ctx, timeout, "netsh", "interface", "ipv6", "show", "neighbors")
	if err != nil {
		LogDebug("[ARP] Windows NDP failed: %v", err)
		return
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 {
			macStr := strings.ReplaceAll(fields[1], "-", ":")
			if mac, err := net.ParseMAC(macStr); err == nil {
				ipStr := fields[0]
				if ip := net.ParseIP(ipStr); ip != nil {
					addFunc(ip.String(), mac)
				}
			}
		}
	}
}

func collectDarwinARP(ctx context.Context, addFunc func(string, net.HardwareAddr), timeout time.Duration) {
	out, err := runCommand(ctx, timeout, "arp", "-an")
	if err != nil {
		LogDebug("[ARP] Darwin ARP failed: %v", err)
		return
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		matches := darwinARPRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			ipStr := matches[1]
			macStr := matches[2]
			
			if macStr == "ff:ff:ff:ff:ff:ff" || macStr == "(incomplete)" {
				continue
			}

			if mac, err := net.ParseMAC(macStr); err == nil {
				addFunc(ipStr, mac)
			}
		}
	}
}

func collectDarwinNDP(ctx context.Context, addFunc func(string, net.HardwareAddr), timeout time.Duration) {
	out, err := runCommand(ctx, timeout, "ndp", "-an")
	if err != nil {
		LogDebug("[ARP] Darwin NDP failed: %v", err)
		return
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 {
			ipStr := fields[0]
			macStr := fields[1]

			if macStr == "(incomplete)" {
				continue
			}

			if idx := strings.Index(ipStr, "%"); idx != -1 {
				ipStr = ipStr[:idx]
			}

			if mac, err := net.ParseMAC(macStr); err == nil {
				if ip := net.ParseIP(ipStr); ip != nil {
					addFunc(ip.String(), mac)
				}
			}
		}
	}
}

// --- Helpers ---

// runCommand executes a command with a strict timeout context
func runCommand(parentCtx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

