/*
File: arp.go
Description: Handles ARP and NDP table lookups for resolving IP addresses to MAC addresses.
             Supports Linux, Windows, and macOS.
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

var (
	windowsARPRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})`)
	darwinARPRegex  = regexp.MustCompile(`\((.*?)\) at ([0-9a-fA-F:]+)`)
)

type ARPCache struct {
	sync.RWMutex
	table map[string]net.HardwareAddr
}

var (
	arpCache      = &ARPCache{table: make(map[string]net.HardwareAddr)}
	lastARPAccess atomic.Int64
)

func maintainARPCache(ctx context.Context) {
	LogInfo("[ARP] Starting background ARP/NDP table maintenance")
	refreshARP() // Immediate refresh on startup
	lastRefresh := time.Now()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			LogInfo("[ARP] Stopping background ARP/NDP table maintenance")
			return
		case <-ticker.C:
			// Smart Refresh: Only refresh if there has been access since the last refresh.
			// This prevents running expensive exec commands when the proxy is idle.
			lastAccessTime := time.Unix(0, lastARPAccess.Load())
			
			if lastAccessTime.After(lastRefresh) {
				refreshARP()
				lastRefresh = time.Now()
			} else {
				// Only log this at DEBUG level to avoid cluttering INFO logs
				LogDebug("[ARP] Skipping refresh - No queries since last update (%v)", lastRefresh.Format(time.TimeOnly))
			}
		}
	}
}

func getMacFromCache(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}

	// Record activity timestamp (nanoseconds)
	// This signals the background routine that the cache is being used
	lastARPAccess.Store(time.Now().UnixNano())

	arpCache.RLock()
	defer arpCache.RUnlock()
	return arpCache.table[ip.String()]
}

func refreshARP() {
	start := time.Now()
	newTable := make(map[string]net.HardwareAddr)
	
	var err error
	switch runtime.GOOS {
	case "linux":
		err = parseLinuxARP(newTable)
	case "windows":
		parseWindowsARP(newTable)
		parseWindowsNDP(newTable)
	case "darwin":
		parseDarwinARP(newTable)
		parseDarwinNDP(newTable)
	default:
		parseDarwinARP(newTable)
	}

	if err != nil {
		LogWarn("[ARP] Failed to refresh ARP table: %v", err)
	}

	arpCache.Lock()
	countBefore := len(arpCache.table)
	arpCache.table = newTable
	arpCache.Unlock()

	if len(newTable) != countBefore || currentLogLevel <= LevelDebug {
		LogDebug("[ARP] Table refreshed in %v. Entries: %d (Previous: %d)", 
			time.Since(start), len(newTable), countBefore)
	}
}

func parseLinuxARP(table map[string]net.HardwareAddr) error {
	cmd := exec.Command("ip", "neigh", "show")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	count := 0
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip := f[0]
		for i, v := range f {
			if v == "lladdr" && i+1 < len(f) {
				if mac, err := net.ParseMAC(f[i+1]); err == nil {
					table[ip] = mac
					count++
				}
			}
		}
	}
	return nil
}

func parseWindowsARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("arp", "-a")
	out, err := cmd.Output()
	if err != nil {
		LogDebug("[ARP] Windows ARP fetch failed: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := windowsARPRegex.FindStringSubmatch(sc.Text())
		if len(m) == 3 {
			if mac, err := net.ParseMAC(strings.ReplaceAll(m[2], "-", ":")); err == nil {
				table[m[1]] = mac
			}
		}
	}
}

func parseWindowsNDP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("netsh", "interface", "ipv6", "show", "neighbors")
	out, err := cmd.Output()
	if err != nil {
		LogDebug("[ARP] Windows NDP fetch failed: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			if mac, err := net.ParseMAC(strings.ReplaceAll(f[1], "-", ":")); err == nil {
				if ip := net.ParseIP(f[0]); ip != nil {
					table[ip.String()] = mac
				}
			}
		}
	}
}

func parseDarwinARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("arp", "-an")
	out, err := cmd.Output()
	if err != nil {
		LogDebug("[ARP] Darwin/BSD ARP fetch failed: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := darwinARPRegex.FindStringSubmatch(sc.Text())
		if len(m) == 3 && m[2] != "ff:ff:ff:ff:ff:ff" && m[2] != "(incomplete)" {
			if mac, err := net.ParseMAC(m[2]); err == nil {
				table[m[1]] = mac
			}
		}
	}
}

func parseDarwinNDP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("ndp", "-an")
	out, err := cmd.Output()
	if err != nil {
		LogDebug("[ARP] Darwin/BSD NDP fetch failed: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			ipStr := f[0]
			if idx := strings.Index(ipStr, "%"); idx != -1 {
				ipStr = ipStr[:idx]
			}
			if mac, err := net.ParseMAC(f[1]); err == nil {
				if ip := net.ParseIP(ipStr); ip != nil {
					table[ip.String()] = mac
				}
			}
		}
	}
}

