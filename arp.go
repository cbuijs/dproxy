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

var arpCache = &ARPCache{table: make(map[string]net.HardwareAddr)}

func maintainARPCache(ctx context.Context) {
	refreshARP()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshARP()
		}
	}
}

func getMacFromCache(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}
	arpCache.RLock()
	defer arpCache.RUnlock()
	return arpCache.table[ip.String()]
}

func refreshARP() {
	newTable := make(map[string]net.HardwareAddr)
	switch runtime.GOOS {
	case "linux":
		parseLinuxARP(newTable)
	case "windows":
		parseWindowsARP(newTable)
		parseWindowsNDP(newTable)
	case "darwin":
		parseDarwinARP(newTable)
		parseDarwinNDP(newTable)
	default:
		parseDarwinARP(newTable)
	}
	arpCache.Lock()
	arpCache.table = newTable
	arpCache.Unlock()
}

func parseLinuxARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("ip", "neigh", "show")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
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
				}
			}
		}
	}
}

func parseWindowsARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("arp", "-a")
	out, err := cmd.Output()
	if err != nil {
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

