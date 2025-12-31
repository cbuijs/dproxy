/*
File: hosts.go
Description: Handles loading, parsing, and querying of standard HOSTS files.
             Supports IPv4, IPv6, PTR (Reverse), and optional wildcard matching for subdomains.
             UPDATED: Added automatic hot-reloading based on file modification timestamps.
*/

package main

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// HostsCache holds the parsed data from multiple hosts files.
type HostsCache struct {
	sync.RWMutex
	// forward: hostname -> list of IPs
	forward map[string][]net.IP
	// reverse: IP string -> list of hostnames
	reverse map[string][]string
	
	// Maintenance fields
	paths      []string
	fileMtimes map[string]time.Time
}

// NewHostsCache creates a new, empty HostsCache.
func NewHostsCache() *HostsCache {
	return &HostsCache{
		forward:    make(map[string][]net.IP),
		reverse:    make(map[string][]string),
		fileMtimes: make(map[string]time.Time),
	}
}

// Load reads multiple hosts files and populates the cache.
// It replaces existing data for the loaded files.
func (hc *HostsCache) Load(paths []string) {
	hc.Lock()
	defer hc.Unlock()

	hc.paths = paths
	// Clear existing data to ensure clean state on reload
	hc.forward = make(map[string][]net.IP)
	hc.reverse = make(map[string][]string)

	totalNames := 0
	totalIPs := 0

	for _, path := range paths {
		names, ips := hc.loadFileLocked(path)
		totalNames += names
		totalIPs += ips
	}
	LogInfo("[HOSTS] Loaded %d hosts files (%d names, %d IPs)", len(paths), len(hc.forward), len(hc.reverse))
}

// loadFileLocked parses a single file. Callers must hold the Lock.
func (hc *HostsCache) loadFileLocked(path string) (int, int) {
	file, err := os.Open(path)
	if err != nil {
		LogWarn("[HOSTS] Failed to open file %s: %v", path, err)
		return 0, 0
	}
	defer file.Close()

	// Update mod time
	info, err := file.Stat()
	if err == nil {
		hc.fileMtimes[path] = info.ModTime()
	}

	addedNames := 0
	addedIPs := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ipStr := fields[0]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue // Invalid IP
		}

		// Normalize IP for reverse map key
		ipKey := ip.String()
		if _, exists := hc.reverse[ipKey]; !exists {
			addedIPs++
		}

		// Remaining fields are hostnames
		for _, host := range fields[1:] {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			
			// Update Forward Map
			hc.forward[host] = append(hc.forward[host], ip)

			// Update Reverse Map
			hc.reverse[ipKey] = append(hc.reverse[ipKey], host)
			addedNames++
		}
	}

	return addedNames, addedIPs
}

// StartAutoRefresh starts a background routine to check for file changes.
func (hc *HostsCache) StartAutoRefresh(ctx context.Context, checkInterval time.Duration) {
	if len(hc.paths) == 0 {
		return
	}
	
	LogInfo("[HOSTS] Starting auto-refresh monitor for %d files (Interval: %v)", len(hc.paths), checkInterval)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkFiles()
		}
	}
}

func (hc *HostsCache) checkFiles() {
	changed := false

	// Check stat of all files without locking first to avoid contention
	for _, path := range hc.paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		
		hc.RLock()
		lastMod, known := hc.fileMtimes[path]
		hc.RUnlock()

		if !known || info.ModTime().After(lastMod) {
			LogInfo("[HOSTS] File changed detected: %s. Reloading...", path)
			changed = true
			break // If any file changed, we reload everything to ensure consistency
		}
	}

	if changed {
		// Reload all files to keep state consistent
		// (Simpler than partial updates, fast enough for hosts files)
		hc.Load(hc.paths)
	}
}

// Lookup performs a forward lookup (A/AAAA).
// If wildcard is true, it checks parent domains if exact match fails.
func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool) []dns.RR {
	hc.RLock()
	defer hc.RUnlock()

	qName = strings.ToLower(strings.TrimSuffix(qName, "."))
	var ips []net.IP
	matchType := ""
	matchedName := ""

	// 1. Exact Match
	if matches, ok := hc.forward[qName]; ok {
		ips = matches
		matchType = "exact"
		matchedName = qName
	} else if wildcard {
		// 2. Wildcard/Suffix Match (if enabled)
		// e.g., query "ads.google.com" matches host entry "google.com"
		parts := strings.Split(qName, ".")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if matches, ok := hc.forward[parent]; ok {
				ips = matches
				matchType = "wildcard"
				matchedName = parent
				break
			}
		}
	}

	if len(ips) == 0 {
		return nil
	}

	var answers []dns.RR
	for _, ip := range ips {
		// Filter by query type
		if qType == dns.TypeA && ip.To4() != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
			rr.A = ip.To4()
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA && ip.To4() == nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
			rr.AAAA = ip
			answers = append(answers, rr)
		}
	}

	if len(answers) > 0 {
		LogDebug("[HOSTS] Hit (%s): %s -> %s (Matches: %v)", matchType, qName, matchedName, ips)
	}

	return answers
}

// LookupPTR performs a reverse lookup.
// It parses the IP from the in-addr.arpa or ip6.arpa query name.
func (hc *HostsCache) LookupPTR(qName string) []dns.RR {
	hc.RLock()
	defer hc.RUnlock()

	// Extract IP from PTR query
	ip := extractIPFromPTR(qName)
	if ip == nil {
		return nil
	}

	names, ok := hc.reverse[ip.String()]
	if !ok {
		return nil
	}

	var answers []dns.RR
	for _, name := range names {
		rr := new(dns.PTR)
		rr.Hdr = dns.RR_Header{Name: qName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 0}
		rr.Ptr = dns.Fqdn(name)
		answers = append(answers, rr)
	}

	LogDebug("[HOSTS] PTR Hit: %s -> %v", qName, names)
	return answers
}

// extractIPFromPTR converts "4.3.2.1.in-addr.arpa." to net.IP
func extractIPFromPTR(qName string) net.IP {
	qName = strings.TrimSuffix(strings.ToLower(qName), ".")
	
	if strings.HasSuffix(qName, ".in-addr.arpa") {
		// IPv4
		parts := strings.Split(strings.TrimSuffix(qName, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return nil
		}
		// Reverse the bytes
		ipStr := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		return net.ParseIP(ipStr)
	} else if strings.HasSuffix(qName, ".ip6.arpa") {
		// IPv6
		hexStr := strings.TrimSuffix(qName, ".ip6.arpa")
		hexStr = strings.ReplaceAll(hexStr, ".", "")
		// IPv6 PTR is reversed nibbles. 
		// "b.a.9.8....1.0.0.2.ip6.arpa" -> 2001:...89ab
		// We need to reverse the string of nibbles
		runes := []rune(hexStr)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		
		// Insert colons every 4 chars
		var sb strings.Builder
		for i, r := range runes {
			if i > 0 && i%4 == 0 {
				sb.WriteString(":")
			}
			sb.WriteRune(r)
		}
		return net.ParseIP(sb.String())
	}
	return nil
}

