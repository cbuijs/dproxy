/*
File: hosts.go
Description: Handles loading, parsing, and querying of standard HOSTS files AND Domain Lists.
             Supports IPv4, IPv6, PTR (Reverse), and optional wildcard matching for subdomains.
             UPDATED: Added logic to detect "Domain Lists" (lines without IPs) and treat them as blocked (0.0.0.0).
             UPDATED: Parser now returns and logs the detected file format (HOSTS/DOMAINS/MIXED).
             UPDATED: Strict parsing: discarding empty/comment lines, ensuring HOSTS syntax (IP host...), and stripping leading/trailing dots from domains.
             UPDATED: Filters out domain names that are syntactically valid IP addresses.
             UPDATED: Added debug logging for hostname sanitation and skipping.
*/

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type urlMeta struct {
	etag         string
	lastModified string
}

// HostsCache holds the parsed data from multiple hosts files and URLs.
type HostsCache struct {
	sync.RWMutex
	// forward: hostname -> list of IPs
	forward map[string][]net.IP
	// reverse: IP string -> list of hostnames
	reverse map[string][]string

	// Maintenance fields
	paths      []string
	urls       []string
	wildcard   bool
	performOpt bool
	fileMtimes map[string]time.Time
	urlMetas   map[string]urlMeta
	client     *http.Client
}

// NewHostsCache creates a new, empty HostsCache.
func NewHostsCache() *HostsCache {
	return &HostsCache{
		forward:    make(map[string][]net.IP),
		reverse:    make(map[string][]string),
		fileMtimes: make(map[string]time.Time),
		urlMetas:   make(map[string]urlMeta),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Load reads multiple hosts files AND URLs, then populates the cache.
func (hc *HostsCache) Load(paths []string, urls []string, wildcard bool, optimize bool) {
	start := time.Now()
	// 1. Prepare new data structures locally
	newForward := make(map[string][]net.IP)
	newReverse := make(map[string][]string)
	newFileMtimes := make(map[string]time.Time)
	newUrlMetas := make(map[string]urlMeta)

	totalNames := 0
	totalIPs := 0

	// 2. Load Files
	for _, path := range paths {
		names, ips, mtime := hc.loadFile(path, newForward, newReverse)
		totalNames += names
		totalIPs += ips
		if !mtime.IsZero() {
			newFileMtimes[path] = mtime
		}
	}

	// 3. Load URLs
	for _, url := range urls {
		names, ips, meta := hc.loadURL(url, newForward, newReverse)
		totalNames += names
		totalIPs += ips
		newUrlMetas[url] = meta
	}

	loadDuration := time.Since(start)

	// 4. Optimize (if wildcard enabled AND optimize requested)
	if wildcard && optimize {
		hc.optimize(newForward, newReverse)
	}

	// 5. Atomic Swap
	hc.Lock()
	hc.forward = newForward
	hc.reverse = newReverse
	hc.paths = paths
	hc.urls = urls
	hc.wildcard = wildcard
	hc.performOpt = optimize
	hc.fileMtimes = newFileMtimes
	hc.urlMetas = newUrlMetas
	hc.Unlock()

	LogInfo("[HOSTS] Loaded %d files and %d URLs in %v (%d names, %d IPs)", 
		len(paths), len(urls), loadDuration, len(newForward), len(newReverse))
}

// optimize removes subdomains from the maps if their parent domain exists.
func (hc *HostsCache) optimize(fwd map[string][]net.IP, rev map[string][]string) {
	const parallelThreshold = 5000
	
	count := len(fwd)
	if count == 0 {
		return
	}

	start := time.Now()
	var toDelete []string

	if count < parallelThreshold {
		toDelete = hc.findRedundantKeys(fwd, nil)
	} else {
		keys := make([]string, 0, count)
		for k := range fwd {
			keys = append(keys, k)
		}

		numWorkers := runtime.NumCPU()
		if count/numWorkers < 1000 {
			numWorkers = count / 1000
			if numWorkers < 1 {
				numWorkers = 1
			}
		}

		LogDebug("[HOSTS] Optimizing %d entries using %d workers", count, numWorkers)

		toDeleteCh := make(chan string, count/10)
		var wg sync.WaitGroup

		chunkSize := (count + numWorkers - 1) / numWorkers

		for i := 0; i < numWorkers; i++ {
			startIndex := i * chunkSize
			endIndex := startIndex + chunkSize
			if startIndex >= count {
				break
			}
			if endIndex > count {
				endIndex = count
			}

			wg.Add(1)
			go func(chunk []string) {
				defer wg.Done()
				hc.findRedundantKeysChannel(fwd, chunk, toDeleteCh)
			}(keys[startIndex:endIndex])
		}

		go func() {
			wg.Wait()
			close(toDeleteCh)
		}()

		for k := range toDeleteCh {
			toDelete = append(toDelete, k)
		}
	}

	removedCount := len(toDelete)
	
	for _, hostname := range toDelete {
		ips := fwd[hostname]
		delete(fwd, hostname)

		for _, ip := range ips {
			ipKey := ip.String()
			names := rev[ipKey]
			n := 0
			for _, name := range names {
				if name != hostname {
					names[n] = name
					n++
				}
			}
			names = names[:n]
			
			if len(names) == 0 {
				delete(rev, ipKey)
			} else {
				rev[ipKey] = names
			}
		}
	}

	if removedCount > 0 {
		LogDebug("[HOSTS] Optimization complete in %v: Removed %d redundant subdomains", time.Since(start), removedCount)
	}
}

func (hc *HostsCache) findRedundantKeys(fwd map[string][]net.IP, keys []string) []string {
	var redundant []string
	
	check := func(hostname string) {
		domain := hostname
		for {
			idx := strings.IndexByte(domain, '.')
			if idx == -1 {
				break
			}
			domain = domain[idx+1:]
			
			if domain == "" {
				break
			}

			if _, exists := fwd[domain]; exists {
				redundant = append(redundant, hostname)
				break
			}
		}
	}

	if keys != nil {
		for _, k := range keys {
			check(k)
		}
	} else {
		for k := range fwd {
			check(k)
		}
	}
	return redundant
}

func (hc *HostsCache) findRedundantKeysChannel(fwd map[string][]net.IP, keys []string, out chan<- string) {
	for _, hostname := range keys {
		domain := hostname
		for {
			idx := strings.IndexByte(domain, '.')
			if idx == -1 {
				break
			}
			domain = domain[idx+1:]
			
			if domain == "" {
				break
			}

			if _, exists := fwd[domain]; exists {
				out <- hostname
				break
			}
		}
	}
}

// isBlockedIP checks if an IP is one of the "blocking" addresses (0.0.0.0, ::, 127.0.0.1, ::1).
func isBlockedIP(ip net.IP) bool {
	if ip.IsUnspecified() { // 0.0.0.0 or ::
		return true
	}
	if ip.IsLoopback() { // 127.0.0.0/8 or ::1
		return true
	}
	return false
}

// parseReader is a helper to parse HOSTS content OR DOMAIN lists from any reader.
// Automatically detects format line-by-line.
// Returns: addedNames, addedIPs, detectedFormatString
func parseReader(sourceName string, r io.Reader, forward map[string][]net.IP, reverse map[string][]string) (int, int, string) {
	addedNames := 0
	addedIPs := 0
	
	// Format detection counters
	hostsCount := 0
	domainsCount := 0

	zeroIP := net.IPv4(0, 0, 0, 0) // Used for domain list entries (blocked)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// 1. Skip empty lines and comments (#)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		
		// Re-trim after removing comments
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Attempt to parse first field as IP
		ipStr := fields[0]
		ip := net.ParseIP(ipStr)

		if ip != nil {
			// --- HOSTS FORMAT: IP domain1 [domain2...] ---
			if len(fields) < 2 {
				continue // Valid IP but no domain? Skip.
			}
			
			hostsCount++
			
			isBlocked := isBlockedIP(ip)
			ipKey := ip.String()
			
			// Only add to reverse lookup if NOT a blocked IP
			if !isBlocked {
				if _, exists := reverse[ipKey]; !exists {
					addedIPs++
				}
			}

			// Process domains (fields[1:])
			for _, originalHost := range fields[1:] {
				// Normalize: lowercase and trim ALL leading/trailing dots
				host := strings.ToLower(strings.Trim(originalHost, "."))
				if host == "" {
					continue
				}

				if host != strings.ToLower(originalHost) {
					LogDebug("[HOSTS] [%s] Sanitized hostname: '%s' -> '%s'", sourceName, originalHost, host)
				}

				// Skip if the hostname is actually an IP address
				if net.ParseIP(host) != nil {
					LogDebug("[HOSTS] [%s] Skipped hostname '%s' because it is a valid IP address", sourceName, host)
					continue
				}
				
				forward[host] = append(forward[host], ip)
				
				if !isBlocked {
					reverse[ipKey] = append(reverse[ipKey], host)
				}
				addedNames++
			}

		} else {
			// --- DOMAIN LIST FORMAT: domain ---
			// Line starts with something that is NOT an IP. Treat as domain to block.
			
			domainsCount++
			// Only process the first field as the domain
			originalHost := fields[0]
			// Normalize: lowercase and trim ALL leading/trailing dots
			host := strings.ToLower(strings.Trim(originalHost, "."))
			
			if host != "" {
				if host != strings.ToLower(originalHost) {
					LogDebug("[HOSTS] [%s] Sanitized domain list entry: '%s' -> '%s'", sourceName, originalHost, host)
				}

				// Skip if the hostname is actually an IP address
				if net.ParseIP(host) != nil {
					LogDebug("[HOSTS] [%s] Skipped domain list entry '%s' because it is a valid IP address", sourceName, host)
					continue
				}

				// Store as 0.0.0.0 (Blocked)
				forward[host] = append(forward[host], zeroIP)
				addedNames++
			}
		}
	}

	// Determine format string
	format := "UNKNOWN"
	if hostsCount > 0 && domainsCount == 0 {
		format = "HOSTS"
	} else if domainsCount > 0 && hostsCount == 0 {
		format = "DOMAINS"
	} else if hostsCount > 0 && domainsCount > 0 {
		format = "MIXED"
	} else if addedNames == 0 {
		format = "EMPTY"
	}

	return addedNames, addedIPs, format
}

func (hc *HostsCache) loadFile(path string, fwd map[string][]net.IP, rev map[string][]string) (int, int, time.Time) {
	file, err := os.Open(path)
	if err != nil {
		LogWarn("[HOSTS] Failed to open file %s: %v", path, err)
		return 0, 0, time.Time{}
	}
	defer file.Close()

	info, err := file.Stat()
	mtime := time.Time{}
	if err == nil {
		mtime = info.ModTime()
	}

	names, _, format := parseReader(path, file, fwd, rev)
	LogDebug("[HOSTS] Parsed file %s (%s): %d names", path, format, names)
	return names, 0, mtime
}

func (hc *HostsCache) loadURL(url string, fwd map[string][]net.IP, rev map[string][]string) (int, int, urlMeta) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		LogWarn("[HOSTS] Invalid URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}

	hc.RLock()
	oldMeta, exists := hc.urlMetas[url]
	hc.RUnlock()
	if exists {
		if oldMeta.etag != "" {
			req.Header.Set("If-None-Match", oldMeta.etag)
		}
		if oldMeta.lastModified != "" {
			req.Header.Set("If-Modified-Since", oldMeta.lastModified)
		}
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		LogWarn("[HOSTS] Failed to fetch URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		LogDebug("[HOSTS] URL %s not modified (304)", url)
		resp.Body.Close()
		req.Header.Del("If-None-Match")
		req.Header.Del("If-Modified-Since")
		resp, err = hc.client.Do(req)
		if err != nil {
			return 0, 0, urlMeta{}
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		LogWarn("[HOSTS] URL %s returned status %d", url, resp.StatusCode)
		return 0, 0, urlMeta{}
	}

	meta := urlMeta{
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
	}

	names, _, format := parseReader(url, resp.Body, fwd, rev)
	LogDebug("[HOSTS] Parsed URL %s (%s): %d names", url, format, names)
	return names, 0, meta
}

func (hc *HostsCache) StartAutoRefresh(ctx context.Context, checkInterval time.Duration) {
	if len(hc.paths) == 0 && len(hc.urls) == 0 {
		return
	}
	
	LogInfo("[HOSTS] Starting auto-refresh for %d files, %d URLs (Interval: %v)", 
		len(hc.paths), len(hc.urls), checkInterval)
	
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkUpdates()
		}
	}
}

func (hc *HostsCache) HasRemote() bool {
	hc.RLock()
	defer hc.RUnlock()
	return len(hc.urls) > 0
}

func (hc *HostsCache) checkUpdates() {
	shouldReload := false

	for _, path := range hc.paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		hc.RLock()
		lastMod, known := hc.fileMtimes[path]
		hc.RUnlock()

		if !known || info.ModTime().After(lastMod) {
			LogInfo("[HOSTS] File changed: %s", path)
			shouldReload = true
			break 
		}
	}

	if !shouldReload {
		for _, url := range hc.urls {
			if hc.checkURLChanged(url) {
				LogInfo("[HOSTS] URL changed: %s", url)
				shouldReload = true
				break
			}
		}
	}

	if shouldReload {
		hc.RLock()
		wildcard := hc.wildcard
		optimize := hc.performOpt
		hc.RUnlock()
		hc.Load(hc.paths, hc.urls, wildcard, optimize)
	}
}

func (hc *HostsCache) checkURLChanged(url string) bool {
	hc.RLock()
	meta, known := hc.urlMetas[url]
	hc.RUnlock()

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	if known {
		if meta.etag != "" {
			req.Header.Set("If-None-Match", meta.etag)
		}
		if meta.lastModified != "" {
			req.Header.Set("If-Modified-Since", meta.lastModified)
		}
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false
	}

	return resp.StatusCode == http.StatusOK
}

func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()

	qName = strings.ToLower(strings.TrimSuffix(qName, "."))
	var ips []net.IP
	matchType := ""
	matchedName := ""
	found := false

	if matches, ok := hc.forward[qName]; ok {
		ips = matches
		matchType = "exact"
		matchedName = qName
		found = true
	} else if wildcard {
		parts := strings.Split(qName, ".")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if matches, ok := hc.forward[parent]; ok {
				ips = matches
				matchType = "wildcard"
				matchedName = parent
				found = true
				break
			}
		}
	}

	if !found {
		return nil, false
	}

	// Check if this domain is blocked (has 0.0.0.0, ::, 127.0.0.1, or ::1)
	isBlocked := false
	for _, ip := range ips {
		if isBlockedIP(ip) {
			isBlocked = true
			break
		}
	}

	var answers []dns.RR

	// If blocked, force return 0.0.0.0 (A) or :: (AAAA) regardless of what's in the file
	if isBlocked {
		if qType == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
			rr.A = net.IPv4(0, 0, 0, 0)
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
			rr.AAAA = net.ParseIP("::")
			answers = append(answers, rr)
		}
		// If other types (MX, etc.), return empty answers + found=true -> triggers NXDOMAIN in process.go
		LogDebug("[HOSTS] Hit (%s): %s -> %s (BLOCKED -> Null Response)", matchType, qName, matchedName)
		return answers, true
	}

	// Normal Behavior
	for _, ip := range ips {
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
	} else {
		LogDebug("[HOSTS] Hit (%s): %s -> %s (No %s records found, existing IPs: %v)", matchType, qName, matchedName, dns.TypeToString[qType], ips)
	}

	return answers, true
}

func (hc *HostsCache) LookupPTR(qName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()

	ip := extractIPFromPTR(qName)
	if ip == nil {
		return nil, false
	}

	// Check for Blocked IPs (0.0.0.0, ::, 127.0.0.1, ::1) -> Force NXDOMAIN (Found=true, Answers=nil)
	if isBlockedIP(ip) {
		LogDebug("[HOSTS] PTR Hit: %s -> BLOCKED (NXDOMAIN)", qName)
		return nil, true
	}

	names, ok := hc.reverse[ip.String()]
	if !ok {
		return nil, false
	}

	var answers []dns.RR
	for _, name := range names {
		rr := new(dns.PTR)
		rr.Hdr = dns.RR_Header{Name: qName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 0}
		rr.Ptr = dns.Fqdn(name)
		answers = append(answers, rr)
	}

	LogDebug("[HOSTS] PTR Hit: %s -> %v", qName, names)
	return answers, true
}

func extractIPFromPTR(qName string) net.IP {
	qName = strings.TrimSuffix(strings.ToLower(qName), ".")
	
	if strings.HasSuffix(qName, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(qName, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return nil
		}
		ipStr := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		return net.ParseIP(ipStr)
	} else if strings.HasSuffix(qName, ".ip6.arpa") {
		hexStr := strings.TrimSuffix(qName, ".ip6.arpa")
		hexStr = strings.ReplaceAll(hexStr, ".", "")
		runes := []rune(hexStr)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
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

