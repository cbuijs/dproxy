/*
File: hosts.go
Version: 1.8.0
Description: Main entry point for Hosts Cache. Handles runtime lookups and auto-refresh orchestration.
             REFACTORED: Heavy loading and optimization logic moved to hosts_loader.go.
             UPDATED: Restored detailed logging for HOSTS hits, specifically highlighting BLOCKED queries.
             UPDATED: Lookup now accepts clientInfo and ruleName for richer logging context.
*/

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type HostsCache struct {
	sync.RWMutex
	forward map[string][]net.IP
	reverse map[string][]string

	paths      []string
	urls       []string
	wildcard   bool
	performOpt bool
	defaultTTL uint32
	cacheDir   string

	fileMtimes map[string]time.Time
	urlMetas   map[string]urlMeta

	client *http.Client
}

func NewHostsCache() *HostsCache {
	return &HostsCache{
		forward:    make(map[string][]net.IP),
		reverse:    make(map[string][]string),
		fileMtimes: make(map[string]time.Time),
		urlMetas:   make(map[string]urlMeta),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		defaultTTL: 0,
	}
}

func (hc *HostsCache) SetTTL(ttl uint32) {
	hc.Lock()
	defer hc.Unlock()
	hc.defaultTTL = ttl
}

// LoadFromCache merges a loaded SourceCache into the active runtime cache.
func (hc *HostsCache) LoadFromCache(paths []string, urls []string, sourceCache SourceCache, wildcard bool, optimize bool) (int, int) {
	start := time.Now()

	newForward := make(map[string][]net.IP)
	newReverse := make(map[string][]string)
	newFileMtimes := make(map[string]time.Time)
	newUrlMetas := make(map[string]urlMeta)

	totalSources := 0

	merge := func(key string) {
		if data, ok := sourceCache[key]; ok {
			totalSources++
			for k, v := range data.Forward {
				newForward[k] = append(newForward[k], v...)
			}
			for k, v := range data.Reverse {
				newReverse[k] = append(newReverse[k], v...)
			}
			if !data.MTime.IsZero() {
				newFileMtimes[key] = data.MTime
			}
			newUrlMetas[key] = data.Meta
		} else {
			LogWarn("[HOSTS] Source not found in cache during merge: %s", key)
		}
	}

	for _, path := range paths {
		merge(path)
	}
	for _, url := range urls {
		merge(url)
	}

	if wildcard && optimize {
		hc.optimize(newForward, newReverse)
	}

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

	LogInfo("[HOSTS] Cache assembled from %d sources in %v (%d names)", totalSources, time.Since(start), len(newForward))
	return len(newForward), len(newReverse)
}

// Load triggers a fresh load of the specified paths and URLs.
func (hc *HostsCache) Load(paths []string, urls []string, wildcard bool, optimize bool) {
	cache := BatchLoadSources(paths, urls, hc.cacheDir)
	names, ips := hc.LoadFromCache(paths, urls, cache, wildcard, optimize)
	LogInfo("[HOSTS] Refresh complete: %d names, %d IPs", names, ips)
}

func (hc *HostsCache) StartAutoRefresh(ctx context.Context, checkInterval time.Duration) {
	if len(hc.paths) == 0 && len(hc.urls) == 0 {
		return
	}
	LogInfo("[HOSTS] Starting auto-refresh for %d files, %d URLs (Interval: %v)", len(hc.paths), len(hc.urls), checkInterval)
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
		w := hc.wildcard
		o := hc.performOpt
		hc.RUnlock()
		hc.Load(hc.paths, hc.urls, w, o)
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
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusNotModified && resp.StatusCode == http.StatusOK
}

// Lookup queries the hosts cache.
func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool, clientInfo, ruleName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()
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
		curr := qName
		for {
			idx := strings.IndexByte(curr, '.')
			if idx == -1 {
				break
			}
			parent := curr[idx+1:]
			if parent == "" {
				break
			}

			if matches, ok := hc.forward[parent]; ok {
				ips = matches
				matchType = "wildcard"
				matchedName = parent
				found = true
				break
			}
			curr = parent
		}
	}

	if !found {
		return nil, false
	}

	isBlocked := false
	for _, ip := range ips {
		if isBlockedIP(ip) {
			isBlocked = true
			break
		}
	}

	var answers []dns.RR
	ttl := hc.defaultTTL
	if isBlocked {
		if qType == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = net.IPv4(0, 0, 0, 0)
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = net.ParseIP("::")
			answers = append(answers, rr)
		}
		// Explicit logging for BLOCKED queries with Client and Rule info
		LogInfo("[HOSTS] BLOCKED: %s (Type: %s) -> Matched: %s (%s) | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], matchedName, matchType, ruleName, clientInfo)
		return answers, true
	}

	for _, ip := range ips {
		if qType == dns.TypeA && ip.To4() != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ip.To4()
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA && ip.To4() == nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ip
			answers = append(answers, rr)
		}
	}
	
	if len(answers) > 0 {
		// Log successful HOSTS resolution
		LogInfo("[HOSTS] Resolved: %s (Type: %s) -> %v [Match: %s, Source: %s] | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], ips, matchType, matchedName, ruleName, clientInfo)
	} else {
		// Log valid domain found but no records for requested type
		LogInfo("[HOSTS] No Records: %s found in HOSTS, but no %s records available. | Rule: %s | Client: %s", 
			qName, dns.TypeToString[qType], ruleName, clientInfo)
	}
	return answers, true
}

func (hc *HostsCache) LookupPTR(qName, clientInfo, ruleName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()
	ip := extractIPFromPTR(qName)
	if ip == nil {
		return nil, false
	}
	if isBlockedIP(ip) {
		return nil, true
	}
	names, ok := hc.reverse[ip.String()]
	if !ok {
		return nil, false
	}

	var answers []dns.RR
	ttl := hc.defaultTTL
	for _, name := range names {
		rr := new(dns.PTR)
		rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		rr.Ptr = dns.Fqdn(name)
		answers = append(answers, rr)
	}
	LogInfo("[HOSTS] PTR Resolved: %s -> %v | Rule: %s | Client: %s", qName, names, ruleName, clientInfo)
	return answers, true
}

func extractIPFromPTR(qName string) net.IP {
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
		n := len(runes)
		for i := 0; i < n/2; i++ {
			runes[i], runes[n-1-i] = runes[n-1-i], runes[i]
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

