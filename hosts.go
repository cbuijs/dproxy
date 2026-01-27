/*
File: hosts.go
Version: 3.0.0 (Unified netip.Addr)
Description: Main entry point for Hosts Cache. Handles runtime lookups, auto-refresh, and Safe Search injection.
             OPTIMIZED: Unified internal storage to use netip.Addr, reducing memory overhead and GC pressure.
*/

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"
)

// --- Compact Host Trie Implementation ---

type HostNode struct {
	Children   map[string]*HostNode
	IsBlocked  bool
	IsAllowed  bool
	CustomIPs  []netip.Addr // Changed from []net.IP to []netip.Addr
	SourceName string
	Domain     string
	SourceID   uint16
}

type HostTrie struct {
	Root *HostNode
}

func NewHostTrie() *HostTrie {
	return &HostTrie{Root: &HostNode{}}
}

func (t *HostTrie) Insert(domain string, ips []netip.Addr, isAllow bool, source string) {
	if domain == "" {
		return
	}

	var validIPs []netip.Addr
	allZeros := true

	if len(ips) > 0 {
		for _, ip := range ips {
			if ip.IsValid() && !ip.IsUnspecified() {
				validIPs = append(validIPs, ip)
				allZeros = false
			}
		}
	} else {
		allZeros = true
	}

	node := t.Root
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		if node.Children == nil {
			node.Children = make(map[string]*HostNode)
		}

		child, ok := node.Children[part]
		if !ok {
			child = &HostNode{}
			node.Children[part] = child
		}
		node = child
	}

	node.SourceName = source
	node.Domain = domain

	if isAllow {
		node.IsAllowed = true
		node.IsBlocked = false
		node.CustomIPs = nil
		if len(validIPs) > 0 {
			node.CustomIPs = validIPs
		}
	} else {
		if allZeros {
			node.IsBlocked = true
			node.CustomIPs = nil
		} else {
			node.IsBlocked = false
			node.CustomIPs = validIPs
		}
	}
}

func (t *HostTrie) Search(qName string, wildcard bool) (bool, bool, []netip.Addr, string, string) {
	node := t.Root

	parts := strings.Split(qName, ".")
	var lastMatchNode *HostNode

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		if node.Children == nil {
			node = nil
			break
		}

		next, ok := node.Children[part]
		if !ok {
			node = nil
			break
		}

		node = next

		if node.IsBlocked || node.IsAllowed || len(node.CustomIPs) > 0 {
			lastMatchNode = node
		}
	}

	if node != nil {
		if node.IsBlocked || node.IsAllowed || len(node.CustomIPs) > 0 {
			return true, node.IsAllowed, t.getIPs(node), node.SourceName, node.Domain
		}
	}

	if wildcard && lastMatchNode != nil {
		return true, lastMatchNode.IsAllowed, t.getIPs(lastMatchNode), lastMatchNode.SourceName, lastMatchNode.Domain
	}

	return false, false, nil, "", ""
}

func (t *HostTrie) getIPs(node *HostNode) []netip.Addr {
	if node.IsBlocked {
		return nil
	}
	return node.CustomIPs
}

// --- Main HostsCache Struct ---

type HostsCache struct {
	sync.RWMutex

	trie           *HostTrie
	reverse        map[string][]string
	cnames         map[string]string
	safeSearchMeta map[string]string
	ipRanger       cidranger.Ranger
	sources        []string

	paths           []string
	urls            []string
	wildcard        bool
	performOpt      bool
	optimizeTLD     bool
	filterResponses bool
	defaultTTL      uint32
	cacheDir        string

	fileMtimes map[string]time.Time
	urlMetas   map[string]urlMeta

	client *http.Client
}

func NewHostsCache() *HostsCache {
	return &HostsCache{
		trie:           NewHostTrie(),
		reverse:        make(map[string][]string),
		cnames:         make(map[string]string),
		safeSearchMeta: make(map[string]string),
		ipRanger:       cidranger.NewPCTrieRanger(),
		fileMtimes:     make(map[string]time.Time),
		urlMetas:       make(map[string]urlMeta),
		sources:        make([]string, 0),
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

func (hc *HostsCache) LoadSafeSearch(mode string) {
	config := GenerateSafeSearchConfig(mode)
	if config == nil {
		return
	}

	hc.Lock()
	defer hc.Unlock()

	countIP := 0
	countCNAME := 0

	// IPs in SafeSearchResult are already map[string][]netip.Addr
	for domain, ips := range config.IPs {
		hc.trie.Insert(domain, ips, false, "SafeSearch:"+mode)
		countIP++
	}

	for domain, target := range config.CNAMEs {
		hc.cnames[domain] = target
		countCNAME++
	}

	for domain, service := range config.Services {
		hc.safeSearchMeta[domain] = fmt.Sprintf("%s (%s)", service, mode)
	}

	LogInfo("[HOSTS] Applied Safe Search (%s): %d IPs, %d CNAMEs", mode, countIP, countCNAME)
}

func (hc *HostsCache) LoadFromCache(paths []string, urls []string, sourceCache SourceCache, wildcard bool, optimize bool, optimizeTLD bool, filterResponses bool) (int, int) {
	start := time.Now()

	newTrie := NewHostTrie()
	newReverse := make(map[string][]string)
	newRanger := cidranger.NewPCTrieRanger()
	filterCount := 0

	newFileMtimes := make(map[string]time.Time)
	newUrlMetas := make(map[string]urlMeta)

	totalSources := 0
	totalRules := 0

	merge := func(key string) {
		if data, ok := sourceCache[key]; ok {
			totalSources++
			sourceName := data.SourceName
			if sourceName == "" {
				sourceName = key
			}

			// Forward Map (Blocklist/Spoof)
			// data.Forward is map[string][]netip.Addr - No conversion needed!
			for domain, ips := range data.Forward {
				newTrie.Insert(domain, ips, false, sourceName)
				totalRules++
			}

			// Allowed Map
			for domain, ips := range data.Allowed {
				newTrie.Insert(domain, ips, true, sourceName)
				totalRules++
			}

			for k, v := range data.Reverse {
				newReverse[k] = append(newReverse[k], v...)
			}

			// Filters
			// data.Filters is []netip.Prefix
			for _, prefix := range data.Filters {
				// Convert netip.Prefix to net.IPNet for cidranger (required)
				addr := prefix.Addr()
				ipBytes := addr.AsSlice()
				mask := net.CIDRMask(prefix.Bits(), addr.BitLen())
				
				ipNet := net.IPNet{
					IP:   net.IP(ipBytes),
					Mask: mask,
				}
				_ = newRanger.Insert(cidranger.NewBasicRangerEntry(ipNet))
				filterCount++
			}

			if !data.MTime.IsZero() {
				newFileMtimes[key] = data.MTime
			}
			newUrlMetas[key] = data.Meta
		}
	}

	for _, path := range paths {
		merge(path)
	}
	for _, url := range urls {
		merge(url)
	}

	hc.Lock()
	hc.trie = newTrie
	hc.reverse = newReverse
	hc.ipRanger = newRanger
	hc.paths = paths
	hc.urls = urls
	hc.wildcard = wildcard
	hc.performOpt = optimize
	hc.optimizeTLD = optimizeTLD
	hc.filterResponses = filterResponses
	hc.fileMtimes = newFileMtimes
	hc.urlMetas = newUrlMetas
	hc.Unlock()

	LogInfo("[HOSTS] Cache assembled from %d sources in %v (%d rules, %d filters)",
		totalSources, time.Since(start), totalRules, filterCount)
	return totalRules, len(newReverse)
}

func (hc *HostsCache) Load(paths []string, urls []string, wildcard bool, optimize bool, optimizeTLD bool, filterResponses bool) {
	cache := BatchLoadSources(paths, urls, hc.cacheDir)
	names, ips := hc.LoadFromCache(paths, urls, cache, wildcard, optimize, optimizeTLD, filterResponses)
	LogInfo("[HOSTS] Refresh complete: %d rules, %d PTRs", names, ips)
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
		t := hc.optimizeTLD
		fr := hc.filterResponses
		hc.RUnlock()
		hc.Load(hc.paths, hc.urls, w, o, t, fr)
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

func (hc *HostsCache) GetHostnames(ip net.IP) []string {
	hc.RLock()
	defer hc.RUnlock()
	return hc.reverse[ip.String()]
}

func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool, clientInfo, ruleName string) ([]dns.RR, bool, bool) {
	hc.RLock()
	defer hc.RUnlock()

	if target, ok := hc.cnames[qName]; ok {
		rr := new(dns.CNAME)
		rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: hc.defaultTTL}
		rr.Target = dns.Fqdn(target)

		if meta, hasMeta := hc.safeSearchMeta[qName]; hasMeta {
			LogInfo("[SAFESEARCH] Enforced Safe Search for %s (%s) -> CNAME Spoofed: %s | Rule: %s | Client: %s",
				qName, meta, target, ruleName, clientInfo)
		} else {
			LogDebug("[HOSTS] CNAME: %s -> %s | Rule: %s | Client: %s", qName, target, ruleName, clientInfo)
		}
		return []dns.RR{rr}, true, false
	}

	found, isAllowed, ips, sourceName, hitDomain := hc.trie.Search(qName, wildcard)

	if !found {
		return nil, false, false
	}

	matchType := "exact"
	if wildcard {
		matchType = "wildcard-check"
	}

	if isAllowed {
		if len(ips) == 0 {
			if IsCompact() {
				LogDebug("[HOSTS] ALLOWED: %s (Type: %s) -> Bypass | Client: %s",
					qName, dns.TypeToString[qType], clientInfo)
			} else {
				LogDebug("[HOSTS] ALLOWED: %s (Type: %s) -> Bypass [Match: %s, Hit: %s, Source: %s] | Rule: %s | Client: %s",
					qName, dns.TypeToString[qType], matchType, hitDomain, sourceName, ruleName, clientInfo)
			}
			return nil, true, true
		} else {
			rrs, _ := hc.generateRRs(qName, qType, ips, matchType, sourceName, hitDomain, ruleName, clientInfo)
			return rrs, true, false
		}
	} else {
		if len(ips) == 0 {
			rrs, _ := hc.generateBlockRRs(qName, qType, matchType, sourceName, hitDomain, ruleName, clientInfo)
			return rrs, true, false
		}
		rrs, _ := hc.generateRRs(qName, qType, ips, matchType, sourceName, hitDomain, ruleName, clientInfo)
		return rrs, true, false
	}
}

// FilterResponse applies host filtering (domains and IPs) to a DNS response.
// Returns (modified, matchedAllow)
func (hc *HostsCache) FilterResponse(msg *dns.Msg, qName, ruleName, clientInfo string) (bool, bool) {
	if msg == nil || len(msg.Answer) == 0 {
		return false, false
	}

	hc.RLock()
	// Optimization: If filtering disabled, return fast
	if !hc.filterResponses {
		hc.RUnlock()
		return false, false
	}
	ranger := hc.ipRanger
	wildcard := hc.wildcard
	hc.RUnlock() // Unlock early to avoid holding lock during loop

	modified := false
	matchedAllow := false
	seenA := false
	seenAAAA := false

	// Re-acquire lock only when searching trie/ranger
	// Or even better, iterate first, collect IPs/Domains, then lock once?
	// For now, simple lock is safer.
	hc.RLock()
	defer hc.RUnlock()

	keepCount := 0
	for _, rr := range msg.Answer {
		dropRecord := false

		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
			seenA = true
		case *dns.AAAA:
			ip = r.AAAA
			seenAAAA = true
		}

		if ip != nil {
			networks, err := ranger.ContainingNetworks(ip)
			if err == nil && len(networks) > 0 {
				dropRecord = true
				match := networks[len(networks)-1].Network()
				LogInfo("[HOSTS] FILTERED IP: %s from response for %s | Trigger: %s | Rule: %s | Client: %s",
					ip.String(), qName, match.String(), ruleName, clientInfo)
			}
		}

		if !dropRecord {
			var targetDomain string
			var recType string

			switch r := rr.(type) {
			case *dns.CNAME:
				targetDomain = r.Target
				recType = "CNAME"
			case *dns.MX:
				targetDomain = r.Mx
				recType = "MX"
			case *dns.NS:
				targetDomain = r.Ns
				recType = "NS"
			case *dns.PTR:
				targetDomain = r.Ptr
				recType = "PTR"
			case *dns.SRV:
				targetDomain = r.Target
				recType = "SRV"
			case *dns.DNAME:
				targetDomain = r.Target
				recType = "DNAME"
			case *dns.SOA:
				targetDomain = r.Ns
				recType = "SOA"
			}

			if targetDomain != "" {
				targetDomain = strings.ToLower(strings.TrimSuffix(targetDomain, "."))
				found, isAllowed, _, sourceName, _ := hc.trie.Search(targetDomain, wildcard)

				if found {
					if isAllowed {
						matchedAllow = true
					} else {
						dropRecord = true
						LogInfo("[HOSTS] FILTERED DOMAIN: %s (%s) from response for %s | Source: %s | Rule: %s | Client: %s",
							targetDomain, recType, qName, sourceName, ruleName, clientInfo)
					}
				}
			}
		}

		if dropRecord {
			modified = true
		} else {
			if keepCount != len(msg.Answer) {
				msg.Answer[keepCount] = rr
			}
			keepCount++
		}
	}

	if modified {
		msg.Answer = msg.Answer[:keepCount]
		// If we dropped everything, we should probably return NXDOMAIN or a Block Record
		// depending on config. For now, let's inject 0.0.0.0 if empty to be safe?
		if len(msg.Answer) == 0 {
			LogInfo("[HOSTS] BLOCKED: %s -> All records filtered, injecting block record | Rule: %s | Client: %s",
				qName, ruleName, clientInfo)

			var qType uint16
			if len(msg.Question) > 0 {
				qType = msg.Question[0].Qtype
			}

			if qType == dns.TypeA || (qType == 0 && seenA) {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.A = net.IPv4(0, 0, 0, 0)
				msg.Answer = append(msg.Answer, rr)
			} else if qType == dns.TypeAAAA || (qType == 0 && seenAAAA) {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: hc.defaultTTL}
				rr.AAAA = net.ParseIP("::")
				msg.Answer = append(msg.Answer, rr)
			}
		}
	}

	return modified, matchedAllow
}

func (hc *HostsCache) generateBlockRRs(qName string, qType uint16, matchType, sourceName, hitDomain, ruleName, clientInfo string) ([]dns.RR, bool) {
	var answers []dns.RR
	ttl := hc.defaultTTL

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

	if IsCompact() {
		LogInfo("[HOSTS] BLOCKED: %s (Type: %s) -> 0.0.0.0/:: | Client: %s",
			qName, dns.TypeToString[qType], clientInfo)
	} else {
		LogInfo("[HOSTS] BLOCKED: %s (Type: %s) -> 0.0.0.0/:: [Match: %s, Hit: %s, Source: %s] | Rule: %s | Client: %s",
			qName, dns.TypeToString[qType], matchType, hitDomain, sourceName, ruleName, clientInfo)
	}

	return answers, true
}

func (hc *HostsCache) generateRRs(qName string, qType uint16, ips []netip.Addr, matchType, source, hitDomain, ruleName, clientInfo string) ([]dns.RR, bool) {
	var answers []dns.RR
	ttl := hc.defaultTTL

	for _, ip := range ips {
		if qType == dns.TypeA && ip.Is4() {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = net.IP(ip.AsSlice())
			answers = append(answers, rr)
		} else if qType == dns.TypeAAAA && ip.Is6() {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = net.IP(ip.AsSlice())
			answers = append(answers, rr)
		}
	}

	if len(answers) > 0 {
		if _, isSafeSearch := hc.safeSearchMeta[qName]; !isSafeSearch {
			LogDebug("[HOSTS] Resolved: %s (Type: %s) -> %v [Match: %s, Hit: %s, Source: %s] | Rule: %s | Client: %s",
				qName, dns.TypeToString[qType], ips, matchType, hitDomain, source, ruleName, clientInfo)
		}
	} else {
		LogDebug("[HOSTS] No Records: %s found in HOSTS, but no %s records available. | Rule: %s | Client: %s",
			qName, dns.TypeToString[qType], ruleName, clientInfo)
	}
	return answers, true
}

// isBlockedIP checks if a net.IP is unspecified or loopback.
func isBlockedIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

func (hc *HostsCache) LookupPTR(qName, clientInfo, ruleName string) ([]dns.RR, bool) {
	hc.RLock()
	defer hc.RUnlock()

	// USE SHARED UTILITY FUNCTION HERE
	ip := ExtractIPFromPTR(qName)
	if ip == nil {
		return nil, false
	}

	if hc.filterResponses {
		contains, err := hc.ipRanger.Contains(ip)
		if err == nil && contains {
			return nil, false
		}
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
	LogDebug("[HOSTS] PTR Resolved: %s -> %v | Rule: %s | Client: %s", qName, names, ruleName, clientInfo)
	return answers, true
}

