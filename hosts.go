/*
File: hosts.go
Description: Handles loading and querying of HOSTS files.
OPTIMIZED: Wildcard lookup now iterates domain parents using string indexing instead of splitting.
*/

package main

import (
	"bufio"
	"bytes"
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

type SourceData struct {
	Forward map[string][]net.IP
	Reverse map[string][]string
	Names   int
	IPs     int
	MTime   time.Time
	Meta    urlMeta
}

type SourceCache map[string]*SourceData

type HostsCache struct {
	sync.RWMutex
	forward map[string][]net.IP
	reverse map[string][]string

	paths      []string
	urls       []string
	wildcard   bool
	performOpt bool
	defaultTTL uint32

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

func BatchLoadSources(paths []string, urls []string) SourceCache {
	cache := make(SourceCache)
	var mu sync.Mutex
	var wg sync.WaitGroup

	uniquePaths := make(map[string]bool)
	for _, p := range paths {
		uniquePaths[p] = true
	}

	uniqueUrls := make(map[string]bool)
	for _, u := range urls {
		uniqueUrls[u] = true
	}

	maxConcurrency := runtime.NumCPU() * 2
	if maxConcurrency < 4 {
		maxConcurrency = 4
	}
	sem := make(chan struct{}, maxConcurrency)

	LogInfo("[HOSTS] Global Batch Load: %d unique files, %d unique URLs", len(uniquePaths), len(uniqueUrls))

	add := func(key string, data *SourceData) {
		mu.Lock()
		cache[key] = data
		mu.Unlock()
	}

	for path := range uniquePaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fwd := make(map[string][]net.IP)
			rev := make(map[string][]string)
			names, ips, mtime := loadFileInternal(p, fwd, rev)

			add(p, &SourceData{Forward: fwd, Reverse: rev, Names: names, IPs: ips, MTime: mtime})
		}(path)
	}

	client := &http.Client{Timeout: 15 * time.Second}

	for url := range uniqueUrls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fwd := make(map[string][]net.IP)
			rev := make(map[string][]string)
			names, ips, meta := loadURLInternal(client, u, fwd, rev, urlMeta{})

			add(u, &SourceData{Forward: fwd, Reverse: rev, Names: names, IPs: ips, Meta: meta})
		}(url)
	}

	wg.Wait()
	return cache
}

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
			if data.Meta.etag != "" || data.Meta.lastModified != "" {
				newUrlMetas[key] = data.Meta
			}
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

	LogDebug("[HOSTS] Cache assembled from %d sources in %v (%d names)", totalSources, time.Since(start), len(newForward))
	return len(newForward), len(newReverse)
}

func (hc *HostsCache) Load(paths []string, urls []string, wildcard bool, optimize bool) {
	cache := BatchLoadSources(paths, urls)
	names, ips := hc.LoadFromCache(paths, urls, cache, wildcard, optimize)
	LogInfo("[HOSTS] Refresh complete: %d names, %d IPs", names, ips)
}

func (hc *HostsCache) optimize(fwd map[string][]net.IP, rev map[string][]string) {
	const parallelThreshold = 5000
	count := len(fwd)
	if count == 0 {
		return
	}

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

		toDeleteCh := make(chan string, count/10)
		var wg sync.WaitGroup
		chunkSize := (count + numWorkers - 1) / numWorkers

		for i := 0; i < numWorkers; i++ {
			start, end := i*chunkSize, (i+1)*chunkSize
			if start >= count {
				break
			}
			if end > count {
				end = count
			}
			wg.Add(1)
			go func(chunk []string) {
				defer wg.Done()
				hc.findRedundantKeysChannel(fwd, chunk, toDeleteCh)
			}(keys[start:end])
		}
		go func() { wg.Wait(); close(toDeleteCh) }()
		for k := range toDeleteCh {
			toDelete = append(toDelete, k)
		}
	}

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

func isBlockedIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

func parseReader(sourceName string, r io.Reader, forward map[string][]net.IP, reverse map[string][]string) (int, int, string) {
	addedNames := 0
	addedIPs := 0
	hostsCount := 0
	domainsCount := 0
	zeroIP := net.IPv4(0, 0, 0, 0)
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lineBytes := scanner.Bytes()
		if idx := bytes.IndexByte(lineBytes, '#'); idx >= 0 {
			lineBytes = lineBytes[:idx]
		}
		lineBytes = bytes.TrimSpace(lineBytes)
		if len(lineBytes) == 0 {
			continue
		}

		line := string(lineBytes)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		ipStr := fields[0]
		ip := net.ParseIP(ipStr)

		if ip != nil {
			if len(fields) < 2 {
				continue
			}
			hostsCount++
			isBlocked := isBlockedIP(ip)
			ipKey := ip.String()
			if !isBlocked {
				if _, exists := reverse[ipKey]; !exists {
					addedIPs++
				}
			}
			for _, originalHost := range fields[1:] {
				host := strings.ToLower(strings.Trim(originalHost, "."))
				if host == "" {
					continue
				}
				if net.ParseIP(host) != nil {
					continue
				}
				forward[host] = append(forward[host], ip)
				if !isBlocked {
					reverse[ipKey] = append(reverse[ipKey], host)
				}
				addedNames++
			}
		} else {
			domainsCount++
			originalHost := fields[0]
			host := strings.ToLower(strings.Trim(originalHost, "."))
			if host != "" {
				if net.ParseIP(host) != nil {
					continue
				}
				forward[host] = append(forward[host], zeroIP)
				addedNames++
			}
		}
	}

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

func loadFileInternal(path string, fwd map[string][]net.IP, rev map[string][]string) (int, int, time.Time) {
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

func loadURLInternal(client *http.Client, url string, fwd map[string][]net.IP, rev map[string][]string, oldMeta urlMeta) (int, int, urlMeta) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		LogWarn("[HOSTS] Invalid URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	if oldMeta.etag != "" {
		req.Header.Set("If-None-Match", oldMeta.etag)
	}
	if oldMeta.lastModified != "" {
		req.Header.Set("If-Modified-Since", oldMeta.lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		LogWarn("[HOSTS] Failed to fetch URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		LogDebug("[HOSTS] URL %s not modified (304)", url)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		req.Header.Del("If-None-Match")
		req.Header.Del("If-Modified-Since")
		resp, err = client.Do(req)
		if err != nil {
			return 0, 0, urlMeta{}
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		LogWarn("[HOSTS] URL %s returned status %d", url, resp.StatusCode)
		return 0, 0, urlMeta{}
	}

	meta := urlMeta{etag: resp.Header.Get("ETag"), lastModified: resp.Header.Get("Last-Modified")}
	names, _, format := parseReader(url, resp.Body, fwd, rev)
	LogDebug("[HOSTS] Parsed URL %s (%s): %d names", url, format, names)
	return names, 0, meta
}

func (hc *HostsCache) loadFile(path string, fwd map[string][]net.IP, rev map[string][]string) (int, int, time.Time) {
	return loadFileInternal(path, fwd, rev)
}
func (hc *HostsCache) loadURL(url string, fwd map[string][]net.IP, rev map[string][]string) (int, int, urlMeta) {
	hc.RLock()
	old := hc.urlMetas[url]
	hc.RUnlock()
	return loadURLInternal(hc.client, url, fwd, rev, old)
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
	return resp.StatusCode != http.StatusNotModified && resp.StatusCode == http.StatusOK
}

// Lookup queries the hosts cache.
// OPTIMIZED: Avoids strings.Split for wildcard matching
func (hc *HostsCache) Lookup(qName string, qType uint16, wildcard bool) ([]dns.RR, bool) {
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
		// Optimization: Walk the domain string finding dots to avoid allocation
		// qName: sub.example.com -> example.com -> com
		
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
		LogDebug("[HOSTS] Hit (%s): %s -> %s (BLOCKED -> Null Response, TTL: %d)", matchType, qName, matchedName, ttl)
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
		LogDebug("[HOSTS] Hit (%s): %s -> %s (Matches: %v, TTL: %d)", matchType, qName, matchedName, ips, ttl)
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
	LogDebug("[HOSTS] PTR Hit: %s -> %v (TTL: %d)", qName, names, ttl)
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

