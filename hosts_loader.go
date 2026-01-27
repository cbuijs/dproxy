/*
File: hosts_loader.go
Version: 3.0.1 (Fix unused import)
Description: Contains logic for parsing, loading, optimizing, and disk-caching HOSTS data.
             FIXED: Removed unused "net" import.
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type urlMeta struct {
	ETag         string
	LastModified string
}

// SourceData holds the parsed data from a single source.
// OPTIMIZED: 
// - 'Blocked' uses map[string]struct{} for zero-allocation sets (0.0.0.0 targets).
// - 'Forward' retains map[string][]netip.Addr only for non-blocked/custom IPs.
// - 'Allowed' uses map[string]struct{} for simple allowlists.
type SourceData struct {
	Blocked    map[string]struct{}     // Domains blocked with 0.0.0.0 or ::
	Forward    map[string][]netip.Addr // Domains redirected to specific IPs
	Reverse    map[string][]string
	Allowed    map[string][]netip.Addr // Domains allowed (potentially with spoof IPs)
	Filters    []netip.Prefix          // IP filters
	SourceName string                  
	Names      int
	IPs        int
	MTime      time.Time
	Meta       urlMeta
}

// SourceCache is a map of source identifiers (path or URL) to their parsed data.
type SourceCache map[string]*SourceData

// BatchLoadSources loads multiple paths/URLs concurrently.
func BatchLoadSources(paths []string, urls []string, cacheDir string) SourceCache {
	cache := make(SourceCache)
	var mu sync.Mutex
	var wg sync.WaitGroup

	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			LogWarn("[HOSTS] Failed to create cache dir %s: %v", cacheDir, err)
			cacheDir = "" 
		}
	}

	uniquePaths := make(map[string]bool)
	for _, p := range paths { uniquePaths[p] = true }

	uniqueUrls := make(map[string]bool)
	for _, u := range urls { uniqueUrls[u] = true }

	maxConcurrency := runtime.NumCPU() * 2
	if maxConcurrency < 4 { maxConcurrency = 4 }
	sem := make(chan struct{}, maxConcurrency)

	LogInfo("[HOSTS] Global Batch Load: %d unique files, %d unique URLs (CacheDir: %s)", len(uniquePaths), len(uniqueUrls), cacheDir)

	add := func(key string, data *SourceData) {
		mu.Lock()
		cache[key] = data
		mu.Unlock()
	}

	// Helper to load
	load := func(key string, isURL bool) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		isAllowlist := false
		actualKey := key
		if strings.HasPrefix(key, "!") {
			isAllowlist = true
			actualKey = strings.TrimPrefix(key, "!")
		}

		// Try Disk Cache
		if cacheDir != "" {
			if data := loadFromDiskCache(cacheDir, key, isURL); data != nil {
				// Check staleness
				valid := true
				if !isURL {
					info, err := os.Stat(actualKey)
					if err != nil || info.ModTime().After(data.MTime) { valid = false }
				}
				
				if valid {
					LogInfo("[HOSTS] Loaded %s from disk cache (Blocked: %d, Forward: %d, Allowed: %d)", 
						key, len(data.Blocked), len(data.Forward), len(data.Allowed))
					add(key, data)
					return
				}
			}
		}

		blocked := make(map[string]struct{})
		fwd := make(map[string][]netip.Addr)
		rev := make(map[string][]string)
		allowed := make(map[string][]netip.Addr)
		var filters []netip.Prefix
		
		var names, ips int
		var mtime time.Time
		var meta urlMeta

		if isURL {
			client := &http.Client{Timeout: 15 * time.Second}
			names, ips, meta = loadURLInternal(client, actualKey, blocked, fwd, rev, allowed, &filters, isAllowlist, urlMeta{}, key)
		} else {
			names, ips, mtime = loadFileInternal(actualKey, blocked, fwd, rev, allowed, &filters, isAllowlist, key)
		}

		data := &SourceData{
			Blocked:    blocked,
			Forward:    fwd,
			Reverse:    rev,
			Allowed:    allowed,
			Filters:    filters,
			Names:      names,
			IPs:        ips,
			MTime:      mtime,
			Meta:       meta,
			SourceName: key,
		}
		add(key, data)

		if cacheDir != "" && names > 0 {
			saveToDiskCache(cacheDir, key, isURL, data)
		}
	}

	for p := range uniquePaths {
		wg.Add(1)
		go load(p, false)
	}
	for u := range uniqueUrls {
		wg.Add(1)
		go load(u, true)
	}

	wg.Wait()
	return cache
}

// --- Disk Cache Logic ---

func getCacheFilename(cacheDir, key string, isURL bool) string {
	hash := sha256.Sum256([]byte(key))
	prefix := "file_"
	if isURL { prefix = "url_" }
	return filepath.Join(cacheDir, prefix+hex.EncodeToString(hash[:])+".bin")
}

func loadFromDiskCache(cacheDir, key string, isURL bool) *SourceData {
	filename := getCacheFilename(cacheDir, key, isURL)
	f, err := os.Open(filename)
	if err != nil { return nil }
	defer f.Close()

	var data SourceData
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&data); err != nil {
		os.Remove(filename)
		return nil
	}
	return &data
}

func saveToDiskCache(cacheDir, key string, isURL bool, data *SourceData) {
	filename := getCacheFilename(cacheDir, key, isURL)
	tmpFile, err := os.CreateTemp(cacheDir, "tmp_cache_*")
	if err != nil { return }

	enc := gob.NewEncoder(tmpFile)
	if err := enc.Encode(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return
	}
	tmpFile.Close()
	os.Rename(tmpFile.Name(), filename)
}

// --- Parsing Logic ---

func isBlockedAddr(addr netip.Addr) bool {
	return addr.IsUnspecified() || addr.IsLoopback()
}

func parseReader(sourceName string, r io.Reader, blocked map[string]struct{}, forward map[string][]netip.Addr, reverse map[string][]string, allowed map[string][]netip.Addr, filters *[]netip.Prefix, isGlobalAllowlist bool) (int, int, string) {
	addedNames := 0
	addedIPs := 0
	hostsCount := 0
	domainsCount := 0
	filterCount := 0
	
	nothing := struct{}{}

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

		splitIdx := -1
		for i, b := range lineBytes {
			if b == ' ' || b == '\t' {
				splitIdx = i
				break
			}
		}

		var firstField, rest []byte
		if splitIdx == -1 {
			firstField = lineBytes
			rest = nil
		} else {
			firstField = lineBytes[:splitIdx]
			rest = lineBytes[splitIdx+1:]
		}

		firstFieldStr := string(firstField)

		var ip netip.Addr
		var prefix netip.Prefix
		var err error
		isCIDR := false

		if strings.IndexByte(firstFieldStr, '/') != -1 {
			prefix, err = netip.ParsePrefix(firstFieldStr)
			if err == nil { isCIDR = true }
		}
		if !isCIDR {
			ip, err = netip.ParseAddr(firstFieldStr)
		}

		if isCIDR {
			// Filters logic...
			*filters = append(*filters, prefix)
			filterCount++
			continue
		}

		if err == nil && ip.IsValid() {
			// HOSTS format
			hostsCount++
			isBlocked := isBlockedAddr(ip)
			
			if !isBlocked && !isGlobalAllowlist {
				ipKey := ip.String()
				if _, exists := reverse[ipKey]; !exists {
					addedIPs++
				}
			}

			// Iterate hostnames
			pos := 0
			end := len(rest)
			for pos < end {
				for pos < end && (rest[pos] == ' ' || rest[pos] == '\t') { pos++ }
				if pos >= end { break }
				tokenStart := pos
				for pos < end && rest[pos] != ' ' && rest[pos] != '\t' { pos++ }
				
				hostBytes := rest[tokenStart:pos]
				isLineAllow := false
				if len(hostBytes) > 0 && hostBytes[0] == '!' {
					isLineAllow = true
					hostBytes = hostBytes[1:]
				}

				host := string(hostBytes)
				host = strings.ToLower(strings.Trim(host, "."))
				if host == "" { continue }
				if _, err := netip.ParseAddr(host); err == nil { continue }

				if isGlobalAllowlist || isLineAllow {
					// Add to Allowed
					allowed[host] = append(allowed[host], ip)
				} else {
					if isBlocked {
						// Optimized: Add to Blocked Set
						blocked[host] = nothing
					} else {
						// Add to Forward Map
						forward[host] = append(forward[host], ip)
						reverse[ip.String()] = append(reverse[ip.String()], host)
					}
				}
				addedNames++
			}

		} else {
			// DOMAINS format
			domainsCount++
			isLineAllow := false
			if len(firstField) > 0 && firstField[0] == '!' {
				isLineAllow = true
				firstField = firstField[1:]
			}
			host := string(firstField)
			host = strings.ToLower(strings.Trim(host, "."))
			if host != "" {
				if _, err := netip.ParseAddr(host); err == nil { continue }
				
				if isGlobalAllowlist || isLineAllow {
					allowed[host] = nil 
				} else {
					blocked[host] = nothing
				}
				addedNames++
			}
		}
	}

	format := "UNKNOWN"
	if hostsCount > 0 { format = "HOSTS" } else if domainsCount > 0 { format = "DOMAINS" }
	return addedNames, addedIPs, format
}

func loadFileInternal(path string, blocked map[string]struct{}, fwd map[string][]netip.Addr, rev map[string][]string, allowed map[string][]netip.Addr, filters *[]netip.Prefix, isAllowlist bool, sourceName string) (int, int, time.Time) {
	file, err := os.Open(path)
	if err != nil {
		LogWarn("[HOSTS] Failed to open file %s: %v", path, err)
		return 0, 0, time.Time{}
	}
	defer file.Close()
	info, err := file.Stat()
	mtime := time.Time{}
	if err == nil { mtime = info.ModTime() }
	
	names, _, format := parseReader(sourceName, file, blocked, fwd, rev, allowed, filters, isAllowlist)
	LogInfo("[HOSTS] Parsed file %s (%s): %d names (Blocked: %d, Forward: %d, Allowed: %d)", sourceName, format, names, len(blocked), len(fwd), len(allowed))
	return names, 0, mtime
}

func loadURLInternal(client *http.Client, url string, blocked map[string]struct{}, fwd map[string][]netip.Addr, rev map[string][]string, allowed map[string][]netip.Addr, filters *[]netip.Prefix, isAllowlist bool, oldMeta urlMeta, sourceName string) (int, int, urlMeta) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return 0, 0, urlMeta{} }
	if oldMeta.ETag != "" { req.Header.Set("If-None-Match", oldMeta.ETag) }
	
	resp, err := client.Do(req)
	if err != nil {
		LogWarn("[HOSTS] Failed to fetch URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return 0, 0, oldMeta
	}
	
	meta := urlMeta{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	names, _, format := parseReader(sourceName, resp.Body, blocked, fwd, rev, allowed, filters, isAllowlist)
	LogInfo("[HOSTS] Parsed URL %s (%s): %d names (Blocked: %d, Forward: %d, Allowed: %d)", sourceName, format, names, len(blocked), len(fwd), len(allowed))
	return names, 0, meta
}

