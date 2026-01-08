/*
File: hosts_loader.go
Version: 1.0.0
Description: Contains logic for parsing, loading, optimizing, and disk-caching HOSTS data.
             Extracted from hosts.go.
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io"
	"net"
	"net/http"
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

type SourceData struct {
	Forward map[string][]net.IP
	Reverse map[string][]string
	Names   int
	IPs     int
	MTime   time.Time
	Meta    urlMeta
}

type SourceCache map[string]*SourceData

// BatchLoadSources loads multiple paths/URLs concurrently.
func BatchLoadSources(paths []string, urls []string, cacheDir string) SourceCache {
	cache := make(SourceCache)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create cache dir if it doesn't exist
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			LogWarn("[HOSTS] Failed to create cache dir %s: %v", cacheDir, err)
			cacheDir = "" // Disable caching if failed
		}
	}

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

	LogInfo("[HOSTS] Global Batch Load: %d unique files, %d unique URLs (CacheDir: %s)", len(uniquePaths), len(uniqueUrls), cacheDir)

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

			// 1. Try Load from Disk Cache
			if cacheDir != "" {
				if data := loadFromDiskCache(cacheDir, p, false); data != nil {
					// Verify MTime
					info, err := os.Stat(p)
					if err == nil && !info.ModTime().After(data.MTime) {
						LogInfo("[HOSTS] Loaded %s from disk cache", p)
						add(p, data)
						return
					}
				}
			}

			fwd := make(map[string][]net.IP)
			rev := make(map[string][]string)
			names, ips, mtime := loadFileInternal(p, fwd, rev)

			data := &SourceData{Forward: fwd, Reverse: rev, Names: names, IPs: ips, MTime: mtime}
			add(p, data)

			// Save to Disk Cache
			if cacheDir != "" && names > 0 {
				saveToDiskCache(cacheDir, p, false, data)
			}
		}(path)
	}

	client := &http.Client{Timeout: 15 * time.Second}

	for url := range uniqueUrls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 1. Try Load from Disk Cache (Startup Optimization)
			if cacheDir != "" {
				if data := loadFromDiskCache(cacheDir, u, true); data != nil {
					LogInfo("[HOSTS] Loaded URL %s from disk cache (will revalidate later)", u)
					add(u, data)
					return
				}
			}

			fwd := make(map[string][]net.IP)
			rev := make(map[string][]string)
			names, ips, meta := loadURLInternal(client, u, fwd, rev, urlMeta{})

			data := &SourceData{Forward: fwd, Reverse: rev, Names: names, IPs: ips, Meta: meta}
			add(u, data)

			// Save to Disk Cache
			if cacheDir != "" && names > 0 {
				saveToDiskCache(cacheDir, u, true, data)
			}
		}(url)
	}

	wg.Wait()
	return cache
}

// --- Disk Cache Logic ---

func getCacheFilename(cacheDir, key string, isURL bool) string {
	hash := sha256.Sum256([]byte(key))
	prefix := "file_"
	if isURL {
		prefix = "url_"
	}
	return filepath.Join(cacheDir, prefix+hex.EncodeToString(hash[:])+".bin")
}

func loadFromDiskCache(cacheDir, key string, isURL bool) *SourceData {
	filename := getCacheFilename(cacheDir, key, isURL)
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	var data SourceData
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&data); err != nil {
		LogWarn("[HOSTS] Failed to decode cache for %s: %v", key, err)
		os.Remove(filename) // Corrupt cache
		return nil
	}
	return &data
}

func saveToDiskCache(cacheDir, key string, isURL bool, data *SourceData) {
	filename := getCacheFilename(cacheDir, key, isURL)

	// Atomic write: write to temp file then rename
	tmpFile, err := os.CreateTemp(cacheDir, "tmp_cache_*")
	if err != nil {
		LogWarn("[HOSTS] Failed to create temp cache file: %v", err)
		return
	}

	enc := gob.NewEncoder(tmpFile)
	if err := enc.Encode(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		LogWarn("[HOSTS] Failed to encode cache for %s: %v", key, err)
		return
	}
	tmpFile.Close()

	if err := os.Rename(tmpFile.Name(), filename); err != nil {
		LogWarn("[HOSTS] Failed to rename cache file: %v", err)
		os.Remove(tmpFile.Name())
	} else {
		LogInfo("[HOSTS] Saved cache for %s", key)
	}
}

// --- Parsing Logic ---

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

		// Find first field delimiter
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

		// Check if first field is IP
		ip := net.ParseIP(string(firstField))

		if ip != nil {
			// --- HOSTS FORMAT (IP Hostname...) ---
			// Need at least one hostname
			// Scan 'rest' to see if there is any non-whitespace content
			hasHosts := false
			if len(rest) > 0 {
				for _, b := range rest {
					if b != ' ' && b != '\t' {
						hasHosts = true
						break
					}
				}
			}
			if !hasHosts {
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

			// Iterate over hostnames in 'rest' without allocating a slice
			pos := 0
			end := len(rest)
			for pos < end {
				// Skip whitespace
				for pos < end && (rest[pos] == ' ' || rest[pos] == '\t') {
					pos++
				}
				if pos >= end {
					break
				}

				// Find end of token
				tokenStart := pos
				for pos < end && rest[pos] != ' ' && rest[pos] != '\t' {
					pos++
				}
				hostBytes := rest[tokenStart:pos]

				// Process hostname
				// Note: strings.Trim/ToLower allocates, but it's unavoidable for the map key.
				host := string(hostBytes)
				host = strings.ToLower(strings.Trim(host, "."))

				if host == "" {
					continue
				}
				// Skip if hostname looks like an IP
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
			// --- DOMAINS FORMAT (Domain) ---
			domainsCount++
			host := string(firstField)
			host = strings.ToLower(strings.Trim(host, "."))

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
	LogInfo("[HOSTS] Parsed file %s (%s): %d names", path, format, names)
	return names, 0, mtime
}

func loadURLInternal(client *http.Client, url string, fwd map[string][]net.IP, rev map[string][]string, oldMeta urlMeta) (int, int, urlMeta) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		LogWarn("[HOSTS] Invalid URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	if oldMeta.ETag != "" {
		req.Header.Set("If-None-Match", oldMeta.ETag)
	}
	if oldMeta.LastModified != "" {
		req.Header.Set("If-Modified-Since", oldMeta.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		LogWarn("[HOSTS] Failed to fetch URL %s: %v", url, err)
		return 0, 0, urlMeta{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		LogInfo("[HOSTS] URL %s not modified (304)", url)
		return 0, 0, oldMeta
	}

	if resp.StatusCode != http.StatusOK {
		LogWarn("[HOSTS] URL %s returned status %d", url, resp.StatusCode)
		return 0, 0, urlMeta{}
	}

	meta := urlMeta{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	names, _, format := parseReader(url, resp.Body, fwd, rev)
	LogInfo("[HOSTS] Parsed URL %s (%s): %d names", url, format, names)
	return names, 0, meta
}

// --- Optimization Logic (defined on HostsCache but located here for grouping) ---

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

