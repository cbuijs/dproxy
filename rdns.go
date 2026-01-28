/*
File: rdns.go
Version: 1.1.6 (Clean)
Description: Thread-safe, sharded LRU cache for Reverse DNS (PTR) lookups.
             Prevents logging subsystem from blocking on repetitive system resolver calls.
             UPDATED: Reverted debug logging to standard levels.
*/

package main

import (
	"container/list"
	"context"
	"hash/maphash"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	rdnsShardCount = 64
	rdnsCacheSize  = 4096
	rdnsTTL        = 1 * time.Hour
)

// Global instance
var globalRDNS = newRDNSCache()

type rdnsEntry struct {
	ip        string
	hostname  string
	expiresAt time.Time
}

type rdnsShard struct {
	sync.RWMutex
	items   map[string]*list.Element
	lruList *list.List
}

type RDNSCache struct {
	shards   [rdnsShardCount]*rdnsShard
	seed     maphash.Seed
	capacity int
}

func newRDNSCache() *RDNSCache {
	c := &RDNSCache{
		seed:     maphash.MakeSeed(),
		capacity: rdnsCacheSize / rdnsShardCount,
	}
	for i := 0; i < rdnsShardCount; i++ {
		c.shards[i] = &rdnsShard{
			items:   make(map[string]*list.Element),
			lruList: list.New(),
		}
	}
	return c
}

func (c *RDNSCache) getShard(key string) *rdnsShard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	h.WriteString(key)
	return c.shards[h.Sum64()&(rdnsShardCount-1)]
}

// GetHostname returns the cached hostname or resolves it via the system resolver.
// This ensures we never block the logging routine repeatedly for the same IP.
func (c *RDNSCache) GetHostname(ip net.IP) string {
	ipStr := ip.String()
	shard := c.getShard(ipStr)

	// 1. Fast Path: Read Lock
	shard.RLock()
	if elem, found := shard.items[ipStr]; found {
		entry := elem.Value.(*rdnsEntry)
		if time.Now().Before(entry.expiresAt) {
			name := entry.hostname
			shard.RUnlock()
			if IsDebugEnabled() {
				displayName := name
				if displayName == "" {
					displayName = "<NO_PTR>"
				}
				LogDebug("[RDNS] Cache Hit: %s -> %s", ipStr, displayName)
			}
			return name
		}
	}
	shard.RUnlock()

	// 2. Slow Path: Resolve (Network I/O)
	// We do this outside the lock to avoid blocking other readers.
	// Reduced timeout to 100ms to minimize latency impact on first request.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var hostname string
	names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	if IsDebugEnabled() {
		if err != nil {
			LogDebug("[RDNS] Lookup Failed for %s: %v (Time: %v)", ipStr, err, time.Since(start))
		} else if hostname == "" {
			LogDebug("[RDNS] Lookup Empty for %s (Time: %v)", ipStr, time.Since(start))
		} else {
			LogDebug("[RDNS] Resolved: %s -> %s (Time: %v)", ipStr, hostname, time.Since(start))
		}
	}

	// 3. Write Lock: Update Cache
	shard.Lock()
	defer shard.Unlock()

	// Double-check in case another goroutine filled it while we were resolving
	if elem, found := shard.items[ipStr]; found {
		entry := elem.Value.(*rdnsEntry)
		// Update TTL even if existing
		entry.expiresAt = time.Now().Add(rdnsTTL)
		shard.lruList.MoveToFront(elem)
		// If we resolved something better, update it. Otherwise keep existing (or empty).
		if hostname != "" {
			entry.hostname = hostname
		}
		return entry.hostname
	}

	// Evict if full
	if shard.lruList.Len() >= c.capacity {
		if oldest := shard.lruList.Back(); oldest != nil {
			shard.lruList.Remove(oldest)
			delete(shard.items, oldest.Value.(*rdnsEntry).ip)
		}
	}

	// Insert new
	entry := &rdnsEntry{
		ip:        ipStr,
		hostname:  hostname,
		expiresAt: time.Now().Add(rdnsTTL),
	}
	elem := shard.lruList.PushFront(entry)
	shard.items[ipStr] = elem

	return hostname
}

