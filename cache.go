/*
File: cache.go
Version: 2.4.0
Description: Thread-safe in-memory DNS cache using Sharded LRU eviction.
             UPDATED: Added NXCache (Negative Intelligence) for "harden-below-nxdomain".
             UPDATED: Added Debug Logging when Harden-Below-NXDOMAIN triggers.
             OPTIMIZED: Switched to RWMutex to allow non-blocking reads for background scans.
*/

package main

import (
	"container/list"
	"context"
	"hash/maphash"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const shardCount = 256

// Global seed for maphash to ensure consistent hashing per process run
var hasherSeed = maphash.MakeSeed()

type CacheItem struct {
	Key         string
	MsgBytes    []byte // Store raw bytes
	Expiration  time.Time
	OriginalTTL uint32 // Original TTL for stale refresh calculation
	QName       string // Query name for refresh
	QType       uint16 // Query type for refresh
	QClass      uint16 // Query class for refresh
	RoutingKey  string // Routing key for refresh
}

type CacheShard struct {
	sync.RWMutex
	items   map[string]*list.Element
	lruList *list.List
}

// NXCacheShard is a lightweight store for NXDOMAIN facts
type NXCacheShard struct {
	sync.RWMutex
	items map[string]time.Time // Key (Domain|RoutingKey) -> Expiration
}

type DNSCache struct {
	shards    [shardCount]*CacheShard
	nxShards  [shardCount]*NXCacheShard
	capacity  int // Total capacity
	shardCap  int // Capacity per shard
	enabled   bool
}

// Global cache instance
var dnsCache = newDNSCache()

func newDNSCache() *DNSCache {
	c := &DNSCache{
		enabled: true,
	}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &CacheShard{
			items:   make(map[string]*list.Element),
			lruList: list.New(),
		}
		c.nxShards[i] = &NXCacheShard{
			items: make(map[string]time.Time),
		}
	}
	return c
}

func (c *DNSCache) getShard(key string) *CacheShard {
	var h maphash.Hash
	h.SetSeed(hasherSeed)
	h.WriteString(key)
	return c.shards[h.Sum64()&(shardCount-1)]
}

func (c *DNSCache) getNXShard(key string) *NXCacheShard {
	var h maphash.Hash
	h.SetSeed(hasherSeed)
	h.WriteString(key)
	return c.nxShards[h.Sum64()&(shardCount-1)]
}

func maintainDNSCache(ctx context.Context) {
	// Update capacity from config
	totalCap := 10000
	if config.Cache.Size > 0 {
		totalCap = config.Cache.Size
	}
	dnsCache.capacity = totalCap
	dnsCache.shardCap = totalCap / shardCount
	if dnsCache.shardCap < 1 {
		dnsCache.shardCap = 1
	}
	dnsCache.enabled = config.Cache.Enabled

	LogInfo("[CACHE] Starting maintenance (Capacity: %d, Type: Sharded LRU [%d shards])", totalCap, shardCount)
	
	// Log TTL configuration
	if config.Cache.MinTTL > 0 || config.Cache.MaxTTL > 0 || config.Cache.MinNegTTL > 0 || config.Cache.MaxNegTTL > 0 {
		LogInfo("[CACHE] TTL Control: MinTTL=%ds, MaxTTL=%ds, MinNegTTL=%ds, MaxNegTTL=%ds", 
			config.Cache.MinTTL, config.Cache.MaxTTL, config.Cache.MinNegTTL, config.Cache.MaxNegTTL)
	}

	if config.Cache.HostsTTL > 0 {
		LogInfo("[CACHE] Hosts File TTL: %ds", config.Cache.HostsTTL)
	}

	// Log TTL Strategy if enabled
	if config.Cache.TTLStrategy != "" && config.Cache.TTLStrategy != "none" {
		LogInfo("[CACHE] TTL Strategy: %s", config.Cache.TTLStrategy)
	}

	if config.Cache.HardenBelowNXDOMAIN {
		LogInfo("[CACHE] Harden Below NXDOMAIN: Enabled (Stopping sub-queries for non-existent parents)")
	}

	// Initialize prefetch subsystem
	initPrefetch()

	// Start stale refresh maintenance in separate goroutine
	if config.Cache.Prefetch.StaleRefresh.Enabled {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			maintainStaleRefresh(ctx)
		}()
	}

	// Ticker for strictly expired items (cleanup)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			LogInfo("[CACHE] Stopping maintenance")
			return
		case <-ticker.C:
			pruneExpired()
		}
	}
}

// getFromCache retrieves a cached response and updates the TTLs to reflect remaining time.
func getFromCache(key string, reqID uint16) *dns.Msg {
	msg, _ := getFromCacheWithTTL(key, reqID)
	return msg
}

// getFromCacheWithTTL retrieves a cached response and returns both the message and
// the actual remaining TTL in seconds.
func getFromCacheWithTTL(key string, reqID uint16) (*dns.Msg, uint32) {
	if !dnsCache.enabled {
		return nil, 0
	}

	shard := dnsCache.getShard(key)
	
	// LOCK SCOPE: Restricted only to map lookup and LRU update
	shard.Lock()
	elem, found := shard.items[key]
	if !found {
		shard.Unlock()
		return nil, 0
	}

	entry := elem.Value.(*CacheItem)
	now := time.Now()

	// Check TTL
	if now.After(entry.Expiration) {
		// Lazy eviction
		shard.lruList.Remove(elem)
		delete(shard.items, key)
		resetCacheHitCount(key)
		shard.Unlock()
		return nil, 0
	}

	// Move to front (Mark as recently used)
	shard.lruList.MoveToFront(elem)
	
	// Grab reference to bytes safely while locked
	// The byte slice itself is immutable in our usage pattern
	msgBytes := entry.MsgBytes
	expiration := entry.Expiration
	shard.Unlock()
	// END LOCK SCOPE

	// Record hit (using atomic counters, thread-safe)
	recordCacheHit(key)

	// EXPENSIVE OP: Unpack happens outside lock
	msg := getMsg()
	if err := msg.Unpack(msgBytes); err != nil {
		// If corruption, we might want to delete it, but acquiring lock again is expensive.
		// Just drop it for now.
		putMsg(msg)
		return nil, 0
	}

	msg.Id = reqID

	// Calculate remaining TTL
	remainingSeconds := uint32(expiration.Sub(now).Seconds())
	if remainingSeconds <= 0 {
		putMsg(msg)
		return nil, 0
	}

	// Adjust TTLs (CPU work, safe outside lock)
	updateTTL := func(rrs []dns.RR) {
		for _, rr := range rrs {
			rr.Header().Ttl = remainingSeconds
		}
	}
	updateTTL(msg.Answer)
	updateTTL(msg.Ns)
	updateTTL(msg.Extra)

	return msg, remainingSeconds
}

func addToCache(key string, msg *dns.Msg) {
	if !dnsCache.enabled {
		return
	}

	// --- Harden NXDOMAIN Logic ---
	// If the response is NXDOMAIN, we cache this fact separately to support "harden-below-nxdomain"
	// We extract the RoutingKey from the main cache key to ensure we don't bleed NX facts across views.
	// Key format: Name|Type|Class|RoutingKey
	var routingKey string
	parts := strings.Split(key, "|")
	if len(parts) >= 4 {
		routingKey = parts[3]
	}

	// Calculate minTTL for the record
	minTTL := uint32(3600)
	foundTTL := false
	checkRR := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			foundTTL = true
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}
	checkRR(msg.Answer)
	checkRR(msg.Ns)
	checkRR(msg.Extra)

	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		if config.Cache.MinNegTTL > 0 {
			minTTL = uint32(config.Cache.MinNegTTL)
		} else {
			minTTL = 60
		}
	}

	// If this is an NXDOMAIN response, store it in the lightweight NXCache
	if msg.Rcode == dns.RcodeNameError && len(msg.Question) > 0 {
		qName := msg.Question[0].Name
		addNXDomain(qName, routingKey, minTTL)
	}

	// --- Standard Caching Logic ---

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	if !foundTTL && msg.Rcode != dns.RcodeNameError {
		return // Don't cache success without TTLs (unless we default them, but risky)
	}

	if minTTL == 0 {
		return
	}

	// PACK the message before locking
	packed, err := msg.Pack()
	if err != nil {
		return
	}

	finalBytes := make([]byte, len(packed))
	copy(finalBytes, packed)

	var qName string
	var qType, qClass uint16
	if len(msg.Question) > 0 {
		qName = msg.Question[0].Name
		qType = msg.Question[0].Qtype
		qClass = msg.Question[0].Qclass
	}

	expiration := time.Now().Add(time.Duration(minTTL) * time.Second)

	shard := dnsCache.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	// Check if update or new
	if elem, found := shard.items[key]; found {
		shard.lruList.MoveToFront(elem)
		entry := elem.Value.(*CacheItem)
		entry.MsgBytes = finalBytes
		entry.Expiration = expiration
		entry.OriginalTTL = minTTL
		entry.QName = qName
		entry.QType = qType
		entry.QClass = qClass
		entry.RoutingKey = routingKey
		return
	}

	// Evict if full
	if shard.lruList.Len() >= dnsCache.shardCap {
		if oldest := shard.lruList.Back(); oldest != nil {
			shard.lruList.Remove(oldest)
			oldestEntry := oldest.Value.(*CacheItem)
			delete(shard.items, oldestEntry.Key)
			resetCacheHitCount(oldestEntry.Key)
		}
	}

	// Add new
	item := &CacheItem{
		Key:         key,
		MsgBytes:    finalBytes,
		Expiration:  expiration,
		OriginalTTL: minTTL,
		QName:       qName,
		QType:       qType,
		QClass:      qClass,
		RoutingKey:  routingKey,
	}
	elem := shard.lruList.PushFront(item)
	shard.items[key] = elem
}

// addNXDomain adds a domain to the NX cache
func addNXDomain(qName, routingKey string, ttl uint32) {
	if ttl == 0 {
		return
	}
	
	key := qName + "|" + routingKey
	shard := dnsCache.getNXShard(key)
	
	shard.Lock()
	shard.items[key] = time.Now().Add(time.Duration(ttl) * time.Second)
	shard.Unlock()
}

// CheckParentNXDomain checks if the domain or any of its parents are known to be NXDOMAIN.
// Returns true and the remaining TTL if found.
func CheckParentNXDomain(qName, routingKey string) (bool, uint32) {
	// Start with the full domain (harden "at" nxdomain) and walk up
	// e.g., a.b.c.com -> a.b.c.com, b.c.com, c.com, com
	
	current := qName
	now := time.Now()

	for {
		// Key format matches addNXDomain
		key := current + "|" + routingKey
		
		shard := dnsCache.getNXShard(key)
		shard.RLock()
		expires, found := shard.items[key]
		shard.RUnlock()

		if found {
			if now.Before(expires) {
				remaining := uint32(expires.Sub(now).Seconds())
				// DEBUG LOG ADDED HERE
				LogDebug("[CACHE] HardenNX: Parent %s is NXDOMAIN (TTL: %d), blocking %s", current, remaining, qName)
				return true, remaining
			} else {
				// Lazy cleanup on read miss (can be skipped, prune handles it)
			}
		}

		// Move up one label
		idx := strings.IndexByte(current, '.')
		if idx == -1 || idx == len(current)-1 {
			// No more parents (or just root left)
			break
		}
		current = current[idx+1:]
	}

	return false, 0
}


func pruneExpired() {
	now := time.Now()
	cleaned := 0
	cleanedNX := 0

	// Prune Standard Cache
	for _, shard := range dnsCache.shards {
		shard.Lock()
		for i := 0; i < 5; i++ {
			elem := shard.lruList.Back()
			if elem == nil {
				break
			}
			entry := elem.Value.(*CacheItem)
			if now.After(entry.Expiration) {
				shard.lruList.Remove(elem)
				delete(shard.items, entry.Key)
				resetCacheHitCount(entry.Key)
				cleaned++
			} else {
				break
			}
		}
		shard.Unlock()
	}

	// Prune NX Cache (Random sampling or full scan? Map doesn't support order, so strict iteration is expensive)
	// We'll just do a quick pass if enabled, maybe limiting the number of keys we check per interval
	// For simplicity in this version, we scan all (since it's per minute)
	for _, shard := range dnsCache.nxShards {
		shard.Lock()
		for k, expires := range shard.items {
			if now.After(expires) {
				delete(shard.items, k)
				cleanedNX++
			}
		}
		shard.Unlock()
	}

	if cleaned > 0 || cleanedNX > 0 {
		LogDebug("[CACHE] Pruned %d expired items and %d NX facts", cleaned, cleanedNX)
	}
}

// ScanCacheForStale updated to use RLock for non-blocking iteration
func ScanCacheForStale(thresholdPct, minHits int, callback func(entry *CacheItem, hitCount int64)) {
	now := time.Now()
	
	for _, shard := range dnsCache.shards {
		// OPTIMIZATION: Use RLock here. We are only reading items.
		// NOTE: This does NOT update LRU order, which is perfect for background scans.
		shard.RLock()
		
		for key, elem := range shard.items {
			entry := elem.Value.(*CacheItem)
			
			remainingTTL := entry.Expiration.Sub(now)
			if remainingTTL <= 0 {
				continue 
			}

			originalTTL := entry.OriginalTTL
			if originalTTL == 0 {
				continue 
			}

			remainingPct := int((remainingTTL.Seconds() / float64(originalTTL)) * 100)

			if remainingPct > thresholdPct {
				continue
			}

			hitCount := getCacheHitCount(key)
			if hitCount < int64(minHits) {
				continue
			}
			
			callback(entry, hitCount)
		}
		shard.RUnlock()
	}
}

func getCacheStats() (size int, capacity int) {
	size = 0
	for _, shard := range dnsCache.shards {
		shard.RLock()
		size += shard.lruList.Len()
		shard.RUnlock()
	}
	return size, dnsCache.capacity
}

