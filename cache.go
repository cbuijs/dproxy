/*
File: cache.go
Version: 2.2.0
Description: Thread-safe in-memory DNS cache using Sharded LRU eviction.
UPDATED: Implemented MinNegTTL in addToCache fallback logic.
UPDATED: Maintenance logging now shows MaxNegTTL and HostsTTL.
*/

package main

import (
	"container/list"
	"context"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const shardCount = 256

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
	sync.Mutex
	items   map[string]*list.Element
	lruList *list.List
}

type DNSCache struct {
	shards    [shardCount]*CacheShard
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
	}
	return c
}

func (c *DNSCache) getShard(key string) *CacheShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%uint32(shardCount)]
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
// This is the legacy function for backwards compatibility.
func getFromCache(key string, reqID uint16) *dns.Msg {
	msg, _ := getFromCacheWithTTL(key, reqID)
	return msg
}

// getFromCacheWithTTL retrieves a cached response and returns both the message and
// the actual remaining TTL in seconds. This is used for more detailed cache hit logging.
func getFromCacheWithTTL(key string, reqID uint16) (*dns.Msg, uint32) {
	if !dnsCache.enabled {
		return nil, 0
	}

	shard := dnsCache.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	elem, found := shard.items[key]
	if !found {
		return nil, 0
	}

	entry := elem.Value.(*CacheItem)

	// Check TTL
	now := time.Now()
	if now.After(entry.Expiration) {
		// Lazy eviction
		shard.lruList.Remove(elem)
		delete(shard.items, key)
		resetCacheHitCount(key) // Clean up hit counter
		return nil, 0
	}

	// Move to front (Mark as recently used)
	shard.lruList.MoveToFront(elem)

	// Record hit for stale refresh popularity tracking
	recordCacheHit(key)

	// Unpack from bytes to a fresh message
	msg := getMsg()
	if err := msg.Unpack(entry.MsgBytes); err != nil {
		// If unpack fails (corruption?), invalidate entry
		shard.lruList.Remove(elem)
		delete(shard.items, key)
		resetCacheHitCount(key)
		putMsg(msg)
		return nil, 0
	}

	msg.Id = reqID

	// Calculate the actual remaining TTL (time left in cache)
	remainingSeconds := uint32(entry.Expiration.Sub(now).Seconds())
	if remainingSeconds <= 0 {
		putMsg(msg) // Should have been caught by expiration check, but safety first
		return nil, 0
	}

	// Adjust TTLs in the response to reflect remaining time
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

	// Only cache Success and NXDOMAIN
	// (Unless we want to allow REFUSED/SERVFAIL caching in future, but currently sticking to standard)
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	// Determine minTTL from records (TTL clamping already applied in process.go,
	// so these values should be within the configured limits)
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

	// If no records found (e.g. NXDOMAIN with no SOA), we need a default negative TTL.
	// We use the configured MinNegTTL if available, otherwise default to 60.
	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		if config.Cache.MinNegTTL > 0 {
			minTTL = uint32(config.Cache.MinNegTTL)
		} else {
			minTTL = 60
		}
	} else if !foundTTL {
		// Empty response with no RCode error? Don't cache if we can't determine TTL.
		return
	}

	if minTTL == 0 {
		return
	}

	// PACK the message before locking
	packed, err := msg.Pack()
	if err != nil {
		return
	}

	// Create a copy of the slice to ensure we own the memory and it fits tightly
	finalBytes := make([]byte, len(packed))
	copy(finalBytes, packed)

	// Extract query info for stale refresh
	var qName string
	var qType, qClass uint16
	var routingKey string
	if len(msg.Question) > 0 {
		qName = msg.Question[0].Name
		qType = msg.Question[0].Qtype
		qClass = msg.Question[0].Qclass
	}

	// Parse routing key from cache key
	parts := strings.Split(key, "|")
	if len(parts) >= 4 {
		routingKey = parts[3]
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
			resetCacheHitCount(oldestEntry.Key) // Clean up hit counter
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

func pruneExpired() {
	// Prune a small batch from every shard
	now := time.Now()
	cleaned := 0

	for _, shard := range dnsCache.shards {
		shard.Lock()
		for i := 0; i < 5; i++ { // Check oldest 5 items per shard
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
				// LRU list is ordered, so if tail isn't expired, nothing else is (mostly)
				break
			}
		}
		shard.Unlock()
	}

	if cleaned > 0 {
		LogDebug("[CACHE] Pruned %d expired items across shards", cleaned)
	}
}

// scanAndRefreshStale updated to handle sharding (used by prefetch.go)
func ScanCacheForStale(thresholdPct, minHits int, callback func(entry *CacheItem, hitCount int64)) {
	now := time.Now()
	
	for _, shard := range dnsCache.shards {
		// Lock each shard individually to avoid blocking the whole world
		shard.Lock()
		// Iterate over items
		for key, elem := range shard.items {
			entry := elem.Value.(*CacheItem)
			
			// Calculate remaining TTL percentage
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
		shard.Unlock()
	}
}

// getCacheStats returns current cache statistics
func getCacheStats() (size int, capacity int) {
	size = 0
	for _, shard := range dnsCache.shards {
		shard.Lock()
		size += shard.lruList.Len()
		shard.Unlock()
	}
	return size, dnsCache.capacity
}

