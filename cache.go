/*
File: cache.go
Description: Thread-safe in-memory DNS cache using O(1) LRU eviction.
OPTIMIZED: Stores packed []byte instead of *dns.Msg to reduce GC pressure and memory usage.
UPDATED: Added support for prefetch (cross-fetch and stale refresh) with metadata tracking.
*/

package main

import (
	"container/list"
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

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

type DNSCache struct {
	sync.Mutex
	capacity int
	items    map[string]*list.Element
	lruList  *list.List
}

// Initialize with a default size; capacity is updated in maintainDNSCache based on config
var dnsCache = &DNSCache{
	capacity: 10000,
	items:    make(map[string]*list.Element),
	lruList:  list.New(),
}

func maintainDNSCache(ctx context.Context) {
	// Update capacity from config
	dnsCache.Lock()
	if config.Cache.Size > 0 {
		dnsCache.capacity = config.Cache.Size
	}
	dnsCache.Unlock()

	LogInfo("[CACHE] Starting maintenance (Capacity: %d, Type: LRU)", config.Cache.Size)

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

func getFromCache(key string, reqID uint16) *dns.Msg {
	if !config.Cache.Enabled {
		return nil
	}

	dnsCache.Lock()
	defer dnsCache.Unlock()

	elem, found := dnsCache.items[key]
	if !found {
		return nil
	}

	entry := elem.Value.(*CacheItem)

	// Check TTL
	now := time.Now()
	if now.After(entry.Expiration) {
		// Lazy eviction
		dnsCache.lruList.Remove(elem)
		delete(dnsCache.items, key)
		resetCacheHitCount(key) // Clean up hit counter
		return nil
	}

	// Move to front (Mark as recently used)
	dnsCache.lruList.MoveToFront(elem)

	// Record hit for stale refresh popularity tracking
	recordCacheHit(key)

	// Unpack from bytes to a fresh message
	msg := getMsg()
	if err := msg.Unpack(entry.MsgBytes); err != nil {
		// If unpack fails (corruption?), invalidate entry
		dnsCache.lruList.Remove(elem)
		delete(dnsCache.items, key)
		resetCacheHitCount(key)
		putMsg(msg)
		return nil
	}

	msg.Id = reqID

	// Adjust TTLs
	ttlDiff := uint32(entry.Expiration.Sub(now).Seconds())
	if ttlDiff <= 0 {
		putMsg(msg) // Should have been caught by expiration check, but safety first
		return nil
	}

	updateTTL := func(rrs []dns.RR) {
		for _, rr := range rrs {
			rr.Header().Ttl = ttlDiff
		}
	}
	updateTTL(msg.Answer)
	updateTTL(msg.Ns)
	updateTTL(msg.Extra)
	return msg
}

func addToCache(key string, msg *dns.Msg) {
	if !config.Cache.Enabled {
		return
	}

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	// Calculate MinTTL logic
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

	if minTTL == 0 {
		return
	}
	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		minTTL = 60
	} else if !foundTTL {
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

	dnsCache.Lock()
	defer dnsCache.Unlock()

	expiration := time.Now().Add(time.Duration(minTTL) * time.Second)

	// Check if update or new
	if elem, found := dnsCache.items[key]; found {
		dnsCache.lruList.MoveToFront(elem)
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
	if dnsCache.lruList.Len() >= dnsCache.capacity {
		if oldest := dnsCache.lruList.Back(); oldest != nil {
			dnsCache.lruList.Remove(oldest)
			oldestEntry := oldest.Value.(*CacheItem)
			delete(dnsCache.items, oldestEntry.Key)
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
	elem := dnsCache.lruList.PushFront(item)
	dnsCache.items[key] = elem
}

// addToCacheWithMeta is used by prefetch to add entries with explicit metadata
func addToCacheWithMeta(key string, msg *dns.Msg, qName string, qType, qClass uint16, routingKey string) {
	if !config.Cache.Enabled {
		return
	}

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	// Calculate MinTTL logic
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

	if minTTL == 0 {
		return
	}
	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		minTTL = 60
	} else if !foundTTL {
		return
	}

	packed, err := msg.Pack()
	if err != nil {
		return
	}

	finalBytes := make([]byte, len(packed))
	copy(finalBytes, packed)

	dnsCache.Lock()
	defer dnsCache.Unlock()

	expiration := time.Now().Add(time.Duration(minTTL) * time.Second)

	if elem, found := dnsCache.items[key]; found {
		dnsCache.lruList.MoveToFront(elem)
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

	if dnsCache.lruList.Len() >= dnsCache.capacity {
		if oldest := dnsCache.lruList.Back(); oldest != nil {
			dnsCache.lruList.Remove(oldest)
			oldestEntry := oldest.Value.(*CacheItem)
			delete(dnsCache.items, oldestEntry.Key)
			resetCacheHitCount(oldestEntry.Key)
		}
	}

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
	elem := dnsCache.lruList.PushFront(item)
	dnsCache.items[key] = elem
}

func pruneExpired() {
	dnsCache.Lock()
	defer dnsCache.Unlock()

	now := time.Now()
	cleaned := 0

	// Check the oldest 50 items from the tail
	for i := 0; i < 50; i++ {
		elem := dnsCache.lruList.Back()
		if elem == nil {
			break
		}
		entry := elem.Value.(*CacheItem)
		if now.After(entry.Expiration) {
			dnsCache.lruList.Remove(elem)
			delete(dnsCache.items, entry.Key)
			resetCacheHitCount(entry.Key) // Clean up hit counter
			cleaned++
		} else {
			break
		}
	}
	if cleaned > 0 {
		LogDebug("[CACHE] Pruned %d expired items from tail", cleaned)
	}
}

// getCacheStats returns current cache statistics
func getCacheStats() (size int, capacity int) {
	dnsCache.Lock()
	defer dnsCache.Unlock()
	return dnsCache.lruList.Len(), dnsCache.capacity
}

// buildCacheKeyFromQuery constructs a cache key from query parameters
func buildCacheKeyFromQuery(qName string, qType, qClass uint16, routingKey string) string {
	var sb strings.Builder
	sb.WriteString(qName)
	sb.WriteString("|")
	sb.WriteString(strconv.Itoa(int(qType)))
	sb.WriteString("|")
	sb.WriteString(strconv.Itoa(int(qClass)))
	sb.WriteString("|")
	sb.WriteString(routingKey)
	return sb.String()
}

