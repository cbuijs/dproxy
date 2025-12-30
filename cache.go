/*
File: cache.go
Description: Thread-safe in-memory DNS cache using O(1) LRU eviction.
*/

package main

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheItem struct {
	Key        string
	Msg        *dns.Msg
	Expiration time.Time
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

	// Ticker for strictly expired items (cleanup)
	// The LRU handles capacity eviction; this handles TTL expiration cleanup
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

	// Move to front (Mark as recently used)
	dnsCache.lruList.MoveToFront(elem)

	entry := elem.Value.(*CacheItem)

	// Check TTL
	now := time.Now()
	if now.After(entry.Expiration) {
		// Lazy eviction
		dnsCache.lruList.Remove(elem)
		delete(dnsCache.items, key)
		return nil
	}

	msg := entry.Msg.Copy()
	msg.Id = reqID

	ttlDiff := uint32(entry.Expiration.Sub(now).Seconds())
	if ttlDiff <= 0 {
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

	dnsCache.Lock()
	defer dnsCache.Unlock()

	// Check if update or new
	if elem, found := dnsCache.items[key]; found {
		dnsCache.lruList.MoveToFront(elem)
		entry := elem.Value.(*CacheItem)
		entry.Msg = msg
		entry.Expiration = time.Now().Add(time.Duration(minTTL) * time.Second)
		return
	}

	// Evict if full
	if dnsCache.lruList.Len() >= dnsCache.capacity {
		if oldest := dnsCache.lruList.Back(); oldest != nil {
			dnsCache.lruList.Remove(oldest)
			oldestEntry := oldest.Value.(*CacheItem)
			delete(dnsCache.items, oldestEntry.Key)
		}
	}

	// Add new
	item := &CacheItem{
		Key:        key,
		Msg:        msg,
		Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
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
	// Since LRU is access-based, the tail contains the least recently used, 
	// which are good candidates for being expired as well.
	for i := 0; i < 50; i++ {
		elem := dnsCache.lruList.Back()
		if elem == nil {
			break
		}
		entry := elem.Value.(*CacheItem)
		if now.After(entry.Expiration) {
			dnsCache.lruList.Remove(elem)
			delete(dnsCache.items, entry.Key)
			cleaned++
		} else {
			// If the tail item isn't expired, we stop to avoid scanning the whole list
			break
		}
	}
	if cleaned > 0 {
		LogDebug("[CACHE] Pruned %d expired items from tail", cleaned)
	}
}

