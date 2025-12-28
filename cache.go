/*
File: cache.go
Description: Thread-safe in-memory DNS cache with TTL enforcement and SmartLRU eviction.
*/

package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
	LastAccess time.Time
}

type DNSCache struct {
	sync.RWMutex
	items map[string]*CacheEntry
}

var dnsCache = &DNSCache{items: make(map[string]*CacheEntry)}

func maintainDNSCache() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		pruneCache()
	}
}

func getFromCache(key string, reqID uint16) *dns.Msg {
	if !config.Cache.Enabled {
		return nil
	}

	dnsCache.RLock()
	entry, found := dnsCache.items[key]
	dnsCache.RUnlock()

	if !found {
		return nil
	}

	now := time.Now()
	if now.After(entry.Expiration) {
		return nil
	}

	dnsCache.Lock()
	if e, ok := dnsCache.items[key]; ok {
		e.LastAccess = now
	}
	dnsCache.Unlock()

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

	if len(dnsCache.items) >= config.Cache.Size {
		now := time.Now()
		for k, v := range dnsCache.items {
			if now.After(v.Expiration) {
				delete(dnsCache.items, k)
			}
		}

		if len(dnsCache.items) >= config.Cache.Size {
			evictSmartLRU()
		}
	}

	now := time.Now()
	dnsCache.items[key] = &CacheEntry{
		Msg:        msg,
		Expiration: now.Add(time.Duration(minTTL) * time.Second),
		LastAccess: now,
	}
}

func evictSmartLRU() {
	toRemove := config.Cache.Size / 20
	if toRemove < 10 {
		toRemove = 10
	}

	const sampleSize = 50

	for i := 0; i < toRemove; i++ {
		if len(dnsCache.items) == 0 {
			break
		}

		var oldestKey string
		var oldestTime time.Time
		first := true
		count := 0

		for k, v := range dnsCache.items {
			if first || v.LastAccess.Before(oldestTime) {
				oldestTime = v.LastAccess
				oldestKey = k
				first = false
			}
			count++
			if count >= sampleSize {
				break
			}
		}

		if oldestKey != "" {
			delete(dnsCache.items, oldestKey)
		}
	}
}

func pruneCache() {
	dnsCache.Lock()
	defer dnsCache.Unlock()
	now := time.Now()
	for k, v := range dnsCache.items {
		if now.After(v.Expiration) {
			delete(dnsCache.items, k)
		}
	}
}

