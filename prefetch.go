/*
File: prefetch.go
Description: Implements cache prefetching and cross-record fetching for DNS queries.
             UPDATED: Applied TTL clamping and strategy to prefetched entries BEFORE caching.
*/

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// --- Global State ---

var (
	// Semaphore for cross-fetch goroutines (network limiter)
	crossFetchLimiter chan struct{}

	// Semaphore for stale refresh goroutines
	staleRefreshLimiter chan struct{}

	// Worker pool for cross-fetch requests
	prefetchCh chan prefetchReq

	// Track in-flight prefetch operations to avoid duplicates
	inFlightPrefetch sync.Map // key: cacheKey, value: struct{}

	// Cache hit counter for stale refresh popularity tracking
	cacheHitCounter sync.Map // key: cacheKey, value: *atomic.Int64
)

// prefetchReq holds the data needed to perform a cross-fetch
type prefetchReq struct {
	qName      string
	qType      uint16
	routingKey string
	upstreams  []*Upstream
	strategy   string
	clientIP   net.IP
	clientMAC  net.HardwareAddr
}

// --- Initialization ---

func initPrefetch() {
	cfg := config.Cache.Prefetch

	// Initialize cross-fetch limiter (concurrent network requests)
	maxCross := cfg.CrossFetch.MaxConcurrent
	if maxCross <= 0 {
		maxCross = 10
	}
	// Sanity cap for workers
	if maxCross > 256 {
		maxCross = 256
	}

	crossFetchLimiter = make(chan struct{}, maxCross)

	// Initialize worker pool channel (buffer for bursts)
	prefetchCh = make(chan prefetchReq, 4096)

	// Start worker pool
	if cfg.CrossFetch.Enabled && cfg.CrossFetch.Mode != "off" {
		LogInfo("[PREFETCH] Starting %d cross-fetch workers", maxCross)
		for i := 0; i < maxCross; i++ {
			go prefetchWorker()
		}
	}

	// Initialize stale refresh limiter
	maxStale := cfg.StaleRefresh.MaxConcurrent
	if maxStale <= 0 {
		maxStale = 5
	}
	staleRefreshLimiter = make(chan struct{}, maxStale)

	// Log configuration
	if cfg.CrossFetch.Enabled {
		LogInfo("[PREFETCH] Cross-fetch enabled: Mode=%s, Types=%v, MaxConcurrent=%d, Timeout=%v",
			cfg.CrossFetch.Mode, cfg.CrossFetch.FetchTypes, maxCross, cfg.CrossFetch.parsedTimeout)
	} else {
		LogInfo("[PREFETCH] Cross-fetch disabled")
	}

	if cfg.StaleRefresh.Enabled {
		LogInfo("[PREFETCH] Stale refresh enabled: Threshold=%d%%, MinHits=%d, MaxConcurrent=%d, Interval=%v",
			cfg.StaleRefresh.ThresholdPercent, cfg.StaleRefresh.MinHits, maxStale, cfg.StaleRefresh.parsedCheckInterval)
	} else {
		LogInfo("[PREFETCH] Stale refresh disabled")
	}
}

// --- Cross-Fetch Logic ---

// AttemptCrossFetch queues a prefetch request non-blocking.
// If the queue is full, the request is dropped to save resources.
func AttemptCrossFetch(req prefetchReq) {
	select {
	case prefetchCh <- req:
		// Queued successfully
	default:
		// Queue full - backpressure
		LogDebug("[PREFETCH] Queue full, dropping cross-fetch for %s", req.qName)
	}
}

// prefetchWorker consumes requests from the channel and processes them
func prefetchWorker() {
	for req := range prefetchCh {
		processCrossFetch(req)
	}
}

func processCrossFetch(req prefetchReq) {
	cfg := config.Cache.Prefetch.CrossFetch

	// Determine which types to fetch (excluding the type we just queried)
	typesToFetch := make([]uint16, 0, len(cfg.parsedFetchTypes))
	for _, t := range cfg.parsedFetchTypes {
		if t != req.qType {
			typesToFetch = append(typesToFetch, t)
		}
	}

	if len(typesToFetch) == 0 {
		return
	}

	LogDebug("[PREFETCH] Cross-fetch processing for %s (triggered by %s), will fetch: %v",
		req.qName, dns.TypeToString[req.qType], typeListToStrings(typesToFetch))

	for _, fetchType := range typesToFetch {
		// Build cache key to check if already cached
		cacheKey := buildPrefetchCacheKey(req.qName, fetchType, dns.ClassINET, req.routingKey)

		// OPTIMIZATION: Check in-flight FIRST to avoid cache locking if we are already working on it
		if _, loaded := inFlightPrefetch.LoadOrStore(cacheKey, struct{}{}); loaded {
			LogDebug("[PREFETCH] Skipping %s %s - already in-flight", req.qName, dns.TypeToString[fetchType])
			continue
		}

		// Check if already in cache (requires RLock)
		if cachedResp := getFromCache(cacheKey, 0); cachedResp != nil {
			LogDebug("[PREFETCH] Skipping %s %s - already cached", req.qName, dns.TypeToString[fetchType])
			putMsg(cachedResp)
			inFlightPrefetch.Delete(cacheKey)
			continue
		}

		// Try to acquire semaphore (network limiter)
		select {
		case crossFetchLimiter <- struct{}{}:
			// Execute synchronously in the worker (the worker pool size limits concurrency anyway)
			// We keep the limiter pattern in case we want different sizing for CPU vs Network later
			func(ft uint16, key string) {
				defer func() {
					<-crossFetchLimiter
					inFlightPrefetch.Delete(key)
				}()

				// Reconstruct context from struct
				// Note: RequestContext here is partial, only IP/MAC are preserved
				reqCtx := &RequestContext{
					ClientIP:  req.clientIP,
					ClientMAC: req.clientMAC,
				}
				doCrossFetch(req.qName, ft, req.routingKey, key, req.upstreams, req.strategy, reqCtx)
			}(fetchType, cacheKey)
		default:
			// Limiter full, skip this specific type
			inFlightPrefetch.Delete(cacheKey)
			LogDebug("[PREFETCH] Network limiter full, skipping %s %s", req.qName, dns.TypeToString[fetchType])
		}
	}
}

// TriggerCrossFetch is DEPRECATED in favor of AttemptCrossFetch + Worker Pool.
// Kept only if needed by legacy code, but effectively replaced by AttemptCrossFetch.
func TriggerCrossFetch(qName string, qType uint16, routingKey string, upstreams []*Upstream, strategy string, reqCtx *RequestContext) {
	// Wrapper for compatibility, though process.go now calls AttemptCrossFetch directly
	req := prefetchReq{
		qName:      qName,
		qType:      qType,
		routingKey: routingKey,
		upstreams:  upstreams,
		strategy:   strategy,
	}
	if reqCtx.ClientIP != nil {
		req.clientIP = make(net.IP, len(reqCtx.ClientIP))
		copy(req.clientIP, reqCtx.ClientIP)
	}
	if reqCtx.ClientMAC != nil {
		req.clientMAC = make(net.HardwareAddr, len(reqCtx.ClientMAC))
		copy(req.clientMAC, reqCtx.ClientMAC)
	}
	AttemptCrossFetch(req)
}

func doCrossFetch(qName string, qType uint16, routingKey, cacheKey string, upstreams []*Upstream, strategy string, reqCtx *RequestContext) {
	cfg := config.Cache.Prefetch.CrossFetch
	timeout := cfg.parsedTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	// Build the prefetch query
	msg := getMsg()
	msg.SetQuestion(dns.Fqdn(qName), qType)
	msg.RecursionDesired = true

	// Add EDNS0 if we have client context
	if reqCtx != nil && reqCtx.ClientIP != nil {
		addEDNS0Options(msg, reqCtx.ClientIP, reqCtx.ClientMAC)
	}

	// Forward to upstreams
	resp, upstreamStr, rtt, err := forwardToUpstreams(ctx, msg, upstreams, strategy, reqCtx)
	putMsg(msg)

	if err != nil {
		LogDebug("[PREFETCH] Cross-fetch failed for %s %s: %v", qName, dns.TypeToString[qType], err)
		return
	}

	if resp == nil {
		LogDebug("[PREFETCH] Cross-fetch got nil response for %s %s", qName, dns.TypeToString[qType])
		return
	}

	// Clean and cache the response
	cleanResponse(resp)

	// FIX: Apply TTL clamping and strategy logic BEFORE adding to cache
	// This ensures consistency between live responses and prefetched responses
	applyTTLClamping(resp)
	applyTTLStrategy(resp)
	
	addToCache(cacheKey, resp)

	LogInfo("[PREFETCH] Cross-fetched %s %s from %s (RTT: %v, Total: %v, Answers: %d)",
		qName, dns.TypeToString[qType], upstreamStr, rtt, time.Since(start), len(resp.Answer))
}

// --- Stale Refresh Logic ---

// maintainStaleRefresh runs the background loop for proactive cache refresh
func maintainStaleRefresh(ctx context.Context) {
	cfg := config.Cache.Prefetch.StaleRefresh

	if !cfg.Enabled {
		LogInfo("[PREFETCH] Stale refresh maintenance not started (disabled)")
		return
	}

	interval := cfg.parsedCheckInterval
	if interval == 0 {
		interval = 30 * time.Second
	}

	LogInfo("[PREFETCH] Starting stale refresh maintenance (Interval: %v)", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			LogInfo("[PREFETCH] Stopping stale refresh maintenance")
			return
		case <-ticker.C:
			scanAndRefreshStale(ctx)
		}
	}
}

func scanAndRefreshStale(ctx context.Context) {
	cfg := config.Cache.Prefetch.StaleRefresh
	thresholdPct := cfg.ThresholdPercent
	if thresholdPct <= 0 {
		thresholdPct = 10
	}
	minHits := cfg.MinHits
	if minHits <= 0 {
		minHits = 2
	}

	var toRefresh []staleRefreshCandidate

	// Use ScanCacheForStale helper from cache.go to iterate the sharded cache safely
	ScanCacheForStale(thresholdPct, minHits, func(entry *CacheItem, hitCount int64) {
		// Check if already being refreshed
		if _, inFlight := inFlightPrefetch.Load(entry.Key); inFlight {
			return
		}

		// Recalculate remainingPct for logging purposes
		// (ScanCacheForStale already verified it's below threshold)
		remainingPct := 0
		if entry.OriginalTTL > 0 {
			remaining := entry.Expiration.Sub(time.Now())
			remainingPct = int((remaining.Seconds() / float64(entry.OriginalTTL)) * 100)
		}

		toRefresh = append(toRefresh, staleRefreshCandidate{
			key:          entry.Key,
			qName:        entry.QName,
			qType:        entry.QType,
			qClass:       entry.QClass,
			routingKey:   entry.RoutingKey,
			remainingPct: remainingPct,
			hitCount:     hitCount,
		})
	})

	if len(toRefresh) == 0 {
		return
	}

	LogDebug("[PREFETCH] Found %d stale entries to refresh", len(toRefresh))

	// Refresh candidates
	for _, candidate := range toRefresh {
		// Check if already in-flight
		if _, loaded := inFlightPrefetch.LoadOrStore(candidate.key, struct{}{}); loaded {
			continue
		}

		// Try to acquire semaphore (non-blocking)
		select {
		case staleRefreshLimiter <- struct{}{}:
			go func(c staleRefreshCandidate) {
				defer func() {
					<-staleRefreshLimiter
					inFlightPrefetch.Delete(c.key)
				}()

				doStaleRefresh(ctx, c)
			}(candidate)
		default:
			inFlightPrefetch.Delete(candidate.key)
			LogDebug("[PREFETCH] Stale refresh queue full, skipping %s", candidate.key)
		}
	}
}

type staleRefreshCandidate struct {
	key          string
	qName        string
	qType        uint16
	qClass       uint16
	routingKey   string
	remainingPct int
	hitCount     int64
}

func doStaleRefresh(ctx context.Context, c staleRefreshCandidate) {
	timeout := 5 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	// Get upstreams for this routing key
	// For stale refresh, we use default upstreams since we don't have client context
	upstreams := config.Routing.DefaultRule.parsedUpstreams
	strategy := config.Routing.DefaultRule.Strategy

	// If routing key is not DEFAULT, we need to find the right rule
	if c.routingKey != "DEFAULT" {
		for _, rule := range config.Routing.RoutingRules {
			if rule.Name == c.routingKey {
				upstreams = rule.parsedUpstreams
				strategy = rule.Strategy
				break
			}
		}
	}

	// Build refresh query
	msg := getMsg()
	msg.SetQuestion(dns.Fqdn(c.qName), c.qType)
	msg.RecursionDesired = true

	// Empty request context for background refresh
	reqCtx := &RequestContext{}

	// Forward to upstreams
	resp, upstreamStr, rtt, err := forwardToUpstreams(ctx, msg, upstreams, strategy, reqCtx)
	putMsg(msg)

	if err != nil {
		LogDebug("[PREFETCH] Stale refresh failed for %s %s: %v", c.qName, dns.TypeToString[c.qType], err)
		return
	}

	if resp == nil {
		LogDebug("[PREFETCH] Stale refresh got nil response for %s %s", c.qName, dns.TypeToString[c.qType])
		return
	}

	// Clean and cache the response
	cleanResponse(resp)

	// FIX: Apply TTL clamping and strategy logic BEFORE adding to cache
	// This ensures consistency between live responses and refreshed responses
	applyTTLClamping(resp)
	applyTTLStrategy(resp)

	addToCache(c.key, resp)

	LogInfo("[PREFETCH] Stale-refreshed %s %s from %s (RTT: %v, Total: %v, Remaining: %d%%, Hits: %d)",
		c.qName, dns.TypeToString[c.qType], upstreamStr, rtt, time.Since(start), c.remainingPct, c.hitCount)
}

// --- Helper Functions ---

// buildPrefetchCacheKey constructs a cache key for a given query (used by prefetch)
func buildPrefetchCacheKey(qName string, qType, qClass uint16, routingKey string) string {
	// Use numeric encoding to match process.go cache key format
	return fmt.Sprintf("%s|%d|%d|%s", dns.Fqdn(qName), qType, qClass, routingKey)
}

// recordCacheHit increments the hit counter for a cache key
func recordCacheHit(key string) {
	counter, _ := cacheHitCounter.LoadOrStore(key, &atomic.Int64{})
	counter.(*atomic.Int64).Add(1)
}

// getCacheHitCount returns the hit count for a cache key
func getCacheHitCount(key string) int64 {
	counter, ok := cacheHitCounter.Load(key)
	if !ok {
		return 0
	}
	return counter.(*atomic.Int64).Load()
}

// resetCacheHitCount removes the hit counter for a cache key (called on eviction)
func resetCacheHitCount(key string) {
	cacheHitCounter.Delete(key)
}

// parseFetchTypes converts string type names to DNS type codes
func parseFetchTypes(types []string) []uint16 {
	result := make([]uint16, 0, len(types))
	for _, t := range types {
		if code, ok := dns.StringToType[t]; ok {
			result = append(result, code)
		} else {
			LogWarn("[PREFETCH] Unknown DNS type in fetch_types: %s", t)
		}
	}
	return result
}

// typeListToStrings converts a list of DNS type codes to their string names
func typeListToStrings(types []uint16) []string {
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = dns.TypeToString[t]
	}
	return result
}

