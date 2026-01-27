/*
File: prefetch.go
Version: 2.3.0
Description: Implements Predictive Prefetching and Stale Refresh.
             UPDATED: Implemented Adaptive Interval for Stale Refresh logic to reduce CPU usage.
*/

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// --- Global State ---

var (
	// Semaphore for prefetch goroutines (network limiter)
	prefetchLimiter chan struct{}

	// Worker pool channel
	prefetchCh chan predictiveReq

	// Track in-flight prefetch operations to avoid duplicates
	inFlightPrefetch sync.Map // key: cacheKey, value: struct{}

	// Cache hit counter for stale refresh popularity tracking
	cacheHitCounter sync.Map // key: cacheKey, value: *atomic.Int64

	// The Predictive Model Engine
	predictor *MarkovEngine
)

// predictiveReq holds data for the prefetch worker
type predictiveReq struct {
	targetDomain string
	sourceDomain string
	routingKey   string
	upstreams    []*Upstream
	strategy     string
	clientIP     net.IP
	clientMAC    net.HardwareAddr
}

// --- Initialization ---

func initPrefetch() {
	cfg := config.Cache.Prefetch

	// --- PREDICTIVE PREFETCH INIT ---
	if cfg.Predictive.Enabled {
		maxConcurrent := cfg.Predictive.MaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 10
		}
		if maxConcurrent > 512 {
			maxConcurrent = 512
		}

		prefetchLimiter = make(chan struct{}, maxConcurrent)
		prefetchCh = make(chan predictiveReq, 4096)
		predictor = NewMarkovEngine(cfg.Predictive.MaxMemory, cfg.Predictive.Threshold, cfg.Predictive.parsedWindow)

		// Start workers
		LogInfo("[PREDICT] Starting %d predictive prefetch workers", maxConcurrent)
		for i := 0; i < maxConcurrent; i++ {
			go prefetchWorker()
		}
	} else {
		LogInfo("[PREDICT] Predictive prefetching disabled")
	}

	// --- STALE REFRESH INIT ---
	if cfg.StaleRefresh.Enabled {
		// Stale refresh uses its own limiter logic in staleRefresh routines
		// but shares some tracking maps
		LogInfo("[STALE] Stale refresh enabled: Threshold=%d%%, MinHits=%d",
			cfg.StaleRefresh.ThresholdPercent, cfg.StaleRefresh.MinHits)
	}
}

// --- Predictive Logic (Public API) ---

// TrackAndPredict is called after a successful DNS query.
func TrackAndPredict(clientIP net.IP, currentDomain string, routingKey string, upstreams []*Upstream, strategy string, reqCtx *RequestContext) {
	if !config.Cache.Prefetch.Predictive.Enabled || predictor == nil {
		return
	}

	if IsDebugEnabled() {
		LogDebug("[PREDICT] Tracking transition for Client: %s, Domain: %s", clientIP.String(), currentDomain)
	}

	currentDomain = strings.ToLower(strings.TrimSuffix(currentDomain, "."))

	// 1. Update Model & Get Candidates
	candidates := predictor.UpdateAndPredict(clientIP.String(), currentDomain)

	if len(candidates) == 0 {
		return
	}

	if IsDebugEnabled() {
		LogDebug("[PREDICT] Prediction candidates for '%s': %v", currentDomain, candidates)
	}

	// 2. Queue Prefetches
	for _, nextDomain := range candidates {
		if nextDomain == currentDomain {
			continue
		}

		req := predictiveReq{
			targetDomain: nextDomain,
			sourceDomain: currentDomain,
			routingKey:   routingKey,
			upstreams:    upstreams,
			strategy:     strategy,
		}

		if reqCtx != nil {
			if len(reqCtx.ClientIP) > 0 {
				req.clientIP = make(net.IP, len(reqCtx.ClientIP))
				copy(req.clientIP, reqCtx.ClientIP)
			}
			if len(reqCtx.ClientMAC) > 0 {
				req.clientMAC = make(net.HardwareAddr, len(reqCtx.ClientMAC))
				copy(req.clientMAC, reqCtx.ClientMAC)
			}
		}

		AttemptPredictiveFetch(req)
	}
}

// AttemptPredictiveFetch queues a request with load shedding
func AttemptPredictiveFetch(req predictiveReq) {
	// Load Shedding
	if config.Cache.Prefetch.LoadShedding.Enabled {
		ls := config.Cache.Prefetch.LoadShedding
		if ls.MaxGoroutines > 0 {
			routines := runtime.NumGoroutine()
			if routines > ls.MaxGoroutines {
				if IsDebugEnabled() {
					LogDebug("[PREDICT] DROPPED prefetch %s->%s (Load Shedding: %d/%d Goroutines)",
						req.sourceDomain, req.targetDomain, routines, ls.MaxGoroutines)
				}
				return
			}
		}
		if ls.MaxQueueUsagePct > 0 {
			usage := (len(prefetchCh) * 100) / cap(prefetchCh)
			if usage > ls.MaxQueueUsagePct {
				if IsDebugEnabled() {
					LogDebug("[PREDICT] DROPPED prefetch %s->%s (Queue Full: %d%%)",
						req.sourceDomain, req.targetDomain, usage)
				}
				return
			}
		}
	}

	select {
	case prefetchCh <- req:
		if IsDebugEnabled() {
			LogDebug("[PREDICT] QUEUED prefetch %s -> %s (Queue: %d/%d)", req.sourceDomain, req.targetDomain, len(prefetchCh), cap(prefetchCh))
		}
	default:
		// Drop if full
		if IsDebugEnabled() {
			LogDebug("[PREDICT] DROPPED prefetch %s -> %s (Queue Full)", req.sourceDomain, req.targetDomain)
		}
	}
}

func prefetchWorker() {
	for req := range prefetchCh {
		processPredictiveFetch(req)
	}
}

func processPredictiveFetch(req predictiveReq) {
	types := []uint16{dns.TypeA, dns.TypeAAAA}

	for _, qType := range types {
		cacheKey := buildPrefetchCacheKey(req.targetDomain, qType, dns.ClassINET, req.routingKey)

		// Check in-flight
		if _, loaded := inFlightPrefetch.LoadOrStore(cacheKey, struct{}{}); loaded {
			if IsDebugEnabled() {
				LogDebug("[PREDICT] SKIPPING %s (%s): Already in-flight", req.targetDomain, dns.TypeToString[qType])
			}
			continue
		}

		// Check Cache
		if cachedResp := getFromCache(cacheKey, 0); cachedResp != nil {
			putMsg(cachedResp)
			inFlightPrefetch.Delete(cacheKey)
			if IsDebugEnabled() {
				LogDebug("[PREDICT] SKIPPING %s (%s): Already cached", req.targetDomain, dns.TypeToString[qType])
			}
			continue
		}

		// Execute
		select {
		case prefetchLimiter <- struct{}{}:
			func(t uint16, key string) {
				defer func() {
					<-prefetchLimiter
					inFlightPrefetch.Delete(key)
				}()

				reqCtx := &RequestContext{ClientIP: req.clientIP, ClientMAC: req.clientMAC}

				if IsDebugEnabled() {
					LogDebug("[PREDICT] EXECUTING prefetch %s -> %s (%s)", req.sourceDomain, req.targetDomain, dns.TypeToString[t])
				}
				doPredictiveFetch(req.targetDomain, t, req.routingKey, key, req.upstreams, req.strategy, reqCtx, req.sourceDomain)
			}(qType, cacheKey)
		default:
			inFlightPrefetch.Delete(cacheKey)
			if IsDebugEnabled() {
				LogDebug("[PREDICT] SKIPPING %s (%s): Concurrency limit reached", req.targetDomain, dns.TypeToString[qType])
			}
		}
	}
}

func doPredictiveFetch(qName string, qType uint16, routingKey, cacheKey string, upstreams []*Upstream, strategy string, reqCtx *RequestContext, source string) {
	cfg := config.Cache.Prefetch.Predictive
	timeout := cfg.parsedTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	msg := getMsg()
	msg.SetQuestion(dns.Fqdn(qName), qType)
	msg.RecursionDesired = true
	if reqCtx != nil && reqCtx.ClientIP != nil {
		addEDNS0Options(msg, reqCtx.ClientIP, reqCtx.ClientMAC)
	}

	resp, upstreamStr, _, err := forwardToUpstreams(ctx, msg, upstreams, strategy, routingKey, reqCtx)
	putMsg(msg)

	if err != nil {
		if IsDebugEnabled() {
			LogDebug("[PREDICT] FAILED %s (%s): %v", qName, dns.TypeToString[qType], err)
		}
		return
	}
	if resp == nil {
		return
	}

	cleanResponse(resp)
	applyTTLClamping(resp)
	applyTTLStrategy(resp)
	addToCache(cacheKey, resp)

	LogDebug("[PREDICT] SUCCESS %s -> %s (%s). Prefetched from %s", source, qName, dns.TypeToString[qType], upstreamStr)
}

// --- MARKOV ENGINE ---

const (
	markovShards = 64
)

type lastQuery struct {
	domain    string
	timestamp int64 // unix nano
}

type transitionMap map[string]uint32 // ToDomain -> Count

type MarkovShard struct {
	sync.RWMutex
	transitions map[string]transitionMap // FromDomain -> ToDomain -> Count
	totals      map[string]uint32        // FromDomain -> TotalCount
	clients     map[string]lastQuery     // ClientIP -> LastQuery
}

type MarkovEngine struct {
	shards    [markovShards]*MarkovShard
	maxMemory int
	threshold float64
	window    time.Duration
	hasher    maphash.Hash
	hasherMu  sync.Mutex
}

func NewMarkovEngine(maxMemory int, threshold float64, window time.Duration) *MarkovEngine {
	m := &MarkovEngine{
		maxMemory: maxMemory,
		threshold: threshold,
		window:    window,
	}
	for i := 0; i < markovShards; i++ {
		m.shards[i] = &MarkovShard{
			transitions: make(map[string]transitionMap),
			totals:      make(map[string]uint32),
			clients:     make(map[string]lastQuery),
		}
	}
	return m
}

func (m *MarkovEngine) getShard(key string) *MarkovShard {
	m.hasherMu.Lock()
	m.hasher.Reset()
	m.hasher.WriteString(key)
	hash := m.hasher.Sum64()
	m.hasherMu.Unlock()
	return m.shards[hash&(markovShards-1)]
}

func (m *MarkovEngine) UpdateAndPredict(clientKey, currentDomain string) []string {
	shard := m.getShard(clientKey)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	// 1. Get History
	last, exists := shard.clients[clientKey]

	// Update history for next time
	shard.clients[clientKey] = lastQuery{domain: currentDomain, timestamp: now}

	shard.Unlock()

	// --- DOMAIN LOCK SCOPE ---

	// Learn Step (Write)
	if exists && (now-last.timestamp) <= m.window.Nanoseconds() {
		dShard := m.getShard(last.domain)
		dShard.Lock()
		m.incrementTransition(dShard, last.domain, currentDomain)
		dShard.Unlock()
	}

	// Predict Step (Read)
	dShard := m.getShard(currentDomain)
	dShard.RLock()
	candidates := m.getPredictions(dShard, currentDomain)
	dShard.RUnlock()

	shard.Lock()
	return candidates
}

func (m *MarkovEngine) incrementTransition(shard *MarkovShard, from, to string) {
	if len(shard.transitions) >= m.maxMemory/markovShards {
		if _, ok := shard.transitions[from]; !ok {
			return
		}
	}

	tmap, ok := shard.transitions[from]
	if !ok {
		tmap = make(transitionMap)
		shard.transitions[from] = tmap
	}

	tmap[to]++
	shard.totals[from]++

	if shard.totals[from] > 1000 {
		shard.totals[from] /= 2
		for k, v := range tmap {
			newVal := v / 2
			if newVal == 0 {
				delete(tmap, k)
			} else {
				tmap[k] = newVal
			}
		}
	}
}

func (m *MarkovEngine) getPredictions(shard *MarkovShard, from string) []string {
	total := shard.totals[from]
	if total < 10 {
		return nil
	}

	tmap := shard.transitions[from]
	if len(tmap) == 0 {
		return nil
	}

	var preds []string
	for to, count := range tmap {
		probability := float64(count) / float64(total)
		if probability >= m.threshold {
			preds = append(preds, to)
		}
	}
	return preds
}

// --- Stale Refresh Logic ---

var staleRefreshLimiter chan struct{}

func maintainStaleRefresh(ctx context.Context) {
	cfg := config.Cache.Prefetch.StaleRefresh
	if !cfg.Enabled {
		return
	}

	staleRefreshLimiter = make(chan struct{}, cfg.MaxConcurrent)

	// Base Interval from Config
	baseInterval := cfg.parsedCheckInterval
	if baseInterval == 0 {
		baseInterval = 30 * time.Second
	}

	// Limits for Adaptive Interval
	minInterval := 5 * time.Second
	maxInterval := 10 * time.Minute

	currentInterval := baseInterval
	LogInfo("[STALE] Starting adaptive maintenance (Base: %v, Min: %v, Max: %v)", baseInterval, minInterval, maxInterval)
	
	timer := time.NewTimer(currentInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Perform Scan
			candidatesFound := scanAndRefreshStale(ctx)
			
			// Adapt Interval
			if candidatesFound > 0 {
				// If we found candidates, the cache has active/stale items.
				// Check more frequently to catch items *just* before they expire.
				currentInterval = currentInterval / 2
				if currentInterval < minInterval {
					currentInterval = minInterval
				}
				if IsDebugEnabled() {
					LogDebug("[STALE] Found %d candidates. Speeding up refresh to %v", candidatesFound, currentInterval)
				}
			} else {
				// No candidates found. The cache is either empty, or everything is fresh.
				// Back off to save CPU.
				currentInterval = currentInterval * 2
				if currentInterval > maxInterval {
					currentInterval = maxInterval
				}
				if IsDebugEnabled() {
					LogDebug("[STALE] No candidates. Slowing down refresh to %v", currentInterval)
				}
			}
			
			timer.Reset(currentInterval)
		}
	}
}

// scanAndRefreshStale returns the number of refresh candidates queued.
func scanAndRefreshStale(ctx context.Context) int {
	cfg := config.Cache.Prefetch.StaleRefresh
	var toRefresh []staleRefreshCandidate

	ScanCacheForStale(cfg.ThresholdPercent, cfg.MinHits, func(entry *CacheItem, hitCount int64) {
		if _, inFlight := inFlightPrefetch.Load(entry.Key); inFlight {
			return
		}

		remainingPct := 0
		if entry.OriginalTTL > 0 {
			remaining := entry.Expiration.Sub(time.Now())
			remainingPct = int((remaining.Seconds() / float64(entry.OriginalTTL)) * 100)
		}

		toRefresh = append(toRefresh, staleRefreshCandidate{
			key:          entry.Key,
			qName:        entry.QName,
			qType:        entry.QType,
			routingKey:   entry.RoutingKey,
			remainingPct: remainingPct,
			hitCount:     hitCount,
		})
	})

	count := len(toRefresh)
	if count > 0 && IsDebugEnabled() {
		LogDebug("[STALE] Found %d candidates for refresh", count)
	}

	for _, c := range toRefresh {
		if _, loaded := inFlightPrefetch.LoadOrStore(c.key, struct{}{}); loaded {
			continue
		}

		select {
		case staleRefreshLimiter <- struct{}{}:
			go func(cand staleRefreshCandidate) {
				defer func() {
					<-staleRefreshLimiter
					inFlightPrefetch.Delete(cand.key)
				}()
				doStaleRefresh(ctx, cand)
			}(c)
		default:
			inFlightPrefetch.Delete(c.key)
			if IsDebugEnabled() {
				LogDebug("[STALE] Dropped refresh for %s (Concurrency limit)", c.qName)
			}
		}
	}
	
	return count
}

type staleRefreshCandidate struct {
	key          string
	qName        string
	qType        uint16
	routingKey   string
	remainingPct int
	hitCount     int64
}

func doStaleRefresh(ctx context.Context, c staleRefreshCandidate) {
	upstreams := config.Routing.DefaultRule.parsedUpstreams
	strategy := config.Routing.DefaultRule.Strategy

	if IsDebugEnabled() {
		LogDebug("[STALE] Refreshing %s (Hits: %d, Rem: %d%%)", c.qName, c.hitCount, c.remainingPct)
	}

	msg := getMsg()
	msg.SetQuestion(dns.Fqdn(c.qName), c.qType)
	msg.RecursionDesired = true

	resp, _, _, err := forwardToUpstreams(ctx, msg, upstreams, strategy, c.routingKey, nil)
	putMsg(msg)

	if err == nil && resp != nil {
		cleanResponse(resp)
		applyTTLClamping(resp)
		applyTTLStrategy(resp)
		addToCache(c.key, resp)
		LogDebug("[STALE] Refreshed %s", c.qName)
	} else if IsDebugEnabled() {
		LogDebug("[STALE] Failed to refresh %s: %v", c.qName, err)
	}
}

// --- Helpers ---

func buildPrefetchCacheKey(qName string, qType, qClass uint16, routingKey string) string {
	return fmt.Sprintf("%s|%d|%d|%s", dns.Fqdn(qName), qType, qClass, routingKey)
}

func recordCacheHit(key string) {
	counter, _ := cacheHitCounter.LoadOrStore(key, &atomic.Int64{})
	counter.(*atomic.Int64).Add(1)
}

func getCacheHitCount(key string) int64 {
	counter, ok := cacheHitCounter.Load(key)
	if !ok {
		return 0
	}
	return counter.(*atomic.Int64).Load()
}

func resetCacheHitCount(key string) {
	cacheHitCounter.Delete(key)
}

