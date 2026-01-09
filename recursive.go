/*
File: recursive.go
Version: 2.1.0
Description: High-performance recursive resolver with Sharded Caching and RTT-Weighted Selection.
             IMPROVEMENT 1: Sharded InfrastructureCache (256 shards) to eliminate lock contention.
             IMPROVEMENT 2: RTT tracking for Authoritative Servers to prioritize fast upstreams.
             IMPROVEMENT 3: "Happy Eyeballs" race now uses top-3 fastest servers, not random ones.
             IMPROVEMENT 4: Zero-alloc zone walking optimizations.
             FIXED: Implemented missing Glue Resolution logic in getIPsForNS to fix "no reachable nameservers" error.
             FIXED: exchange() signature mismatch.
             FIXED: Strictly honor ip_version setting for NS/Glue retrieval and usage.
             UPDATED: Added verbose debug logging for iterative lookups, glue resolution, and caching.
             UPDATED: Enhanced logging to explicitly show Shortcut jumps (e.g., sub.domain.com -> domain.com).
             UPDATED: Added detailed "Walking the Tree" logging for every iterative step and QNAME minimization details.
*/

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Constants for Cache Management
const (
	infraCacheTTL     = 1 * time.Hour // Default TTL for NS/Glue if not specified
	infraCacheMaxSize = 10000         // Max items per map to prevent unbounded growth
	infraShardCount   = 256           // Number of shards for infrastructure cache
)

// Global seed for maphash
var infraHasherSeed = maphash.MakeSeed()

// Global instance
var recursiveResolver *RecursiveResolver

// Nameserver represents an authoritative server with RTT tracking
type Nameserver struct {
	Name         string
	IPs          []net.IP
	RTT          atomic.Int64 // Weighted Moving Average RTT in nanoseconds
	FailureCount atomic.Int32 // Consecutive failures
}

// UpdateRTT updates the weighted moving average RTT
func (ns *Nameserver) UpdateRTT(duration time.Duration, failure bool) {
	if failure {
		ns.FailureCount.Add(1)
		// Penalize RTT on failure (add 1s virtual latency)
		current := ns.RTT.Load()
		if current == 0 {
			ns.RTT.Store(int64(1 * time.Second))
		} else {
			ns.RTT.Store(current + int64(1*time.Second))
		}
		return
	}

	ns.FailureCount.Store(0)
	newRTT := int64(duration)
	oldRTT := ns.RTT.Load()

	if oldRTT == 0 {
		ns.RTT.Store(newRTT)
	} else {
		// EWMA: 70% old, 30% new
		ns.RTT.Store(int64(float64(oldRTT)*0.7 + float64(newRTT)*0.3))
	}
}

type infraCacheEntry[T any] struct {
	data      T
	expiresAt time.Time
}

// InfraShard reduces lock contention
type InfraShard struct {
	sync.RWMutex
	nsCache   map[string]infraCacheEntry[[]*Nameserver] // Changed to pointer to allow atomic RTT updates
	glueCache map[string]infraCacheEntry[[]net.IP]
}

// InfrastructureCache stores NS records and Glue IPs
type InfrastructureCache struct {
	shards [infraShardCount]*InfraShard
}

func NewInfrastructureCache() *InfrastructureCache {
	ic := &InfrastructureCache{}
	for i := 0; i < infraShardCount; i++ {
		ic.shards[i] = &InfraShard{
			nsCache:   make(map[string]infraCacheEntry[[]*Nameserver]),
			glueCache: make(map[string]infraCacheEntry[[]net.IP]),
		}
	}
	return ic
}

func (ic *InfrastructureCache) getShard(key string) *InfraShard {
	var h maphash.Hash
	h.SetSeed(infraHasherSeed)
	h.WriteString(key)
	return ic.shards[h.Sum64()&(infraShardCount-1)]
}

type RecursiveResolver struct {
	config    RecursionConfig
	rootHints []*Nameserver // Changed to pointer
	cache     *InfrastructureCache
	client    *dns.Client
	glueGroup singleflight.Group
}

func NewRecursiveResolver(cfg RecursionConfig) *RecursiveResolver {
	rr := &RecursiveResolver{
		config: cfg,
		cache:  NewInfrastructureCache(),
		client: &dns.Client{
			Net:            "udp",
			Timeout:        2 * time.Second,
			SingleInflight: false,
			UDPSize:        4096,
		},
	}

	rr.loadRootHints()
	go rr.cacheCleanupLoop()
	return rr
}

func (r *RecursiveResolver) cacheCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		r.pruneCache()
	}
}

func (r *RecursiveResolver) pruneCache() {
	now := time.Now()
	for i, shard := range r.cache.shards {
		shard.Lock()
		cleanedNS := 0
		cleanedGlue := 0
		for k, v := range shard.nsCache {
			if now.After(v.expiresAt) {
				delete(shard.nsCache, k)
				cleanedNS++
			}
		}
		for k, v := range shard.glueCache {
			if now.After(v.expiresAt) {
				delete(shard.glueCache, k)
				cleanedGlue++
			}
		}
		shard.Unlock()
		if cleanedNS > 0 || cleanedGlue > 0 {
			LogDebug("[RECURSION] [CACHE-PRUNE] Shard %d: Pruned %d NS records, %d Glue records", i, cleanedNS, cleanedGlue)
		}
	}
}

func (r *RecursiveResolver) loadRootHints() {
	if r.config.RootHintsFile != "" {
		if err := r.parseRootHintsFile(r.config.RootHintsFile); err != nil {
			LogWarn("[RECURSION] Failed to load root hints file: %v. Using built-ins.", err)
			r.useBuiltInRoots()
		} else {
			LogInfo("[RECURSION] Loaded root hints from %s", r.config.RootHintsFile)
		}
	} else {
		r.useBuiltInRoots()
	}
}

func (r *RecursiveResolver) useBuiltInRoots() {
	// Root servers (A-M)
	r.rootHints = []*Nameserver{
		{Name: "a.root-servers.net.", IPs: []net.IP{net.ParseIP("198.41.0.4"), net.ParseIP("2001:503:ba3e::2:30")}},
		{Name: "b.root-servers.net.", IPs: []net.IP{net.ParseIP("199.9.14.201"), net.ParseIP("2001:500:200::b")}},
		{Name: "c.root-servers.net.", IPs: []net.IP{net.ParseIP("192.33.4.12"), net.ParseIP("2001:500:2::c")}},
		{Name: "d.root-servers.net.", IPs: []net.IP{net.ParseIP("199.7.91.13"), net.ParseIP("2001:500:2d::d")}},
		{Name: "e.root-servers.net.", IPs: []net.IP{net.ParseIP("192.203.230.10"), net.ParseIP("2001:500:a8::e")}},
		{Name: "f.root-servers.net.", IPs: []net.IP{net.ParseIP("192.5.5.241"), net.ParseIP("2001:500:2f::f")}},
		{Name: "g.root-servers.net.", IPs: []net.IP{net.ParseIP("192.112.36.4"), net.ParseIP("2001:500:12::d0d")}},
		{Name: "h.root-servers.net.", IPs: []net.IP{net.ParseIP("198.97.190.53"), net.ParseIP("2001:500:1::53")}},
		{Name: "i.root-servers.net.", IPs: []net.IP{net.ParseIP("192.36.148.17"), net.ParseIP("2001:7fe::53")}},
		{Name: "j.root-servers.net.", IPs: []net.IP{net.ParseIP("192.58.128.30"), net.ParseIP("2001:503:c27::2:30")}},
		{Name: "k.root-servers.net.", IPs: []net.IP{net.ParseIP("193.0.14.129"), net.ParseIP("2001:7fd::1")}},
		{Name: "l.root-servers.net.", IPs: []net.IP{net.ParseIP("199.7.83.42"), net.ParseIP("2001:500:3::42")}},
		{Name: "m.root-servers.net.", IPs: []net.IP{net.ParseIP("202.12.27.33"), net.ParseIP("2001:dc3::35")}},
	}
}

func (r *RecursiveResolver) parseRootHintsFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var roots []*Nameserver
	nsMap := make(map[string][]net.IP)

	zp := dns.NewZoneParser(bufio.NewReader(f), ".", path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.A:
			name := strings.ToLower(v.Header().Name)
			nsMap[name] = append(nsMap[name], v.A)
		case *dns.AAAA:
			name := strings.ToLower(v.Header().Name)
			nsMap[name] = append(nsMap[name], v.AAAA)
		}
	}

	if err := zp.Err(); err != nil {
		return err
	}

	for name, ips := range nsMap {
		roots = append(roots, &Nameserver{Name: name, IPs: ips})
	}

	if len(roots) > 0 {
		r.rootHints = roots
		return nil
	}
	return errors.New("no valid root hints found")
}

func (r *RecursiveResolver) Resolve(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, errors.New("no question")
	}

	q := req.Question[0]
	qName := strings.ToLower(q.Name)

	LogDebug("[RECURSION] [START] Resolving %s %s (QNameMin: %v)", qName, dns.TypeToString[q.Qtype], r.config.QNameMinimization)

	visited := make(map[string]int)

	// QNAME Minimization
	if r.config.QNameMinimization && q.Qtype != dns.TypeNS {
		labels := dns.SplitDomainName(qName)
		// RFC 7816: Iterate from root labels down
		for i := len(labels) - 1; i > 0; i-- {
			partialName := dns.Fqdn(strings.Join(labels[len(labels)-1-i:], "."))
			// Prime the cache
			LogDebug("[RECURSION] [WALK] QNAME Minimization Step: Asking for NS %s", partialName)
			resp, err := r.iterativeQuery(ctx, partialName, dns.TypeNS, 0, visited, reqCtx)

			// If minimization fails (e.g. broken nameserver), we stop optimization but don't fail the request.
			// We just let the Full Resolution below handle it with the full QNAME.
			if err != nil {
				LogDebug("[RECURSION] [WALK] Minimization step failed for %s: %v. Falling back to full QNAME.", partialName, err)
				break
			}
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				LogDebug("[RECURSION] [WALK] Minimization step got NXDOMAIN for %s. Stopping minimization.", partialName)
				break
			}
		}
	}

	// Full resolution
	LogDebug("[RECURSION] [WALK] Starting Full Resolution for %s", qName)
	resp, err := r.iterativeQuery(ctx, qName, q.Qtype, 0, visited, reqCtx)
	if err != nil {
		LogDebug("[RECURSION] [FAILED] Resolution failed for %s: %v", qName, err)
		return nil, err
	}
	LogDebug("[RECURSION] [SUCCESS] Resolved %s (RCODE: %s)", qName, dns.RcodeToString[resp.Rcode])
	return resp, nil
}

// Optimized Iterative Query with RTT Awareness
func (r *RecursiveResolver) iterativeQuery(ctx context.Context, qName string, qType uint16, depth int, visited map[string]int, reqCtx *RequestContext) (*dns.Msg, error) {
	if depth > r.config.MaxDepth {
		LogDebug("[RECURSION] [WALK] Max depth exceeded for %s", qName)
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	loopKey := fmt.Sprintf("%s:%d", qName, qType)
	if visited[loopKey] > 5 {
		LogDebug("[RECURSION] [WALK] Loop detected for %s", loopKey)
		return nil, fmt.Errorf("loop detected")
	}
	visited[loopKey]++

	zone, nsList, hit := r.getClosestNS(qName)
	if !hit {
		LogDebug("[RECURSION] [WALK] No cached NS for %s, starting at ROOT", qName)
		nsList = r.rootHints
	} else {
		if zone != "." && zone != "" {
			LogDebug("[RECURSION] [WALK] Shortcut: Cached zone '%s' found for '%s' (%d servers)", zone, qName, len(nsList))
		} else {
			LogDebug("[RECURSION] [WALK] Cached NS found for zone %s (%d servers)", zone, len(nsList))
		}
	}

	// --- RTT SORTING STRATEGY ---
	// Create a copy to sort without locking the cache
	candidates := make([]*Nameserver, len(nsList))
	copy(candidates, nsList)

	// Sort candidates:
	// 1. FailureCount (prefer 0)
	// 2. RTT (lowest first)
	// 3. Random shuffle for 0-RTT/new items (load balancing)
	sort.Slice(candidates, func(i, j int) bool {
		f1 := candidates[i].FailureCount.Load()
		f2 := candidates[j].FailureCount.Load()
		if f1 != f2 {
			return f1 < f2
		}

		rtt1 := candidates[i].RTT.Load()
		rtt2 := candidates[j].RTT.Load()

		if rtt1 == 0 && rtt2 == 0 {
			return rand.IntN(2) == 0 // Randomize new ones
		}
		if rtt1 == 0 {
			return false
		} // Prefer proven
		if rtt2 == 0 {
			return true
		}

		return rtt1 < rtt2
	})

	// Happy Eyeballs: Race the top 3
	const concurrency = 3
	limit := len(candidates)
	if limit > concurrency {
		limit = concurrency
	}

	type raceResult struct {
		msg *dns.Msg
		err error
		ns  *Nameserver
	}

	resultCh := make(chan raceResult, limit)
	stepCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	active := 0
	for i := 0; i < limit; i++ {
		ns := candidates[i]
		// Get IPs (this might recurse, handled by singleflight)
		LogDebug("[RECURSION] [WALK] Step: Resolving IP for NS %s (Zone: %s)", ns.Name, zone)
		ips := r.getIPsForNS(ctx, ns, depth, visited, reqCtx)
		if len(ips) == 0 {
			LogDebug("[RECURSION] [WALK] No IPs resolved for NS %s, trying next candidate", ns.Name)
			continue
		}
		targetIP := r.pickIP(ips)
		if targetIP == nil {
			LogDebug("[RECURSION] [WALK] No usable IP (IP Version mismatch?) for NS %s", ns.Name)
			continue
		}

		active++
		go func(targetNS *Nameserver, ip net.IP) {
			start := time.Now()
			LogDebug("[RECURSION] [WALK] Sending Query: %s %s -> %s (%s)", qName, dns.TypeToString[qType], targetNS.Name, ip)
			resp, err := r.exchange(stepCtx, ip, qName, qType)
			duration := time.Since(start)

			// Update RTT
			if err != nil {
				targetNS.UpdateRTT(duration, true)
				LogDebug("[RECURSION] [WALK] Query Failed: %s (%s) Error: %v (Duration: %v)", targetNS.Name, ip, err, duration)
			} else {
				targetNS.UpdateRTT(duration, false)
				LogDebug("[RECURSION] [WALK] Query Success: %s (%s) Rcode: %s (Duration: %v)", targetNS.Name, ip, dns.RcodeToString[resp.Rcode], duration)
			}

			if err == nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
				select {
				case resultCh <- raceResult{msg: resp, err: nil, ns: targetNS}:
				case <-stepCtx.Done():
				}
			} else {
				select {
				case resultCh <- raceResult{msg: resp, err: err, ns: targetNS}:
				case <-stepCtx.Done():
				}
			}
		}(ns, targetIP)
	}

	if active == 0 {
		return nil, fmt.Errorf("no reachable nameservers for zone %s", zone)
	}

	var response *dns.Msg
	var lastErr error

	for i := 0; i < active; i++ {
		select {
		case res := <-resultCh:
			if res.err == nil && res.msg != nil {
				response = res.msg
				cancel() // Stop others
				goto ProcessResponse
			}
			if res.err != nil {
				lastErr = res.err
			} else if res.msg != nil {
				response = res.msg
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if response == nil {
		return nil, lastErr
	}

ProcessResponse:
	switch response.Rcode {
	case dns.RcodeSuccess:
		// Referral
		if len(response.Answer) == 0 && len(response.Ns) > 0 {
			referralZone, referralNS, glue := r.extractReferral(response)
			if len(referralNS) > 0 {
				LogDebug("[RECURSION] [WALK] Referral Received: %s -> Delegates to %s (%d NS, %d Glue)", zone, referralZone, len(referralNS), len(glue))
				r.updateInfraCache(referralZone, referralNS, glue)

				// RECURSE: Continue walking down the tree
				return r.iterativeQuery(ctx, qName, qType, depth+1, visited, reqCtx)
			}
		}
		// CNAME
		if len(response.Answer) > 0 && response.Answer[0].Header().Rrtype == dns.TypeCNAME && qType != dns.TypeCNAME {
			cname := response.Answer[0].(*dns.CNAME)
			LogDebug("[RECURSION] [WALK] CNAME Found: %s -> %s. Restarting walk for target.", qName, cname.Target)
			targetResp, err := r.iterativeQuery(ctx, cname.Target, qType, depth+1, visited, reqCtx)
			if err == nil && targetResp != nil {
				response.Answer = append(response.Answer, targetResp.Answer...)
			}
			return response, nil
		}
		// Direct Answer
		LogDebug("[RECURSION] [WALK] Answer Received for %s", qName)
		return response, nil
	case dns.RcodeNameError:
		LogDebug("[RECURSION] [WALK] NXDOMAIN Received for %s", qName)
		return response, nil
	default:
		return response, nil
	}
}

func (r *RecursiveResolver) exchange(ctx context.Context, ip net.IP, qName string, qType uint16) (*dns.Msg, error) {
	m := getMsg()
	defer putMsg(m)
	m.SetQuestion(qName, qType)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)
	// Fixed: discard the duration return value to match function signature
	msg, _, err := r.client.ExchangeContext(ctx, m, net.JoinHostPort(ip.String(), "53"))
	return msg, err
}

// Optimized Closest NS Finder (Sharded & Zero-Alloc)
func (r *RecursiveResolver) getClosestNS(qName string) (string, []*Nameserver, bool) {
	// Start with full name
	end := len(qName)
	if end > 0 && qName[end-1] == '.' {
		// qName is fqdn
	} else {
		end++ // virtual dot
	}

	off := 0
	for {
		zone := qName[off:]
		shard := r.cache.getShard(zone)

		shard.RLock()
		val, ok := shard.nsCache[zone]
		if ok && time.Now().Before(val.expiresAt) {
			data := val.data
			shard.RUnlock()
			return zone, data, true
		}
		shard.RUnlock()

		// Move to next dot
		nextDot := -1
		for i := off; i < len(qName); i++ {
			if qName[i] == '.' {
				nextDot = i
				break
			}
		}
		if nextDot == -1 {
			if off == 0 && qName == "." {
				break
			}
			if off < len(qName) {
				off = len(qName)
				continue
			}
			break
		}
		off = nextDot + 1
		if off >= len(qName) {
			break
		}
	}
	return ".", nil, false
}

func (r *RecursiveResolver) getIPsForNS(ctx context.Context, ns *Nameserver, depth int, visited map[string]int, reqCtx *RequestContext) []net.IP {
	mode := strings.ToLower(r.config.IPVersion)

	// Helper to filter IPs
	filterIPs := func(input []net.IP) []net.IP {
		if mode == "both" {
			return input
		}
		var filtered []net.IP
		for _, ip := range input {
			isV4 := ip.To4() != nil
			if mode == "ipv4" && isV4 {
				filtered = append(filtered, ip)
			} else if mode == "ipv6" && !isV4 {
				filtered = append(filtered, ip)
			}
		}
		return filtered
	}

	if len(ns.IPs) > 0 {
		filtered := filterIPs(ns.IPs)
		if len(filtered) > 0 {
			LogDebug("[RECURSION] Using existing IPs for NS %s: %v", ns.Name, filtered)
			return filtered
		}
		// If filtering removed all IPs, fall through to resolve them (maybe we need A but only have AAAA glue)
	}

	shard := r.cache.getShard(ns.Name)
	shard.RLock()
	val, ok := shard.glueCache[ns.Name]
	if ok && time.Now().Before(val.expiresAt) {
		shard.RUnlock()
		filtered := filterIPs(val.data)
		if len(filtered) > 0 {
			LogDebug("[RECURSION] [GLUE-HIT] Found glue for %s: %v", ns.Name, filtered)
			return filtered
		}
	}
	shard.RUnlock()

	key := "glue:" + ns.Name + ":" + r.config.IPVersion
	res, err, _ := r.glueGroup.Do(key, func() (interface{}, error) {
		LogDebug("[RECURSION] [GLUE-MISS] Resolving glue for %s (Key: %s)", ns.Name, key)
		var ips []net.IP
		var mu sync.Mutex
		var wg sync.WaitGroup

		resolve := func(qType uint16) {
			defer wg.Done()

			// Must copy visited map to prevent concurrent map read/write or side effects in recursion
			visitedCopy := make(map[string]int, len(visited))
			for k, v := range visited {
				visitedCopy[k] = v
			}

			// Perform recursive lookup for the nameserver's own name
			LogDebug("[RECURSION] [GLUE-RESOLVE] Recursive lookup for %s %s", ns.Name, dns.TypeToString[qType])
			resp, err := r.iterativeQuery(ctx, ns.Name, qType, depth+1, visitedCopy, reqCtx)
			if err != nil || resp == nil {
				LogDebug("[RECURSION] [GLUE-RESOLVE] Failed for %s %s: %v", ns.Name, dns.TypeToString[qType], err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					if mode == "ipv4" || mode == "both" {
						ips = append(ips, v.A)
					}
				case *dns.AAAA:
					if mode == "ipv6" || mode == "both" {
						ips = append(ips, v.AAAA)
					}
				}
			}
		}

		if mode == "ipv4" || mode == "both" {
			wg.Add(1)
			go resolve(dns.TypeA)
		}
		if mode == "ipv6" || mode == "both" {
			wg.Add(1)
			go resolve(dns.TypeAAAA)
		}

		wg.Wait()

		if len(ips) > 0 {
			// Cache the result (Glue Cache)
			expires := time.Now().Add(infraCacheTTL)
			gShard := r.cache.getShard(ns.Name)
			gShard.Lock()
			gShard.glueCache[ns.Name] = infraCacheEntry[[]net.IP]{data: ips, expiresAt: expires}
			gShard.Unlock()

			LogDebug("[RECURSION] Resolved Glue for %s: %v", ns.Name, ips)
		} else {
			LogDebug("[RECURSION] Failed to resolve Glue for %s", ns.Name)
		}

		return ips, nil
	})

	if err != nil {
		return nil
	}
	return res.([]net.IP)
}

func (r *RecursiveResolver) extractReferral(msg *dns.Msg) (string, []*Nameserver, map[string][]net.IP) {
	nsMap := make(map[string][]net.IP)
	var nsList []*Nameserver
	zone := ""

	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			zone = strings.ToLower(ns.Header().Name)
			name := strings.ToLower(ns.Ns)
			nsList = append(nsList, &Nameserver{Name: name})
			nsMap[name] = []net.IP{}
		}
	}
	for _, rr := range msg.Extra {
		name := strings.ToLower(rr.Header().Name)
		if _, ok := nsMap[name]; ok {
			switch v := rr.(type) {
			case *dns.A:
				nsMap[name] = append(nsMap[name], v.A)
			case *dns.AAAA:
				nsMap[name] = append(nsMap[name], v.AAAA)
			}
		}
	}
	for i := range nsList {
		if ips := nsMap[nsList[i].Name]; len(ips) > 0 {
			nsList[i].IPs = ips
		}
	}
	return zone, nsList, nsMap
}

func (r *RecursiveResolver) updateInfraCache(zone string, nsList []*Nameserver, glue map[string][]net.IP) {
	LogDebug("[RECURSION] Updating Infra Cache for zone %s (%d NS)", zone, len(nsList))
	expires := time.Now().Add(infraCacheTTL)

	// Update NS Cache
	shard := r.cache.getShard(zone)
	shard.Lock()
	shard.nsCache[zone] = infraCacheEntry[[]*Nameserver]{data: nsList, expiresAt: expires}
	shard.Unlock()

	// Update Glue Cache (might cross shards)
	for name, ips := range glue {
		if len(ips) == 0 {
			continue
		}
		gShard := r.cache.getShard(name)
		gShard.Lock()
		gShard.glueCache[name] = infraCacheEntry[[]net.IP]{data: ips, expiresAt: expires}
		gShard.Unlock()
	}
}

func (r *RecursiveResolver) pickIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	// Simple random for now, can be improved with v4/v6 preference config
	return ips[rand.IntN(len(ips))]
}

