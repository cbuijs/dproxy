/*
File: recursive.go
Version: 1.6.0
Description: Implements a full recursive (iterative) resolver with QNAME minimization,
             loop detection, and infrastructure caching (NS/Glue).
             OPTIMIZED: Parallelized Glue Resolution (A/AAAA).
             OPTIMIZED: Happy Eyeballs / Concurrent Queries for Authoritative Servers.
             OPTIMIZED: Switched Cache to RWMutex for better read performance and type safety.
             OPTIMIZED: Added Singleflight to prevent thundering herd on Glue resolution.
             OPTIMIZED: Used object pooling (getMsg/putMsg) in exchange() to reduce GC pressure.
             FIXED: Strictly enforce ip_version config (ipv4/ipv6) in pickIP and glue resolution.
*/

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Global instance
var recursiveResolver *RecursiveResolver

// Nameserver represents an authoritative server
type Nameserver struct {
	Name string
	IPs  []net.IP
}

// InfrastructureCache stores NS records and Glue IPs to speed up recursion
type InfrastructureCache struct {
	sync.RWMutex
	nsCache   map[string][]Nameserver
	glueCache map[string][]net.IP
}

type RecursiveResolver struct {
	config    RecursionConfig
	rootHints []Nameserver
	cache     *InfrastructureCache
	client    *dns.Client
	glueGroup singleflight.Group
}

func NewRecursiveResolver(cfg RecursionConfig) *RecursiveResolver {
	rr := &RecursiveResolver{
		config: cfg,
		cache: &InfrastructureCache{
			nsCache:   make(map[string][]Nameserver),
			glueCache: make(map[string][]net.IP),
		},
		client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second, // Aggressive timeout for individual recursion steps
		},
	}

	rr.loadRootHints()
	return rr
}

// Built-in Root Hints (IANA)
func (r *RecursiveResolver) loadRootHints() {
	// If file provided, load it
	if r.config.RootHintsFile != "" {
		if err := r.parseRootHintsFile(r.config.RootHintsFile); err != nil {
			LogWarn("[RECURSION] Failed to load root hints file %s: %v. Using built-ins.", r.config.RootHintsFile, err)
			r.useBuiltInRoots()
		} else {
			LogInfo("[RECURSION] Loaded root hints from %s", r.config.RootHintsFile)
		}
	} else {
		r.useBuiltInRoots()
	}
}

func (r *RecursiveResolver) useBuiltInRoots() {
	// Simplified set of Root Servers (A-M)
	r.rootHints = []Nameserver{
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

	var roots []Nameserver
	nsMap := make(map[string][]net.IP)

	zp := dns.NewZoneParser(bufio.NewReader(f), ".", path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			// Just tracking presence
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
		roots = append(roots, Nameserver{Name: name, IPs: ips})
	}

	if len(roots) > 0 {
		r.rootHints = roots
		return nil
	}
	return errors.New("no valid root hints found in file")
}

// Resolve is the entry point
func (r *RecursiveResolver) Resolve(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, errors.New("no question")
	}

	q := req.Question[0]
	qName := strings.ToLower(q.Name)

	LogDebug("[RECURSION] [START] Resolving %s %s (QNameMin: %v)", qName, dns.TypeToString[q.Qtype], r.config.QNameMinimization)

	// Loop detection context
	visited := make(map[string]int)

	// QNAME Minimization Logic (RFC 7816)
	if r.config.QNameMinimization && q.Qtype != dns.TypeNS {
		labels := dns.SplitDomainName(qName)
		for i := len(labels) - 1; i > 0; i-- {
			partialName := dns.Fqdn(strings.Join(labels[len(labels)-1-i:], "."))

			LogDebug("[RECURSION] [MINIMIZATION] Step: Querying partial label '%s' (NS) to prime cache", partialName)
			
			// We iterate, but we expect errors or NXDOMAINs as we drill down.
			// We are only priming the cache here.
			resp, err := r.iterativeQuery(ctx, partialName, dns.TypeNS, 0, visited, reqCtx)
			
			if err != nil {
				LogDebug("[RECURSION] [MINIMIZATION] Failed for '%s': %v. Stopping minimization, falling back to full resolution.", partialName, err)
				break
			}
			
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				LogDebug("[RECURSION] [MINIMIZATION] Got NXDOMAIN for '%s'. Stopping minimization.", partialName)
				break 
			}
		}
	}

	// Full resolution
	LogDebug("[RECURSION] [FULL-RESOLVE] Starting full resolution for %s", qName)
	resp, err := r.iterativeQuery(ctx, qName, q.Qtype, 0, visited, reqCtx)
	if err != nil {
		LogDebug("[RECURSION] [FAILED] Resolution failed for %s: %v", qName, err)
		return nil, err
	}
	LogDebug("[RECURSION] [SUCCESS] Resolved %s (RCODE: %s)", qName, dns.RcodeToString[resp.Rcode])
	return resp, nil
}

// resultStruct for concurrent lookups
type exchangeResult struct {
	msg *dns.Msg
	err error
	ns  string
}

func (r *RecursiveResolver) iterativeQuery(ctx context.Context, qName string, qType uint16, depth int, visited map[string]int, reqCtx *RequestContext) (*dns.Msg, error) {
	if depth > r.config.MaxDepth {
		LogWarn("[RECURSION] Max depth exceeded for %s", qName)
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	// Check loop detection
	loopKey := fmt.Sprintf("%s:%d", qName, qType)
	if visited[loopKey] > 5 {
		LogWarn("[RECURSION] Loop detected for %s %s", qName, dns.TypeToString[qType])
		return nil, fmt.Errorf("recursion loop detected for %s", qName)
	}
	visited[loopKey]++

	// 1. Find closest zone with known NS servers
	zone, nsList, hit := r.getClosestNS(qName)
	if !hit {
		LogDebug("[RECURSION] [NS-MISS] No cached NS found for %s, falling back to ROOT hints", qName)
		nsList = r.rootHints
	} else {
		LogDebug("[RECURSION] [NS-HIT] Found cached NS for closest zone '%s' (%d servers). Shortcut taken.", zone, len(nsList))
	}

	// Shuffle to load balance
	rand.Shuffle(len(nsList), func(i, j int) { nsList[i], nsList[j] = nsList[j], nsList[i] })

	// --- OPTIMIZATION: Concurrent Queries (Happy Eyeballs) ---
	// Instead of trying one by one, we try top 3 simultaneously.
	
	const concurrency = 3
	candidates := nsList
	if len(candidates) > concurrency {
		candidates = candidates[:concurrency]
	}

	// Channel to receive the first successful answer
	resultCh := make(chan exchangeResult, len(candidates))
	
	// Context for this iteration step - cancel others if one succeeds
	stepCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	activeWorkers := 0

	for _, ns := range candidates {
		// Resolve IPs (Parallelized internally)
		ips := r.getIPsForNS(ctx, ns, depth, visited, reqCtx)
		if len(ips) == 0 {
			LogDebug("[RECURSION] Failed to resolve IP for NS %s, skipping", ns.Name)
			continue
		}

		targetIP := r.pickIP(ips)
		if targetIP == nil {
			continue
		}

		activeWorkers++
		go func(targetNS Nameserver, ip net.IP) {
			// Perform exchange
			resp, err := r.exchange(stepCtx, ip, qName, qType)
			
			// If successful answer or definitive error (NXDOMAIN/Success), send result
			if err == nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
				select {
				case resultCh <- exchangeResult{msg: resp, err: nil, ns: targetNS.Name}:
				case <-stepCtx.Done():
				}
			} else {
				// Send error/failure, but don't cancel context
				select {
				case resultCh <- exchangeResult{msg: resp, err: err, ns: targetNS.Name}:
				case <-stepCtx.Done():
				}
			}
		}(ns, targetIP)
	}

	if activeWorkers == 0 {
		return nil, fmt.Errorf("no reachable nameservers for zone %s", zone)
	}

	var lastErr error
	var response *dns.Msg
	var winningNS string

	// Wait for first success or all failures
	for i := 0; i < activeWorkers; i++ {
		select {
		case res := <-resultCh:
			if res.err == nil && res.msg != nil {
				// We got a good response!
				response = res.msg
				winningNS = res.ns
				// Cancel other requests immediately
				cancel()
				goto ProcessResponse
			}
			// Store last error/response to return if all fail
			if res.err != nil {
				lastErr = res.err
			} else if res.msg != nil {
				response = res.msg
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// If we exited loop, no success found
	if lastErr != nil {
		LogWarn("[RECURSION] All servers for zone %s failed. Last error: %v", zone, lastErr)
		return nil, lastErr
	}
	if response != nil {
		// We have a response but it wasn't Success/NXDOMAIN? (Should be covered above, but safety fallback)
		goto ProcessResponse
	}
	
	return nil, errors.New("all authoritative servers failed")

ProcessResponse:
	// 3. Analyze Response
	switch response.Rcode {
	case dns.RcodeSuccess:
		// Is it a referral? (No Answer, but NS in Authority)
		if len(response.Answer) == 0 && len(response.Ns) > 0 {
			referralZone, referralNS, glue := r.extractReferral(response)
			if len(referralNS) > 0 {
				LogDebug("[RECURSION] Referral received to zone '%s' (%d NS records, %d Glue IPs) from %s", referralZone, len(referralNS), len(glue), winningNS)
				
				// Cache the referral
				r.updateInfraCache(referralZone, referralNS, glue)
				
				// Continue recursion with new zone
				LogDebug("[RECURSION] Following referral to %s", referralZone)
				return r.iterativeQuery(ctx, qName, qType, depth+1, visited, reqCtx)
			}
			// NODATA
			LogDebug("[RECURSION] NODATA received for %s from %s", qName, winningNS)
			return response, nil
		}

		// CNAME Handling
		if len(response.Answer) > 0 && response.Answer[0].Header().Rrtype == dns.TypeCNAME && qType != dns.TypeCNAME {
			cnameRR := response.Answer[0].(*dns.CNAME)
			LogDebug("[RECURSION] CNAME found: %s -> %s [Restarting recursion]", qName, cnameRR.Target)
			
			// Restart recursion for the CNAME target
			targetResp, err := r.iterativeQuery(ctx, cnameRR.Target, qType, depth+1, visited, reqCtx)
			if err == nil && targetResp != nil {
				// Prepend CNAME to answer
				response.Answer = append(response.Answer, targetResp.Answer...)
				return response, nil
			}
			LogDebug("[RECURSION] Failed to resolve CNAME target %s", cnameRR.Target)
			return response, nil
		}

		// Actual Answer
		LogDebug("[RECURSION] Final answer received for %s from %s", qName, winningNS)
		return response, nil

	case dns.RcodeNameError:
		LogDebug("[RECURSION] NXDOMAIN received for %s from %s", qName, winningNS)
		return response, nil

	default:
		// Logic should ideally have filtered this in the race loop, but if it's the only response we got:
		LogDebug("[RECURSION] Upstream returned %s from %s", dns.RcodeToString[response.Rcode], winningNS)
		return response, fmt.Errorf("upstream rcode: %s", dns.RcodeToString[response.Rcode])
	}
}

func (r *RecursiveResolver) exchange(ctx context.Context, ip net.IP, qName string, qType uint16) (*dns.Msg, error) {
	// OPTIMIZATION: Use message pool to reduce GC pressure
	m := getMsg()
	defer putMsg(m)

	m.SetQuestion(qName, qType)
	// Iterative queries must NOT have Recursion Desired set
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	addr := net.JoinHostPort(ip.String(), "53")
	resp, _, err := r.client.ExchangeContext(ctx, m, addr)
	return resp, err
}

// getClosestNS walks up the domain tree to find cached NS records
func (r *RecursiveResolver) getClosestNS(qName string) (string, []Nameserver, bool) {
	r.cache.RLock()
	defer r.cache.RUnlock()

	// Try full name, then parents
	// e.g. www.example.com. -> example.com. -> com. -> .

	off := 0
	for {
		zone := qName[off:]
		if val, ok := r.cache.nsCache[zone]; ok {
			return zone, val, true
		}

		// Move to next dot
		nextOff, end := dns.NextLabel(qName, off)
		if end {
			break
		}
		off = nextOff
	}

	return ".", nil, false
}

func (r *RecursiveResolver) getIPsForNS(ctx context.Context, ns Nameserver, depth int, visited map[string]int, reqCtx *RequestContext) []net.IP {
	// 1. Check if we already have IPs (Glue passed in struct)
	if len(ns.IPs) > 0 {
		return ns.IPs
	}

	// 2. Check Glue Cache
	r.cache.RLock()
	if ips, ok := r.cache.glueCache[ns.Name]; ok {
		r.cache.RUnlock()
		return ips
	}
	r.cache.RUnlock()

	// 3. Resolve the NS name
	// OPTIMIZATION: Use Singleflight to prevent Thundering Herd
	// If 100 clients ask for a zone needing this glue, we only resolve it ONCE.
	
	key := fmt.Sprintf("glue:%s:%s", ns.Name, r.config.IPVersion)

	val, err, _ := r.glueGroup.Do(key, func() (interface{}, error) {
		LogDebug("[RECURSION] [GLUE-MISS] No glue for %s, resolving A/AAAA records...", ns.Name)

		// OPTIMIZATION: Resolve A and AAAA concurrently
		var ips []net.IP
		var mu sync.Mutex
		var wg sync.WaitGroup

		resolveType := func(qType uint16) {
			defer wg.Done()
			
			// Copy visited map to avoid race conditions in recursive calls
			visitedCopy := make(map[string]int, len(visited))
			for k, v := range visited {
				visitedCopy[k] = v
			}

			if resp, err := r.iterativeQuery(ctx, ns.Name, qType, depth+1, visitedCopy, reqCtx); err == nil && resp != nil {
				mu.Lock()
				defer mu.Unlock()
				for _, rr := range resp.Answer {
					switch v := rr.(type) {
					case *dns.A:
						ips = append(ips, v.A)
					case *dns.AAAA:
						ips = append(ips, v.AAAA)
					}
				}
			}
		}

		// Strict config handling: use lowercase to support "IPv4" or "ipv4"
		mode := strings.ToLower(r.config.IPVersion)

		if mode == "ipv4" || mode == "both" {
			wg.Add(1)
			go resolveType(dns.TypeA)
		}
		if mode == "ipv6" || mode == "both" {
			wg.Add(1)
			go resolveType(dns.TypeAAAA)
		}

		wg.Wait()
		
		if len(ips) > 0 {
			LogDebug("[RECURSION] [GLUE-RESOLVED] Resolved and cached IPs for %s: %v", ns.Name, ips)
			r.cache.Lock()
			r.cache.glueCache[ns.Name] = ips
			r.cache.Unlock()
		} else {
			LogDebug("[RECURSION] [GLUE-FAILED] Failed to resolve any IPs for NS %s", ns.Name)
		}
		
		return ips, nil
	})

	if err != nil {
		return nil
	}
	return val.([]net.IP)
}

func (r *RecursiveResolver) extractReferral(msg *dns.Msg) (string, []Nameserver, map[string][]net.IP) {
	nsMap := make(map[string][]net.IP) // Name -> Glue IPs
	var nsList []Nameserver
	zone := ""

	// Process Authority section for NS records
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			zone = strings.ToLower(ns.Header().Name)
			nsName := strings.ToLower(ns.Ns)
			nsList = append(nsList, Nameserver{Name: nsName})
			// Initialize map entry
			if _, exists := nsMap[nsName]; !exists {
				nsMap[nsName] = []net.IP{}
			}
		}
	}

	// Process Additional section for Glue
	for _, rr := range msg.Extra {
		header := rr.Header()
		name := strings.ToLower(header.Name)

		if _, needed := nsMap[name]; needed {
			switch v := rr.(type) {
			case *dns.A:
				nsMap[name] = append(nsMap[name], v.A)
			case *dns.AAAA:
				nsMap[name] = append(nsMap[name], v.AAAA)
			}
		}
	}

	// Populate IPs back into nsList
	for i := range nsList {
		if ips, ok := nsMap[nsList[i].Name]; ok && len(ips) > 0 {
			nsList[i].IPs = ips
		}
	}

	return zone, nsList, nsMap
}

func (r *RecursiveResolver) updateInfraCache(zone string, nsList []Nameserver, glue map[string][]net.IP) {
	r.cache.Lock()
	defer r.cache.Unlock()
	
	r.cache.nsCache[zone] = nsList
	
	if len(glue) > 0 {
		for name, ips := range glue {
			if len(ips) > 0 {
				r.cache.glueCache[name] = ips
			}
		}
	}
}

func (r *RecursiveResolver) pickIP(ips []net.IP) net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	// Case-insensitive comparison
	mode := strings.ToLower(r.config.IPVersion)

	// STRICT ENFORCEMENT
	if mode == "ipv6" {
		if len(v6) > 0 {
			return v6[rand.IntN(len(v6))]
		}
		return nil
	}
	if mode == "ipv4" {
		if len(v4) > 0 {
			return v4[rand.IntN(len(v4))]
		}
		return nil
	}

	// "both" - prefer v6 if available (modern best practice), else v4
	if len(v6) > 0 {
		return v6[rand.IntN(len(v6))]
	}
	if len(v4) > 0 {
		return v4[rand.IntN(len(v4))]
	}
	return nil
}

