/*
File: recursive.go
Version: 1.2.0
Description: Implements a full recursive (iterative) resolver with QNAME minimization,
             loop detection, and infrastructure caching (NS/Glue).
             UPDATED: Added explicit Cache HIT/MISS logging for NS and Glue records.
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
	nsCache   sync.Map // Map[zoneString][]Nameserver
	glueCache sync.Map // Map[hostString][]net.IP
}

type RecursiveResolver struct {
	config    RecursionConfig
	rootHints []Nameserver
	cache     *InfrastructureCache
	client    *dns.Client
}

func NewRecursiveResolver(cfg RecursionConfig) *RecursiveResolver {
	rr := &RecursiveResolver{
		config: cfg,
		cache:  &InfrastructureCache{},
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
		// Iteratively resolve parents to prime the cache
		for i := len(labels) - 1; i > 0; i-- {
			// Construct partial name: e.g., "com.", "example.com."
			partialName := dns.Fqdn(strings.Join(labels[len(labels)-1-i:], "."))

			LogDebug("[RECURSION] [MINIMIZATION] Priming cache for partial: %s", partialName)
			// Query for NS of the partial name
			// We ignore the result; we just want the infrastructure cache populated
			r.iterativeQuery(ctx, partialName, dns.TypeNS, 0, visited, reqCtx)
		}
	}

	// Full resolution
	resp, err := r.iterativeQuery(ctx, qName, q.Qtype, 0, visited, reqCtx)
	if err != nil {
		LogDebug("[RECURSION] [FAILED] Resolution failed for %s: %v", qName, err)
		return nil, err
	}
	LogDebug("[RECURSION] [SUCCESS] Resolved %s (RCODE: %s)", qName, dns.RcodeToString[resp.Rcode])
	return resp, nil
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

	LogDebug("[RECURSION] [STEP %d] Querying %s %s", depth, qName, dns.TypeToString[qType])

	// 1. Find closest zone with known NS servers
	zone, nsList, hit := r.getClosestNS(qName)
	if !hit {
		LogDebug("[RECURSION] [NS-MISS] No cached NS found for %s, falling back to ROOT hints.", qName)
		nsList = r.rootHints
	} else {
		LogDebug("[RECURSION] [NS-HIT] Found cached NS for closest zone '%s' (%d servers). Shortcut taken.", zone, len(nsList))
	}

	var lastErr error

	// Try servers in the zone
	// Shuffle to load balance
	rand.Shuffle(len(nsList), func(i, j int) { nsList[i], nsList[j] = nsList[j], nsList[i] })

	for i, ns := range nsList {
		LogDebug("[RECURSION] [ATTEMPT %d/%d] Trying NS %s for zone %s", i+1, len(nsList), ns.Name, zone)

		// Resolve NS IP if missing (Glue logic)
		ips := r.getIPsForNS(ctx, ns, depth, visited, reqCtx)
		if len(ips) == 0 {
			LogDebug("[RECURSION] Failed to resolve IP for NS %s, skipping", ns.Name)
			continue
		}

		// Pick an IP based on config preference
		targetIP := r.pickIP(ips)
		if targetIP == nil {
			LogDebug("[RECURSION] No suitable IP (v4/v6 mismatch) for NS %s, skipping", ns.Name)
			continue
		}

		// 2. Query the Authoritative Server
		LogDebug("[RECURSION] Sending query to %s (%s)", targetIP, ns.Name)
		response, err := r.exchange(ctx, targetIP, qName, qType)
		if err != nil {
			LogDebug("[RECURSION] Exchange failed with %s (%s): %v", ns.Name, targetIP, err)
			lastErr = err
			continue
		}

		LogDebug("[RECURSION] Received response from %s: %s (Answer: %d, Auth: %d, Extra: %d)",
			targetIP, dns.RcodeToString[response.Rcode], len(response.Answer), len(response.Ns), len(response.Extra))

		// 3. Analyze Response
		switch response.Rcode {
		case dns.RcodeSuccess:
			// Is it a referral? (No Answer, but NS in Authority)
			if len(response.Answer) == 0 && len(response.Ns) > 0 {
				referralZone, referralNS, glue := r.extractReferral(response)
				if len(referralNS) > 0 {
					LogDebug("[RECURSION] Referral received to zone '%s' (%d NS records, %d Glue IPs)", referralZone, len(referralNS), len(glue))
					
					// Cache the referral
					r.updateInfraCache(referralZone, referralNS, glue)
					
					// Continue recursion with new zone
					LogDebug("[RECURSION] Following referral to %s", referralZone)
					return r.iterativeQuery(ctx, qName, qType, depth+1, visited, reqCtx)
				}
				// NODATA (Success RCode but no answer and no useful referral)
				LogDebug("[RECURSION] NODATA received for %s", qName)
				return response, nil
			}

			// CNAME Handling
			if len(response.Answer) > 0 && response.Answer[0].Header().Rrtype == dns.TypeCNAME && qType != dns.TypeCNAME {
				cnameRR := response.Answer[0].(*dns.CNAME)
				LogDebug("[RECURSION] CNAME found: %s -> %s. Restarting recursion for target.", qName, cnameRR.Target)
				
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
			LogDebug("[RECURSION] Final answer received for %s", qName)
			return response, nil

		case dns.RcodeNameError:
			LogDebug("[RECURSION] NXDOMAIN received for %s", qName)
			return response, nil

		default:
			// Server failure, refused, etc. Try next NS.
			LogDebug("[RECURSION] Upstream error %s from %s", dns.RcodeToString[response.Rcode], ns.Name)
			lastErr = fmt.Errorf("upstream rcode: %s", dns.RcodeToString[response.Rcode])
		}
	}

	if lastErr != nil {
		LogWarn("[RECURSION] All servers for zone %s failed. Last error: %v", zone, lastErr)
		return nil, lastErr
	}
	LogWarn("[RECURSION] All servers for zone %s failed (exhausted).", zone)
	return nil, errors.New("all authoritative servers failed")
}

func (r *RecursiveResolver) exchange(ctx context.Context, ip net.IP, qName string, qType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
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
	// Try full name, then parents
	// e.g. www.example.com. -> example.com. -> com. -> .

	off := 0
	for {
		zone := qName[off:]
		if val, ok := r.cache.nsCache.Load(zone); ok {
			return zone, val.([]Nameserver), true
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
		LogDebug("[RECURSION] [GLUE-HIT] Using provided glue for %s: %v. Shortcut taken.", ns.Name, ns.IPs)
		return ns.IPs
	}

	// 2. Check Glue Cache
	if val, ok := r.cache.glueCache.Load(ns.Name); ok {
		ips := val.([]net.IP)
		LogDebug("[RECURSION] [GLUE-HIT] Found cached glue for %s: %v. Shortcut taken.", ns.Name, ips)
		return ips
	}

	// 3. Resolve the NS name (Chicken and egg prevention needed?)
	// To prevent loops, we must ensure we aren't trying to resolve a name that is part of the zone we are stuck in.
	// But `iterativeQuery` handles loop detection via `visited`.

	LogDebug("[RECURSION] [GLUE-MISS] No glue for %s, resolving A/AAAA records...", ns.Name)
	var ips []net.IP

	if r.config.IPVersion == "ipv4" || r.config.IPVersion == "both" {
		if resp, err := r.iterativeQuery(ctx, ns.Name, dns.TypeA, depth+1, visited, reqCtx); err == nil && resp != nil {
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, a.A)
				}
			}
		}
	}
	if r.config.IPVersion == "ipv6" || r.config.IPVersion == "both" {
		if resp, err := r.iterativeQuery(ctx, ns.Name, dns.TypeAAAA, depth+1, visited, reqCtx); err == nil && resp != nil {
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.AAAA); ok {
					ips = append(ips, a.AAAA)
				}
			}
		}
	}

	if len(ips) > 0 {
		LogDebug("[RECURSION] [GLUE-RESOLVED] Resolved and cached IPs for %s: %v", ns.Name, ips)
		r.cache.glueCache.Store(ns.Name, ips)
	} else {
		LogDebug("[RECURSION] [GLUE-FAILED] Failed to resolve any IPs for NS %s", ns.Name)
	}
	return ips
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
	LogDebug("[RECURSION] [CACHE-UPDATE] Caching %d NS records for zone %s", len(nsList), zone)
	r.cache.nsCache.Store(zone, nsList)
	
	if len(glue) > 0 {
		LogDebug("[RECURSION] [CACHE-UPDATE] Caching %d glue records", len(glue))
		for name, ips := range glue {
			if len(ips) > 0 {
				r.cache.glueCache.Store(name, ips)
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

	preferV6 := r.config.IPVersion == "ipv6"
	preferV4 := r.config.IPVersion == "ipv4"

	if preferV6 && len(v6) > 0 {
		return v6[rand.IntN(len(v6))]
	}
	if preferV4 && len(v4) > 0 {
		return v4[rand.IntN(len(v4))]
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

