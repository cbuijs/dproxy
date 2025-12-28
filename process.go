/*
File: process.go
Description: Handles the core processing logic for DNS requests, including Singleflight, EDNS0 extraction,
             logging, response cleaning, and forwarding to upstreams with specific strategies.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const EDNS0_OPTION_MAC = 65001

type RequestContext struct {
	ClientIP       net.IP
	ClientMAC      net.HardwareAddr
	ClientECS      net.IP
	ClientECSNet   *net.IPNet
	ClientEDNSMAC  net.HardwareAddr
	ServerIP       net.IP
	ServerPort     int
	ServerHostname string
	ServerPath     string
	QueryName      string
	Protocol       string
}

// --- Result type for singleflight ---

type queryResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
}

// --- Core Processing ---

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtx *RequestContext) {
	start := time.Now()

	remoteAddr := w.RemoteAddr()
	ip := getIPFromAddr(remoteAddr)
	mac := getMacFromCache(ip)

	reqCtx.ClientIP = ip
	reqCtx.ClientMAC = mac

	extractEDNS0ClientInfo(r, reqCtx)

	msg := r.Copy()
	addEDNS0Options(msg, ip, mac)

	var qInfo, cacheKey, ecsSubnet string
	if len(r.Question) > 0 {
		q := r.Question[0]
		reqCtx.QueryName = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		qInfo = fmt.Sprintf("%s (%s)", q.Name, dns.TypeToString[q.Qtype])
	}

	if reqCtx.ClientECS != nil {
		if reqCtx.ClientECSNet != nil {
			mask, _ := reqCtx.ClientECSNet.Mask.Size()
			ecsSubnet = fmt.Sprintf("%s/%d", reqCtx.ClientECS.String(), mask)
		} else {
			ecsSubnet = reqCtx.ClientECS.String()
		}
	}

	if opt := r.IsEdns0(); opt != nil {
		var extra []string
		if reqCtx.ClientECS != nil {
			extra = append(extra, fmt.Sprintf("ECS:%s", ecsSubnet))
		}
		if reqCtx.ClientEDNSMAC != nil {
			extra = append(extra, fmt.Sprintf("MAC65001:%s", reqCtx.ClientEDNSMAC.String()))
		}
		if len(extra) > 0 {
			qInfo += fmt.Sprintf(" [%s]", strings.Join(extra, " "))
		}
	}

	if len(r.Question) > 0 {
		q := r.Question[0]

		effectiveIP := reqCtx.ClientIP
		if reqCtx.ClientECS != nil {
			effectiveIP = reqCtx.ClientECS
		}

		effectiveMAC := reqCtx.ClientMAC
		if reqCtx.ClientEDNSMAC != nil {
			effectiveMAC = reqCtx.ClientEDNSMAC
		}

		routingKey := fmt.Sprintf("%s:%d:%s:%s:%s:%s",
			reqCtx.ServerIP, reqCtx.ServerPort, reqCtx.ServerHostname, reqCtx.ServerPath,
			effectiveIP, effectiveMAC)
		cacheKey = fmt.Sprintf("%s|%d|%d|%s", q.Name, q.Qtype, q.Qclass, routingKey)
	}

	// Check cache before singleflight
	if config.Cache.Enabled && cacheKey != "" {
		if cachedResp := getFromCache(cacheKey, r.Id); cachedResp != nil {
			cleanResponse(cachedResp)
			logRequest(r.Id, reqCtx, qInfo, "CACHE_HIT", "CACHE", 0, time.Since(start), cachedResp)
			w.WriteMsg(cachedResp)
			return
		}
	}

	// Use singleflight to coalesce identical requests
	result, err, shared := requestGroup.Do(cacheKey, func() (interface{}, error) {
		resp, upstreamStr, rtt, err := forwardToUpstreamsWithContext(ctx, msg, reqCtx)
		if err != nil {
			return nil, err
		}
		return queryResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt}, nil
	})

	if err != nil {
		log.Printf("Error forwarding %s from %s: %v", qInfo, ip, err)
		dns.HandleFailed(w, r)
		return
	}

	qr := result.(queryResult)
	resp := qr.msg

	// If this was a shared result, make a copy to avoid race conditions
	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		cleanResponse(resp)
	}

	// Add to cache
	if config.Cache.Enabled && resp != nil {
		addToCache(cacheKey, resp)
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	logRequest(r.Id, reqCtx, qInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)

	resp.Id = r.Id
	w.WriteMsg(resp)
}

// --- Strategies ---

func forwardToUpstreamsWithContext(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	selectedUpstreams, selectedStrategy := SelectUpstreams(reqCtx)
	return forwardToUpstreams(ctx, req, selectedUpstreams, selectedStrategy)
}

func forwardToUpstreams(ctx context.Context, req *dns.Msg, upstreams []*Upstream, strategy string) (*dns.Msg, string, time.Duration, error) {
	if len(upstreams) == 0 {
		return nil, "", 0, errors.New("no upstreams available")
	}

	if len(upstreams) == 1 {
		u := upstreams[0]
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err
	}

	strat := strings.ToLower(strategy)

	switch strat {
	case "round-robin":
		return roundRobinStrategy(ctx, req, upstreams)

	case "random":
		return randomStrategy(ctx, req, upstreams)

	case "failover":
		return failoverStrategy(ctx, req, upstreams)

	case "fastest":
		return fastestStrategy(ctx, req, upstreams)

	case "race":
		return raceStrategy(ctx, req, upstreams)

	default:
		log.Printf("[STRATEGY] Unknown strategy '%s', using failover", strategy)
		return failoverStrategy(ctx, req, upstreams)
	}
}

func roundRobinStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	idx := rrCounter.Add(1) - 1
	selected := int(idx) % len(upstreams)
	u := upstreams[selected]
	
	log.Printf("[STRATEGY] Round-Robin: Selected #%d/%d: %s", selected+1, len(upstreams), u.String())
	
	resp, rtt, err := u.executeExchange(ctx, req)
	if err != nil {
		log.Printf("[STRATEGY] Round-Robin: Failed with %s: %v, trying failover", u.String(), err)
		// Fallback to next upstream
		for i := 1; i < len(upstreams); i++ {
			nextIdx := (selected + i) % len(upstreams)
			u = upstreams[nextIdx]
			log.Printf("[STRATEGY] Round-Robin Failover: Trying #%d/%d: %s", nextIdx+1, len(upstreams), u.String())
			resp, rtt, err = u.executeExchange(ctx, req)
			if err == nil {
				log.Printf("[STRATEGY] Round-Robin Failover: Success with %s", u.String())
				return resp, u.String(), rtt, nil
			}
			log.Printf("[STRATEGY] Round-Robin Failover: Failed with %s: %v", u.String(), err)
		}
		return nil, "", 0, fmt.Errorf("all upstreams failed in round-robin")
	}
	
	log.Printf("[STRATEGY] Round-Robin: Success with %s (RTT: %v)", u.String(), rtt)
	return resp, u.String(), rtt, nil
}

func randomStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	idx := rand.IntN(len(upstreams))
	u := upstreams[idx]
	
	log.Printf("[STRATEGY] Random: Selected #%d/%d: %s", idx+1, len(upstreams), u.String())
	
	resp, rtt, err := u.executeExchange(ctx, req)
	if err != nil {
		log.Printf("[STRATEGY] Random: Failed with %s: %v, trying others", u.String(), err)
		// Try remaining upstreams in random order
		for i := 1; i < len(upstreams); i++ {
			nextIdx := (idx + i) % len(upstreams)
			u = upstreams[nextIdx]
			log.Printf("[STRATEGY] Random Failover: Trying #%d/%d: %s", nextIdx+1, len(upstreams), u.String())
			resp, rtt, err = u.executeExchange(ctx, req)
			if err == nil {
				log.Printf("[STRATEGY] Random Failover: Success with %s", u.String())
				return resp, u.String(), rtt, nil
			}
			log.Printf("[STRATEGY] Random Failover: Failed with %s: %v", u.String(), err)
		}
		return nil, "", 0, fmt.Errorf("all upstreams failed in random")
	}
	
	log.Printf("[STRATEGY] Random: Success with %s (RTT: %v)", u.String(), rtt)
	return resp, u.String(), rtt, nil
}

func failoverStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	log.Printf("[STRATEGY] Failover: Starting sequence with %d upstreams", len(upstreams))
	
	for i, u := range upstreams {
		log.Printf("[STRATEGY] Failover: Attempting #%d/%d: %s", i+1, len(upstreams), u.String())
		
		resp, rtt, err := u.executeExchange(ctx, req)
		if err == nil {
			log.Printf("[STRATEGY] Failover: Success with %s (RTT: %v)", u.String(), rtt)
			return resp, u.String(), rtt, nil
		}
		
		log.Printf("[STRATEGY] Failover: Failed %s: %v", u.String(), err)
	}
	
	log.Printf("[STRATEGY] Failover: All %d upstreams failed", len(upstreams))
	return nil, "", 0, errors.New("all upstreams failed in failover")
}

func fastestStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	// Smart exploration strategy to prevent lock-in
	// Parameters can be tuned based on your needs
	const (
		explorationRate    = 0.15  // 15% of requests explore alternatives
		staleThreshold     = 30 * time.Second // Consider RTT data stale after this time
		minProbeInterval   = 10 * time.Second // Minimum time between probes per upstream
		rttDifferenceRatio = 0.8   // Explore if another upstream is within 80% of best RTT
	)

	now := time.Now()
	
	// Build stats with freshness information
	type upstreamStat struct {
		upstream     *Upstream
		rtt          int64
		lastProbed   time.Time
		isStale      bool
		index        int
	}
	
	stats := make([]upstreamStat, len(upstreams))
	for i, u := range upstreams {
		rtt := u.getRTT()
		lastProbe := u.getLastProbeTime()
		isStale := rtt > 0 && now.Sub(lastProbe) > staleThreshold
		
		stats[i] = upstreamStat{
			upstream:   u,
			rtt:        rtt,
			lastProbed: lastProbe,
			isStale:    isStale,
			index:      i,
		}
	}

	// Sort by RTT (0 values last, stale data deprioritized)
	sort.Slice(stats, func(i, j int) bool {
		rttI, rttJ := stats[i].rtt, stats[j].rtt
		staleI, staleJ := stats[i].isStale, stats[j].isStale
		
		// Prioritize fresh data over stale data
		if staleI != staleJ {
			return !staleI // Non-stale comes first
		}
		
		// Both have no RTT data - keep original order
		if rttI == 0 && rttJ == 0 {
			return stats[i].index < stats[j].index
		}
		
		// i has no data, j has data - j is better
		if rttI == 0 {
			return false
		}
		
		// i has data, j has no data - i is better
		if rttJ == 0 {
			return true
		}
		
		// Both have data - lower RTT wins
		return rttI < rttJ
	})

	best := stats[0].upstream
	bestRTT := stats[0].rtt
	
	// Exploration logic - prevent lock-in
	shouldExplore := false
	var explorationTarget *Upstream
	var explorationReason string
	
	// Reason 1: Random exploration (epsilon-greedy approach)
	if rand.Float64() < explorationRate {
		// Pick a random upstream that hasn't been probed recently
		candidates := make([]*Upstream, 0)
		for _, s := range stats[1:] { // Skip the best one
			if now.Sub(s.lastProbed) > minProbeInterval {
				candidates = append(candidates, s.upstream)
			}
		}
		
		if len(candidates) > 0 {
			explorationTarget = candidates[rand.IntN(len(candidates))]
			shouldExplore = true
			explorationReason = "random exploration (epsilon-greedy)"
		}
	}
	
	// Reason 2: Check for upstreams without RTT data
	if !shouldExplore {
		for _, s := range stats {
			if s.rtt == 0 && now.Sub(s.lastProbed) > minProbeInterval {
				explorationTarget = s.upstream
				shouldExplore = true
				explorationReason = "no RTT data available"
				break
			}
		}
	}
	
	// Reason 3: Stale data needs refresh
	if !shouldExplore && stats[0].isStale {
		explorationTarget = best
		shouldExplore = true
		explorationReason = "RTT data is stale"
	}
	
	// Reason 4: Competitive upstream (within 20% of best RTT)
	if !shouldExplore && bestRTT > 0 && len(stats) > 1 {
		for _, s := range stats[1:] {
			if s.rtt > 0 && now.Sub(s.lastProbed) > minProbeInterval {
				// Check if this upstream is competitive (within 20% difference)
				if float64(s.rtt) <= float64(bestRTT)/rttDifferenceRatio {
					explorationTarget = s.upstream
					shouldExplore = true
					explorationReason = fmt.Sprintf("competitive RTT (%v vs best %v)", 
						time.Duration(s.rtt), time.Duration(bestRTT))
					break
				}
			}
		}
	}
	
	// Reason 5: Background probing of all upstreams periodically
	for _, s := range stats {
		if now.Sub(s.lastProbed) > 3*staleThreshold {
			// This upstream hasn't been checked in a very long time
			// Launch async probe with a real, commonly-resolved domain
			go func(u *Upstream) {
				probeMsg := new(dns.Msg)
				// Use well-known, highly-available domains from major tech companies
				// These are guaranteed to resolve and are globally cached
				probeDomains := []string{
					"google.com.",      // Google - most queried domain globally
					"googleapis.com.",  // Google APIs - heavily used by apps
					"apple.com.",       // Apple - global presence
					"microsoft.com.",   // Microsoft - enterprise standard
					"facebook.com.",    // Meta - social media giant
				}
				probeDomain := probeDomains[rand.IntN(len(probeDomains))]
				probeMsg.SetQuestion(probeDomain, dns.TypeA)
				probeMsg.RecursionDesired = true
				
				probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				
				_, rtt, err := u.executeExchange(probeCtx, probeMsg)
				if err == nil {
					log.Printf("[STRATEGY] Fastest: Background probe of %s completed (domain: %s, RTT: %v)", 
						u.String(), probeDomain, rtt)
				} else {
					log.Printf("[STRATEGY] Fastest: Background probe of %s failed (domain: %s): %v", 
						u.String(), probeDomain, err)
				}
			}(s.upstream)
		}
	}
	
	// Decide which upstream to use
	var selectedUpstream *Upstream
	if shouldExplore && explorationTarget != nil {
		selectedUpstream = explorationTarget
		log.Printf("[STRATEGY] Fastest: EXPLORING %s (reason: %s)", 
			selectedUpstream.String(), explorationReason)
	} else {
		selectedUpstream = best
		if bestRTT == 0 {
			log.Printf("[STRATEGY] Fastest: Selected %s (no RTT data yet)", best.String())
		} else if stats[0].isStale {
			log.Printf("[STRATEGY] Fastest: Selected %s (RTT: %v - STALE)", 
				best.String(), time.Duration(bestRTT))
		} else {
			log.Printf("[STRATEGY] Fastest: Selected %s (RTT: %v)", 
				best.String(), time.Duration(bestRTT))
		}
	}

	// Execute query
	resp, rtt, err := selectedUpstream.executeExchange(ctx, req)
	
	if err != nil {
		log.Printf("[STRATEGY] Fastest: Failed with %s: %v, trying alternatives", 
			selectedUpstream.String(), err)
		
		// Try remaining upstreams in order of speed
		for _, s := range stats {
			if s.upstream == selectedUpstream {
				continue // Skip the one we just tried
			}
			
			u := s.upstream
			currentRTT := s.rtt
			
			if currentRTT == 0 {
				log.Printf("[STRATEGY] Fastest Failover: Trying %s (no RTT data)", u.String())
			} else {
				log.Printf("[STRATEGY] Fastest Failover: Trying %s (RTT: %v)", 
					u.String(), time.Duration(currentRTT))
			}
			
			resp, rtt, err = u.executeExchange(ctx, req)
			if err == nil {
				// Check response code
				if resp.Rcode != dns.RcodeSuccess {
					log.Printf("[STRATEGY] Fastest Failover: Non-success response from %s (RCODE: %s, RTT: %v - not used for RTT stats)", 
						u.String(), dns.RcodeToString[resp.Rcode], rtt)
				} else {
					log.Printf("[STRATEGY] Fastest Failover: Success with %s (RTT: %v)", 
						u.String(), rtt)
				}
				return resp, u.String(), rtt, nil
			}
			
			log.Printf("[STRATEGY] Fastest Failover: Failed with %s: %v", u.String(), err)
		}
		
		return nil, "", 0, fmt.Errorf("all upstreams failed in fastest strategy")
	}

	// Check if exploration resulted in non-success response
	rcodeStr := dns.RcodeToString[resp.Rcode]
	if resp.Rcode != dns.RcodeSuccess {
		if shouldExplore {
			log.Printf("[STRATEGY] Fastest: Exploration completed with %s (RCODE: %s, RTT: %v - not used for RTT stats)", 
				selectedUpstream.String(), rcodeStr, rtt)
		} else {
			log.Printf("[STRATEGY] Fastest: Non-success response from %s (RCODE: %s, RTT: %v - not used for RTT stats)", 
				selectedUpstream.String(), rcodeStr, rtt)
		}
	} else {
		if shouldExplore {
			log.Printf("[STRATEGY] Fastest: Exploration successful with %s (RTT: %v)", 
				selectedUpstream.String(), rtt)
		} else {
			log.Printf("[STRATEGY] Fastest: Success with %s (RTT: %v)", selectedUpstream.String(), rtt)
		}
	}
	
	return resp, selectedUpstream.String(), rtt, nil
}

func raceStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	log.Printf("[STRATEGY] Race: Starting race among %d upstreams", len(upstreams))

	type result struct {
		msg  *dns.Msg
		name string
		rtt  time.Duration
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan result, len(upstreams))

	// Launch all queries in parallel
	for _, u := range upstreams {
		go func(upstream *Upstream) {
			log.Printf("[STRATEGY] Race: Querying %s", upstream.String())
			resp, rtt, err := upstream.executeExchange(ctx, req)
			
			select {
			case resCh <- result{msg: resp, name: upstream.String(), rtt: rtt, err: err}:
			case <-ctx.Done():
			}
		}(u)
	}

	var lastErr error
	successCount := 0
	failCount := 0
	
	// Wait for first success or all failures
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				successCount++
				log.Printf("[STRATEGY] Race: Winner #%d: %s (RTT: %v)", successCount, res.name, res.rtt)
				
				// First success wins
				if successCount == 1 {
					// Cancel other pending requests
					cancel()
					
					log.Printf("[STRATEGY] Race: Completed - %s won", res.name)
					return res.msg, res.name, res.rtt, nil
				}
			} else {
				failCount++
				lastErr = res.err
				log.Printf("[STRATEGY] Race: Failed %s: %v", res.name, res.err)
			}
			
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}
	}

	// All failed
	if lastErr != nil {
		log.Printf("[STRATEGY] Race: All %d upstreams failed", len(upstreams))
		return nil, "", 0, fmt.Errorf("all upstreams failed in race: %w", lastErr)
	}
	
	return nil, "", 0, errors.New("all upstreams failed in race")
}

// --- Helpers ---

func cleanResponse(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.Ns = nil
	msg.Extra = nil
	if len(msg.Answer) > 0 {
		newAnswer := make([]dns.RR, 0, len(msg.Answer))
		for _, rr := range msg.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY, dns.TypeDLV:
				continue
			default:
				newAnswer = append(newAnswer, rr)
			}
		}
		msg.Answer = newAnswer
	}
}

func logRequest(qid uint16, reqCtx *RequestContext, qInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
	macStr := "N/A"
	if reqCtx.ClientMAC != nil {
		macStr = reqCtx.ClientMAC.String()
	}

	ingress := fmt.Sprintf("%s:%d", reqCtx.ServerIP, reqCtx.ServerPort)
	if reqCtx.ServerHostname != "" {
		ingress += fmt.Sprintf(" | Host:%s", reqCtx.ServerHostname)
	}
	if reqCtx.ServerPath != "" {
		ingress += fmt.Sprintf(" | Path:%s", reqCtx.ServerPath)
	}

	log.Printf("[QRY] QID:%d | Client:%s | MAC:%s | Proto:%s | Ingress:%s | Query:%s",
		qid, reqCtx.ClientIP, macStr, reqCtx.Protocol, ingress, qInfo)

	if upstream != "" && upstream != "CACHE" {
		log.Printf("[FWD] QID:%d | Upstream:%s | RTT:%v | Query:%s | Response:%s", qid, upstream, upstreamRTT, qInfo, status)
	}

	var answers []string
	if resp != nil {
		addRRs := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				parts := strings.Fields(rr.String())
				if len(parts) >= 4 {
					s := parts[3]
					if len(parts) > 4 {
						s += " " + strings.Join(parts[4:], " ")
					}
					answers = append(answers, s)
				}
			}
		}
		addRRs(resp.Answer)
		addRRs(resp.Ns)
		addRRs(resp.Extra)
	}

	ansStr := strings.Join(answers, ", ")
	if ansStr == "" {
		ansStr = "Empty"
	}

	log.Printf("[RSP] QID:%d | Status:%s | TotalTime:%v | Answers:[%s]", qid, status, duration, ansStr)
}

func extractEDNS0ClientInfo(msg *dns.Msg, reqCtx *RequestContext) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}

	for _, option := range opt.Option {
		switch o := option.(type) {
		case *dns.EDNS0_SUBNET:
			reqCtx.ClientECS = o.Address
			family := o.Family
			mask := o.SourceNetmask
			var ipNet *net.IPNet
			if family == 1 {
				if mask > 32 {
					mask = 32
				}
				maskBytes := net.CIDRMask(int(mask), 32)
				ipNet = &net.IPNet{IP: o.Address, Mask: maskBytes}
			} else if family == 2 {
				if mask > 128 {
					mask = 128
				}
				maskBytes := net.CIDRMask(int(mask), 128)
				ipNet = &net.IPNet{IP: o.Address, Mask: maskBytes}
			}
			reqCtx.ClientECSNet = ipNet
			log.Printf("[EDNS0] Extracted ECS: %s/%d (family: %d)", o.Address.String(), mask, family)

		case *dns.EDNS0_LOCAL:
			if o.Code == EDNS0_OPTION_MAC && len(o.Data) > 0 {
				reqCtx.ClientEDNSMAC = net.HardwareAddr(o.Data)
				log.Printf("[EDNS0] Extracted MAC from Option 65001: %s", reqCtx.ClientEDNSMAC.String())
			}
		}
	}
}

func addEDNS0Options(msg *dns.Msg, ip net.IP, mac net.HardwareAddr) {
	o := msg.IsEdns0()
	if o == nil {
		msg.SetEdns0(4096, true)
		o = msg.IsEdns0()
	}

	var opts []dns.EDNS0
	var hasECS bool

	for _, opt := range o.Option {
		if _, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			opts = append(opts, opt)
		} else if local, ok := opt.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
			continue
		} else {
			opts = append(opts, opt)
		}
	}

	if !hasECS && ip != nil {
		family := uint16(1)
		mask := uint8(32)
		if ip.To4() == nil {
			family = 2
			mask = 128
		}
		opts = append(opts, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: family,
			SourceNetmask: mask, Address: ip,
		})
	}

	if mac != nil {
		opts = append(opts, &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: mac})
	}

	o.Option = opts
}

