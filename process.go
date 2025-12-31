/*
File: process.go
Description: Handles the core processing logic for DNS requests, including Singleflight, EDNS0 extraction,
             logging, response cleaning, HOSTS file checking, and forwarding to upstreams.
             UPDATED: Fixed HOSTS Lookup call to handle the 2 return values (answers, found).
             UPDATED: Updated HOSTS LookupPTR call to handle the 2 return values (answers, found).
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
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

func (rc *RequestContext) Reset() {
	rc.ClientIP = nil
	rc.ClientMAC = nil
	rc.ClientECS = nil
	rc.ClientECSNet = nil
	rc.ClientEDNSMAC = nil
	rc.ServerIP = nil
	rc.ServerPort = 0
	rc.ServerHostname = ""
	rc.ServerPath = ""
	rc.QueryName = ""
	rc.Protocol = ""
}

var reqCtxPool = sync.Pool{
	New: func() any {
		return &RequestContext{}
	},
}

var raceLimiter = make(chan struct{}, 4096)

type queryResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
}

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtxFromHandler *RequestContext) {
	start := time.Now()

	reqCtx := reqCtxPool.Get().(*RequestContext)
	reqCtx.Reset()
	defer reqCtxPool.Put(reqCtx)

	reqCtx.ServerIP = reqCtxFromHandler.ServerIP
	reqCtx.ServerPort = reqCtxFromHandler.ServerPort
	reqCtx.Protocol = reqCtxFromHandler.Protocol
	reqCtx.ServerHostname = reqCtxFromHandler.ServerHostname
	reqCtx.ServerPath = reqCtxFromHandler.ServerPath

	remoteAddr := w.RemoteAddr()
	ip := getIPFromAddr(remoteAddr)
	mac := getMacFromCache(ip)

	reqCtx.ClientIP = ip
	reqCtx.ClientMAC = mac

	extractEDNS0ClientInfo(r, reqCtx)

	var qInfo, cacheKey string
	var qType uint16
	var sb strings.Builder

	if len(r.Question) > 0 {
		q := r.Question[0]
		reqCtx.QueryName = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		qType = q.Qtype

		sb.Grow(len(q.Name) + 10)
		sb.WriteString(q.Name)
		sb.WriteString(" (")
		sb.WriteString(dns.TypeToString[q.Qtype])
		sb.WriteString(")")
		qInfo = sb.String()
		sb.Reset()
	}

	if opt := r.IsEdns0(); opt != nil {
		sb.WriteString(qInfo)
		firstExtra := true
		if reqCtx.ClientECS != nil {
			sb.WriteString(" [ECS:")
			if reqCtx.ClientECSNet != nil {
				mask, _ := reqCtx.ClientECSNet.Mask.Size()
				sb.WriteString(reqCtx.ClientECS.String())
				sb.WriteString("/")
				sb.WriteString(strconv.Itoa(mask))
			} else {
				sb.WriteString(reqCtx.ClientECS.String())
			}
			sb.WriteString("]")
			firstExtra = false
		}
		if reqCtx.ClientEDNSMAC != nil {
			if !firstExtra {
				sb.WriteString(" ")
			} else {
				sb.WriteString(" [")
			}
			sb.WriteString("MAC65001:")
			sb.WriteString(reqCtx.ClientEDNSMAC.String())
			if firstExtra {
				sb.WriteString("]")
			}
		}
		if sb.Len() > len(qInfo) {
			qInfo = sb.String()
		}
		sb.Reset()
	}

	// UPDATED: SelectUpstreams now returns Hosts info
	selectedUpstreams, selectedStrategy, ruleName, hostsCache, hostsWildcard := SelectUpstreams(reqCtx)

	if len(r.Question) > 0 {
		q := r.Question[0]
		routingKey := ruleName

		sb.Reset()
		sb.WriteString(q.Name)
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qtype)))
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qclass)))
		sb.WriteString("|")
		sb.WriteString(routingKey)
		cacheKey = sb.String()
	}

	// --- HOSTS FILE CHECK ---
	// Checked BEFORE internal cache so updates (e.g. blocklists) take effect immediately
	if hostsCache != nil && len(r.Question) > 0 {
		var answers []dns.RR
		var found bool
		qName := r.Question[0].Name

		if qType == dns.TypePTR {
			// Updated signature handling
			answers, found = hostsCache.LookupPTR(qName)
		} else {
			// Updated signature handling
			answers, found = hostsCache.Lookup(qName, qType, hostsWildcard)
		}

		if found {
			resp := new(dns.Msg)
			resp.SetReply(r)
			
			if len(answers) > 0 {
				resp.Answer = answers
				LogDebug("[PROCESS] Serving from HOSTS file (Rule: %s)", ruleName)
				logRequest(r.Id, reqCtx, qInfo, "", "NOERROR (HOSTS)", "HOSTS", 0, time.Since(start), resp)
			} else {
				// Found name in hosts, but not for this type (e.g. AAAA query but only IPv4 in hosts)
				// OR it's a BLOCKED PTR query (0.0.0.0) where answers is nil
				// Return NXDOMAIN as requested to stop further resolution
				resp.Rcode = dns.RcodeNameError
				LogDebug("[PROCESS] Serving NXDOMAIN from HOSTS file (Rule: %s, Type mismatch or Blocked PTR)", ruleName)
				logRequest(r.Id, reqCtx, qInfo, "", "NXDOMAIN (HOSTS)", "HOSTS", 0, time.Since(start), resp)
			}
			
			w.WriteMsg(resp)
			return
		}
	}

	// Check cache
	if config.Cache.Enabled && cacheKey != "" {
		if cachedResp := getFromCache(cacheKey, r.Id); cachedResp != nil {
			status := fmt.Sprintf("CACHE_HIT (%s)", ruleName)
			logRequest(r.Id, reqCtx, qInfo, "", status, "CACHE", 0, time.Since(start), cachedResp)
			w.WriteMsg(cachedResp)
			return
		}
	}

	msg := r.Copy()
	addEDNS0Options(msg, ip, mac)
	upstreamQInfo := buildUpstreamInfo(msg)

	if opt := msg.IsEdns0(); opt != nil {
		var ednsInfo []string
		for _, option := range opt.Option {
			if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
				ednsInfo = append(ednsInfo, fmt.Sprintf("ECS=%s/%d", ecs.Address, ecs.SourceNetmask))
			} else if local, ok := option.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
				ednsInfo = append(ednsInfo, fmt.Sprintf("MAC65001=%s", net.HardwareAddr(local.Data)))
			}
		}
		if len(ednsInfo) > 0 {
			LogDebug("[UPSTREAM_EDNS0] QID:%d | Forwarding with: %s", r.Id, strings.Join(ednsInfo, ", "))
		}
	}

	// Singleflight
	result, err, shared := requestGroup.Do(cacheKey, func() (interface{}, error) {
		resp, upstreamStr, rtt, err := forwardToUpstreams(ctx, msg, selectedUpstreams, selectedStrategy, reqCtx)
		if err != nil {
			return nil, err
		}
		return queryResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt}, nil
	})

	if err != nil {
		// Distinguish between timeout (load shedding) and actual errors
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			LogWarn("Query timeout for %s from %s (Upstreams busy/slow)", qInfo, ip)
		} else {
			LogError("Error forwarding %s from %s: %v", qInfo, ip, err)
		}
		
		// Ensure client always gets an answer (SERVFAIL)
		dns.HandleFailed(w, r)
		return
	}

	qr := result.(queryResult)
	resp := qr.msg

	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		cleanResponse(resp)
	}

	if config.Cache.Enabled && resp != nil {
		addToCache(cacheKey, resp)

		// --- CROSS-FETCH TRIGGER ---
		// After successful upstream response, trigger background prefetch for related types
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			// Create a copy of request context for background goroutine
			prefetchCtx := &RequestContext{
				ClientIP:  reqCtx.ClientIP,
				ClientMAC: reqCtx.ClientMAC,
			}
			go TriggerCrossFetch(reqCtx.QueryName, qType, ruleName, selectedUpstreams, selectedStrategy, prefetchCtx)
		}
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	logRequest(r.Id, reqCtx, qInfo, upstreamQInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)

	resp.Id = r.Id
	w.WriteMsg(resp)
}

// --- Strategies ---

func forwardToUpstreams(ctx context.Context, req *dns.Msg, upstreams []*Upstream, strategy string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	if len(upstreams) == 0 {
		return nil, "", 0, errors.New("no upstreams available")
	}

	if len(upstreams) == 1 {
		u := upstreams[0]
		resp, rtt, err := u.executeExchange(ctx, req, reqCtx)
		return resp, u.DynamicString(reqCtx), rtt, err
	}

	strat := strings.ToLower(strategy)

	switch strat {
	case "round-robin":
		return roundRobinStrategy(ctx, req, upstreams, reqCtx)
	case "random":
		return randomStrategy(ctx, req, upstreams, reqCtx)
	case "failover":
		return failoverStrategy(ctx, req, upstreams, reqCtx)
	case "fastest":
		return fastestStrategy(ctx, req, upstreams, reqCtx)
	case "race":
		return raceStrategy(ctx, req, upstreams, reqCtx)
	default:
		LogWarn("[STRATEGY] Unknown strategy '%s', using failover", strategy)
		return failoverStrategy(ctx, req, upstreams, reqCtx)
	}
}

func roundRobinStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	startIdx := rrCounter.Add(1) - 1
	n := len(upstreams)

	for i := 0; i < n; i++ {
		idx := (int(startIdx) + i) % n
		u := upstreams[idx]

		if !u.IsHealthy() {
			continue
		}

		LogDebug("[STRATEGY] Round-Robin: Selected #%d/%d: %s", idx+1, n, u.String())
		resp, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			LogDebug("[STRATEGY] Round-Robin: Success with %s (RTT: %v)", u.DynamicString(reqCtx), rtt)
			return resp, u.DynamicString(reqCtx), rtt, nil
		}

		LogWarn("[STRATEGY] Round-Robin: Failed with %s: %v", u.DynamicString(reqCtx), err)
	}

	return nil, "", 0, fmt.Errorf("all upstreams failed or unhealthy in round-robin")
}

func randomStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	n := len(upstreams)
	startIdx := rand.IntN(n)

	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		u := upstreams[idx]

		if !u.IsHealthy() {
			continue
		}

		LogDebug("[STRATEGY] Random: Trying #%d/%d: %s", idx+1, n, u.String())
		resp, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			LogDebug("[STRATEGY] Random: Success with %s (RTT: %v)", u.DynamicString(reqCtx), rtt)
			return resp, u.DynamicString(reqCtx), rtt, nil
		}
		LogWarn("[STRATEGY] Random: Failed with %s: %v", u.DynamicString(reqCtx), err)
	}

	return nil, "", 0, fmt.Errorf("all upstreams failed or unhealthy in random")
}

func failoverStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	for i, u := range upstreams {
		if !u.IsHealthy() {
			continue
		}

		LogDebug("[STRATEGY] Failover: Attempting #%d/%d: %s", i+1, len(upstreams), u.String())
		resp, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			LogDebug("[STRATEGY] Failover: Success with %s (RTT: %v)", u.DynamicString(reqCtx), rtt)
			return resp, u.DynamicString(reqCtx), rtt, nil
		}
		LogWarn("[STRATEGY] Failover: Failed %s: %v", u.DynamicString(reqCtx), err)
	}
	return nil, "", 0, errors.New("all upstreams failed or unhealthy in failover")
}

func fastestStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	const (
		explorationRate    = 0.15
		staleThreshold     = 30 * time.Second
		minProbeInterval   = 10 * time.Second
		rttDifferenceRatio = 0.8
	)

	now := time.Now()
	type upstreamStat struct {
		upstream   *Upstream
		rtt        int64
		lastProbed time.Time
		isStale    bool
		index      int
	}

	stats := make([]upstreamStat, 0, len(upstreams))
	for i, u := range upstreams {
		if !u.IsHealthy() {
			continue
		}

		rtt := u.getRTT()
		lastProbe := u.getLastProbeTime()
		stats = append(stats, upstreamStat{
			upstream:   u,
			rtt:        rtt,
			lastProbed: lastProbe,
			isStale:    rtt > 0 && now.Sub(lastProbe) > staleThreshold,
			index:      i,
		})
	}

	if len(stats) == 0 {
		return nil, "", 0, errors.New("all upstreams are unhealthy (circuit open)")
	}

	sort.Slice(stats, func(i, j int) bool {
		rttI, rttJ := stats[i].rtt, stats[j].rtt
		staleI, staleJ := stats[i].isStale, stats[j].isStale
		if staleI != staleJ {
			return !staleI
		}
		if rttI == 0 && rttJ == 0 {
			return stats[i].index < stats[j].index
		}
		if rttI == 0 {
			return false
		}
		if rttJ == 0 {
			return true
		}
		return rttI < rttJ
	})

	best := stats[0].upstream
	bestRTT := stats[0].rtt
	shouldExplore := false
	var explorationTarget *Upstream
	var explorationReason string

	if rand.Float64() < explorationRate {
		candidates := make([]*Upstream, 0)
		for _, s := range stats[1:] {
			if now.Sub(s.lastProbed) > minProbeInterval {
				candidates = append(candidates, s.upstream)
			}
		}
		if len(candidates) > 0 {
			explorationTarget = candidates[rand.IntN(len(candidates))]
			shouldExplore = true
			explorationReason = "random exploration"
		}
	}
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
	if !shouldExplore && stats[0].isStale {
		explorationTarget = best
		shouldExplore = true
		explorationReason = "RTT data is stale"
	}
	if !shouldExplore && bestRTT > 0 && len(stats) > 1 {
		for _, s := range stats[1:] {
			if s.rtt > 0 && now.Sub(s.lastProbed) > minProbeInterval {
				if float64(s.rtt) <= float64(bestRTT)/rttDifferenceRatio {
					explorationTarget = s.upstream
					shouldExplore = true
					explorationReason = fmt.Sprintf("competitive RTT (%v vs best %v)", time.Duration(s.rtt), time.Duration(bestRTT))
					break
				}
			}
		}
	}

	for _, s := range stats {
		if now.Sub(s.lastProbed) > 3*staleThreshold {
			go func(u *Upstream) {
				probeMsg := new(dns.Msg)
				probeDomains := []string{"google.com.", "apple.com.", "microsoft.com."}
				probeMsg.SetQuestion(probeDomains[rand.IntN(len(probeDomains))], dns.TypeA)
				probeMsg.RecursionDesired = true
				probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				u.executeExchange(probeCtx, probeMsg, &RequestContext{})
			}(s.upstream)
		}
	}

	var selectedUpstream *Upstream
	if shouldExplore && explorationTarget != nil {
		selectedUpstream = explorationTarget
		LogDebug("[STRATEGY] Fastest: EXPLORING %s (reason: %s)", selectedUpstream.String(), explorationReason)
	} else {
		selectedUpstream = best
		LogDebug("[STRATEGY] Fastest: Selected %s (RTT: %v)", best.String(), time.Duration(bestRTT))
	}

	resp, rtt, err := selectedUpstream.executeExchange(ctx, req, reqCtx)
	if err != nil {
		LogWarn("[STRATEGY] Fastest: Failed with %s: %v, trying alternatives", selectedUpstream.DynamicString(reqCtx), err)
		for _, s := range stats {
			if s.upstream == selectedUpstream {
				continue
			}
			u := s.upstream
			resp, rtt, err = u.executeExchange(ctx, req, reqCtx)
			if err == nil {
				LogDebug("[STRATEGY] Fastest Failover: Success with %s (RTT: %v)", u.DynamicString(reqCtx), rtt)
				return resp, u.DynamicString(reqCtx), rtt, nil
			}
		}
		return nil, "", 0, fmt.Errorf("all upstreams failed in fastest strategy")
	}

	return resp, selectedUpstream.DynamicString(reqCtx), rtt, nil
}

func raceStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	candidates := make([]*Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		if u.IsHealthy() {
			candidates = append(candidates, u)
		}
	}

	if len(candidates) == 0 {
		return nil, "", 0, errors.New("all upstreams are unhealthy (circuit open)")
	}

	LogDebug("[STRATEGY] Race: Starting race among %d upstreams (filtered from %d)", len(candidates), len(upstreams))

	type result struct {
		msg  *dns.Msg
		name string
		rtt  time.Duration
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resCh := make(chan result, len(candidates))

	for _, u := range candidates {
		select {
		case raceLimiter <- struct{}{}:
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}

		go func(upstream *Upstream) {
			defer func() { <-raceLimiter }()

			resp, rtt, err := upstream.executeExchange(ctx, req, reqCtx)
			if err != nil {
				LogWarn("[STRATEGY] Race: Upstream %s failed: %v", upstream.DynamicString(reqCtx), err)
			} else {
				LogDebug("[STRATEGY] Race: Upstream %s responded in %v", upstream.DynamicString(reqCtx), rtt)
			}
			select {
			case resCh <- result{msg: resp, name: upstream.DynamicString(reqCtx), rtt: rtt, err: err}:
			case <-ctx.Done():
			}
		}(u)
	}

	var lastErr error
	successCount := 0
	for i := 0; i < len(candidates); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				successCount++
				if successCount == 1 {
					LogDebug("[STRATEGY] Race: Winner is %s (RTT: %v)", res.name, res.rtt)
					cancel()
					return res.msg, res.name, res.rtt, nil
				}
			} else {
				lastErr = res.err
			}
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}
	}
	if lastErr != nil {
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
	if len(msg.Answer) == 0 {
		return
	}
	n := 0
	for _, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY, dns.TypeDLV:
			continue
		default:
			if n != -1 {
				msg.Answer[n] = rr
				n++
			}
		}
	}
	msg.Answer = msg.Answer[:n]
}

func logRequest(qid uint16, reqCtx *RequestContext, qInfo, upstreamQInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
	macStr := "N/A"
	if reqCtx.ClientMAC != nil {
		macStr = reqCtx.ClientMAC.String()
	}

	var sb strings.Builder
	sb.WriteString(reqCtx.ServerIP.String())
	sb.WriteString(":")
	sb.WriteString(strconv.Itoa(reqCtx.ServerPort))
	if reqCtx.ServerHostname != "" {
		sb.WriteString(" | Host:")
		sb.WriteString(reqCtx.ServerHostname)
	}
	if reqCtx.ServerPath != "" {
		sb.WriteString(" | Path:")
		sb.WriteString(reqCtx.ServerPath)
	}
	ingress := sb.String()

	LogInfo("[QRY] QID:%d | Client:%s | MAC:%s | Proto:%s | Ingress:%s | Query:%s",
		qid, reqCtx.ClientIP, macStr, reqCtx.Protocol, ingress, qInfo)

	if upstream != "" && upstream != "CACHE" {
		useInfo := qInfo
		if upstreamQInfo != "" {
			useInfo = upstreamQInfo
		}
		LogInfo("[FWD] QID:%d | Upstream:%s | RTT:%v | Query:%s | Response:%s", qid, upstream, upstreamRTT, useInfo, status)
	}

	sb.Reset()
	if resp != nil {
		first := true
		addRRs := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				parts := strings.Fields(rr.String())
				if len(parts) >= 4 {
					if !first {
						sb.WriteString(", ")
					}
					sb.WriteString(parts[3])
					if len(parts) > 4 {
						sb.WriteString(" ")
						sb.WriteString(strings.Join(parts[4:], " "))
					}
					first = false
				}
			}
		}
		addRRs(resp.Answer)
		addRRs(resp.Ns)
		addRRs(resp.Extra)
	}

	ansStr := sb.String()
	if ansStr == "" {
		ansStr = "Empty"
	}

	LogInfo("[RSP] QID:%d | Status:%s | TotalTime:%v | Answers:[%s]", qid, status, duration, ansStr)
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
			LogDebug("[EDNS0] Extracted ECS: %s/%d (family: %d)", o.Address.String(), mask, family)
		case *dns.EDNS0_LOCAL:
			if o.Code == EDNS0_OPTION_MAC && len(o.Data) > 0 {
				reqCtx.ClientEDNSMAC = net.HardwareAddr(o.Data)
				LogDebug("[EDNS0] Extracted MAC from Option 65001: %s", reqCtx.ClientEDNSMAC.String())
			}
		}
	}
}

func buildUpstreamInfo(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	var sb strings.Builder
	sb.WriteString(q.Name)
	sb.WriteString(" (")
	sb.WriteString(dns.TypeToString[q.Qtype])
	sb.WriteString(")")
	opt := msg.IsEdns0()
	if opt != nil {
		var extra []string
		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_SUBNET:
				extra = append(extra, fmt.Sprintf("ECS:%s/%d", v.Address.String(), v.SourceNetmask))
			case *dns.EDNS0_LOCAL:
				if v.Code == EDNS0_OPTION_MAC {
					extra = append(extra, fmt.Sprintf("MAC65001:%s", net.HardwareAddr(v.Data).String()))
				}
			}
		}
		if len(extra) > 0 {
			sb.WriteString(" [")
			sb.WriteString(strings.Join(extra, " "))
			sb.WriteString("]")
		}
	}
	return sb.String()
}

func addEDNS0Options(msg *dns.Msg, ip net.IP, mac net.HardwareAddr) {
	o := msg.IsEdns0()
	if o == nil {
		msg.SetEdns0(4096, true)
		o = msg.IsEdns0()
	}
	var opts []dns.EDNS0
	var hasECS bool
	var hasMAC bool
	var existingMAC net.HardwareAddr
	ecsMode := config.Server.EDNS0.ECS.Mode
	macMode := config.Server.EDNS0.MAC.Mode
	macSource := config.Server.EDNS0.MAC.Source
	LogDebug("[EDNS0] Processing options for upstream (ECS mode: %s, MAC mode: %s)", ecsMode, macMode)
	LogDebug("[EDNS0] Client IP: %v, ARP MAC: %v", ip, mac)
	for _, opt := range o.Option {
		if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			LogDebug("[EDNS0] Found existing ECS from client: %s/%d (family: %d)", ecs.Address, ecs.SourceNetmask, ecs.Family)
		} else if local, ok := opt.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
			hasMAC = true
			existingMAC = net.HardwareAddr(local.Data)
			LogDebug("[EDNS0] Found existing MAC from client: %s", existingMAC)
		}
	}
	for _, opt := range o.Option {
		switch v := opt.(type) {
		case *dns.EDNS0_SUBNET:
			switch ecsMode {
			case "preserve":
				opts = append(opts, opt)
				LogDebug("[EDNS0] ECS: Preserving client's ECS: %s/%d", v.Address, v.SourceNetmask)
			case "add":
				if !hasECS {
					LogDebug("[EDNS0] ECS: Client has no ECS, will add client IP")
				} else {
					opts = append(opts, opt)
					LogDebug("[EDNS0] ECS: Client already has ECS, preserving: %s/%d", v.Address, v.SourceNetmask)
				}
			case "replace":
				LogDebug("[EDNS0] ECS: Replacing client's ECS %s/%d with client IP", v.Address, v.SourceNetmask)
			case "remove":
				LogDebug("[EDNS0] ECS: Removing client's ECS: %s/%d", v.Address, v.SourceNetmask)
			}
		case *dns.EDNS0_LOCAL:
			if v.Code == EDNS0_OPTION_MAC {
				switch macMode {
				case "preserve":
					opts = append(opts, opt)
					LogDebug("[EDNS0] MAC: Preserving client's MAC: %s", net.HardwareAddr(v.Data))
				case "add":
					if !hasMAC {
						LogDebug("[EDNS0] MAC: Client has no MAC, will add from source")
					} else {
						opts = append(opts, opt)
						LogDebug("[EDNS0] MAC: Client already has MAC, preserving: %s", net.HardwareAddr(v.Data))
					}
				case "replace":
					LogDebug("[EDNS0] MAC: Replacing client's MAC %s with source MAC", net.HardwareAddr(v.Data))
				case "remove":
					LogDebug("[EDNS0] MAC: Removing client's MAC: %s", net.HardwareAddr(v.Data))
				case "prefer-edns0":
					opts = append(opts, opt)
					LogDebug("[EDNS0] MAC: Preferring client's EDNS0 MAC: %s", net.HardwareAddr(v.Data))
				case "prefer-arp":
					LogDebug("[EDNS0] MAC: Preferring ARP MAC over client's EDNS0 MAC: %s", net.HardwareAddr(v.Data))
				}
			} else {
				opts = append(opts, opt)
			}
		default:
			opts = append(opts, opt)
		}
	}
	shouldAddECS := false
	switch ecsMode {
	case "preserve":
		shouldAddECS = false
	case "add":
		shouldAddECS = !hasECS
	case "replace":
		shouldAddECS = true
	case "remove":
		shouldAddECS = false
	}
	if shouldAddECS && ip != nil {
		family := uint16(1)
		mask := uint8(32)
		isIPv6 := false
		if ip.To4() == nil {
			family = 2
			mask = 128
			isIPv6 = true
		}
		if isIPv6 {
			if config.Server.EDNS0.ECS.IPv6Mask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.IPv6Mask)
				LogDebug("[EDNS0] ECS: Using configured IPv6 mask: /%d", mask)
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
				LogDebug("[EDNS0] ECS: Using configured source mask for IPv6: /%d", mask)
			} else {
				LogDebug("[EDNS0] ECS: Using default IPv6 mask: /%d", mask)
			}
			if mask > 128 {
				mask = 128
			}
		} else {
			if config.Server.EDNS0.ECS.IPv4Mask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.IPv4Mask)
				LogDebug("[EDNS0] ECS: Using configured IPv4 mask: /%d", mask)
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
				LogDebug("[EDNS0] ECS: Using configured source mask for IPv4: /%d", mask)
			} else {
				LogDebug("[EDNS0] ECS: Using default IPv4 mask: /%d", mask)
			}
			if mask > 32 {
				mask = 32
			}
		}
		opts = append(opts, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        family,
			SourceNetmask: mask,
			Address:       ip,
		})
		LogDebug("[EDNS0] ECS: Added to upstream: %s/%d (family: %d)", ip, mask, family)
	} else if !shouldAddECS && ip != nil {
		LogDebug("[EDNS0] ECS: Not adding to upstream (mode: %s, hasECS: %v)", ecsMode, hasECS)
	}
	shouldAddMAC := false
	var macToAdd net.HardwareAddr
	switch macMode {
	case "preserve":
		shouldAddMAC = false
		LogDebug("[EDNS0] MAC: Preserve mode - not adding new MAC")
	case "add":
		shouldAddMAC = !hasMAC
		macToAdd = determineMAC(mac, existingMAC, macSource)
		if shouldAddMAC {
			LogDebug("[EDNS0] MAC: Add mode - will add MAC from source: %s", macSource)
		} else {
			LogDebug("[EDNS0] MAC: Add mode - client already has MAC, not adding")
		}
	case "replace":
		shouldAddMAC = true
		macToAdd = determineMAC(mac, existingMAC, macSource)
		LogDebug("[EDNS0] MAC: Replace mode - will add MAC from source: %s", macSource)
	case "remove":
		shouldAddMAC = false
		LogDebug("[EDNS0] MAC: Remove mode - not adding MAC")
	case "prefer-edns0":
		if hasMAC {
			shouldAddMAC = false
			LogDebug("[EDNS0] MAC: Prefer-EDNS0 mode - already kept client's MAC")
		} else if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
			LogDebug("[EDNS0] MAC: Prefer-EDNS0 mode - no client MAC, adding ARP MAC")
		} else {
			LogDebug("[EDNS0] MAC: Prefer-EDNS0 mode - no MAC available")
		}
	case "prefer-arp":
		if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
			LogDebug("[EDNS0] MAC: Prefer-ARP mode - using ARP MAC: %s", mac)
		} else if hasMAC && (macSource == "edns0" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = existingMAC
			LogDebug("[EDNS0] MAC: Prefer-ARP mode - no ARP MAC, using client's EDNS0 MAC")
		} else {
			LogDebug("[EDNS0] MAC: Prefer-ARP mode - no MAC available")
		}
	}
	if shouldAddMAC && macToAdd != nil {
		opts = append(opts, &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: macToAdd})
		LogDebug("[EDNS0] MAC: Added to upstream: %s", macToAdd)
	}
	o.Option = opts
	LogDebug("[EDNS0] Final upstream EDNS0 options count: %d", len(opts))
}

func determineMAC(arpMAC, edns0MAC net.HardwareAddr, source string) net.HardwareAddr {
	switch source {
	case "arp":
		return arpMAC
	case "edns0":
		return edns0MAC
	case "both":
		if arpMAC != nil {
			return arpMAC
		}
		return edns0MAC
	default:
		return arpMAC
	}
}

