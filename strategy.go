/*
File: strategy.go
Version: 1.11.1 (Panic & Race Fix)
Last Update: 2026-01-26
Description: Implements upstream selection strategies.
             FIXED: Removed slice mutation (upstreams[:0]) that caused a race condition and nil pointers.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	raceLimiter       = make(chan struct{}, 4096)
	lastFastestWinner sync.Map // map[string]string (RuleName -> Upstream URL)
)

func forwardToUpstreams(ctx context.Context, req *dns.Msg, upstreams []*Upstream, strategy string, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	if len(upstreams) == 0 {
		return nil, "", 0, errors.New("no upstreams available")
	}

	// Safety check: Filter out any nil upstreams to prevent panics.
	// IMPORTANT: Do NOT mutate 'upstreams' in place (upstreams[:0]) as it backs to global config.
	// We allocate a new slice pointer to be safe.
	validUpstreams := make([]*Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		if u != nil {
			validUpstreams = append(validUpstreams, u)
		}
	}
	upstreams = validUpstreams

	if len(upstreams) == 0 {
		return nil, "", 0, errors.New("no valid (non-nil) upstreams available")
	}

	// 1. Single Upstream / Hardcoded Actions
	if len(upstreams) == 1 {
		u := upstreams[0]
		
		// Handle Special Actions immediately
		if u.Action == UpstreamActionBlock {
			resp := getMsg() // Should be putMsg'd by caller (process.go)
			resp.SetReply(req)
			
			// Default to NXDOMAIN
			resp.Rcode = dns.RcodeNameError
			
			// Special handling for A/AAAA to return 0.0.0.0 or ::
			if len(req.Question) > 0 {
				q := req.Question[0]
				if q.Qtype == dns.TypeA {
					resp.Rcode = dns.RcodeSuccess
					rr := new(dns.A)
					rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
					rr.A = net.IPv4(0, 0, 0, 0)
					resp.Answer = append(resp.Answer, rr)
				} else if q.Qtype == dns.TypeAAAA {
					resp.Rcode = dns.RcodeSuccess
					rr := new(dns.AAAA)
					rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
					rr.AAAA = net.ParseIP("::")
					resp.Answer = append(resp.Answer, rr)
				}
			}

			return resp, "BLOCK", 0, nil
		}
		if u.Action == UpstreamActionDrop {
			// Return nil response (DROP)
			return nil, "DROP", 0, nil
		}

		// Still check QPS for single standard upstream
		if !u.Allow() {
			return nil, "", 0, fmt.Errorf("upstream %s is rate limited (QPS exceeded)", u.String())
		}
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		
		// Determine name for logging/return
		name := u.String() // Default fallback
		if reqCtx != nil {
			name = u.DynamicString(reqCtx) // Dynamic if context available
		}
		
		return resp, fmt.Sprintf("%s (%s)", name, addr), rtt, err
	}

	strat := strings.ToLower(strategy)

	switch strat {
	case "round-robin":
		return roundRobinStrategy(ctx, req, upstreams, ruleName, reqCtx)
	case "random":
		return randomStrategy(ctx, req, upstreams, ruleName, reqCtx)
	case "failover":
		return failoverStrategy(ctx, req, upstreams, ruleName, reqCtx)
	case "fastest":
		return fastestStrategy(ctx, req, upstreams, ruleName, reqCtx)
	case "race":
		return raceStrategy(ctx, req, upstreams, ruleName, reqCtx)
	default:
		LogWarn("[STRATEGY] Unknown strategy '%s', using failover", strategy)
		return failoverStrategy(ctx, req, upstreams, ruleName, reqCtx)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Check for net.Error timeout
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return true
	}
	return false
}

func roundRobinStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	startIdx := rrCounter.Add(1) - 1
	n := len(upstreams)

	// Try all upstreams starting from the RR index
	for i := 0; i < n; i++ {
		idx := (int(startIdx) + i) % n
		u := upstreams[idx]

		if !u.IsHealthy() {
			continue
		}

		if !u.Allow() {
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Round-Robin (%s): Skipping busy upstream %s", ruleName, u.String())
			}
			continue
		}

		if IsDebugEnabled() {
			LogDebug("[STRATEGY] Round-Robin (%s): Selected #%d/%d: %s", ruleName, idx+1, n, u.String())
		}
		
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Round-Robin (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			}
			return resp, logStr, rtt, nil
		}

		if isTimeout(err) {
			LogWarn("[STRATEGY] Round-Robin (%s): Timeout on %s (%s), retrying next...", ruleName, u.DynamicString(reqCtx), addr)
		} else {
			LogWarn("[STRATEGY] Round-Robin (%s): Failed with %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
		}
	}

	return nil, "", 0, fmt.Errorf("all upstreams failed, busy, or unhealthy in round-robin")
}

func randomStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	n := len(upstreams)
	startIdx := rand.IntN(n)

	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		u := upstreams[idx]

		if !u.IsHealthy() {
			continue
		}

		if !u.Allow() {
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Random (%s): Skipping busy upstream %s", ruleName, u.String())
			}
			continue
		}

		if IsDebugEnabled() {
			LogDebug("[STRATEGY] Random (%s): Trying #%d/%d: %s", ruleName, idx+1, n, u.String())
		}

		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Random (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			}
			return resp, logStr, rtt, nil
		}
		
		if isTimeout(err) {
			LogWarn("[STRATEGY] Random (%s): Timeout on %s (%s), retrying next...", ruleName, u.DynamicString(reqCtx), addr)
		} else {
			LogWarn("[STRATEGY] Random (%s): Failed with %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
		}
	}

	return nil, "", 0, fmt.Errorf("all upstreams failed, busy, or unhealthy in random")
}

func failoverStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	for i, u := range upstreams {
		if !u.IsHealthy() {
			continue
		}

		if !u.Allow() {
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Failover (%s): Skipping busy upstream %s", ruleName, u.String())
			}
			continue
		}

		if IsDebugEnabled() {
			LogDebug("[STRATEGY] Failover (%s): Attempting #%d/%d: %s", ruleName, i+1, len(upstreams), u.String())
		}

		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Failover (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			}
			return resp, logStr, rtt, nil
		}
		
		if isTimeout(err) {
			LogWarn("[STRATEGY] Failover (%s): Timeout on %s (%s), failover to next...", ruleName, u.DynamicString(reqCtx), addr)
		} else {
			LogWarn("[STRATEGY] Failover (%s): Failed %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
		}
	}
	return nil, "", 0, errors.New("all upstreams failed, busy, or unhealthy in failover")
}

func fastestStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
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
		
		if !u.Allow() {
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
		return nil, "", 0, errors.New("all upstreams are unhealthy or busy")
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

	prevURL, ok := lastFastestWinner.Load(ruleName)
	if !ok || prevURL.(string) != best.String() {
		reason := "Initial selection"
		if ok {
			var prevStat *upstreamStat
			for i := range stats {
				if stats[i].upstream.String() == prevURL.(string) {
					prevStat = &stats[i]
					break
				}
			}

			if prevStat != nil {
				reason = fmt.Sprintf("RTT Improved (%v < %v)", time.Duration(bestRTT), time.Duration(prevStat.rtt))
				if bestRTT == 0 {
					reason = "Previous was stale/failed, falling back to index order"
				}
			} else {
				reason = "Previous upstream became unhealthy, busy, or removed"
			}
			
			// Log switch at INFO level (guarded inside LogInfo internally, but u.String() is cheap enough for INFO event)
			var ipLog string
			ips := best.resolveIPs()
			if len(ips) > 0 {
				var ipStrs []string
				for _, ip := range ips {
					ipStrs = append(ipStrs, ip.String())
				}
				ipLog = fmt.Sprintf(" [%s]", strings.Join(ipStrs, ", "))
			}
			LogInfo("[STRATEGY] Fastest (%s): Switched Primary -> %s%s. Reason: %s", ruleName, best.String(), ipLog, reason)
		}
		lastFastestWinner.Store(ruleName, best.String())
	} else {
		if IsDebugEnabled() && len(stats) > 1 {
			LogDebug("[STRATEGY] Fastest (%s) Top 2: 1. %s (%v) | 2. %s (%v)",
				ruleName,
				stats[0].upstream.String(), time.Duration(stats[0].rtt),
				stats[1].upstream.String(), time.Duration(stats[1].rtt))
		}
	}

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
			explorationReason = "Random Exploration"
		}
	}
	if !shouldExplore {
		for _, s := range stats {
			if s.rtt == 0 && now.Sub(s.lastProbed) > minProbeInterval {
				explorationTarget = s.upstream
				shouldExplore = true
				explorationReason = "No RTT Data"
				break
			}
		}
	}
	if !shouldExplore && stats[0].isStale {
		explorationTarget = best
		shouldExplore = true
		explorationReason = "Primary Data Stale"
	}
	if !shouldExplore && bestRTT > 0 && len(stats) > 1 {
		for _, s := range stats[1:] {
			if s.rtt > 0 && now.Sub(s.lastProbed) > minProbeInterval {
				if float64(s.rtt) <= float64(bestRTT)/rttDifferenceRatio {
					explorationTarget = s.upstream
					shouldExplore = true
					explorationReason = fmt.Sprintf("Competitive RTT (%v ~ %v)", time.Duration(s.rtt), time.Duration(bestRTT))
					break
				}
			}
		}
	}

	for _, s := range stats {
		if now.Sub(s.lastProbed) > 3*staleThreshold {
			if s.upstream.TryLockProbe() {
				go func(u *Upstream) {
					defer u.UnlockProbe()
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
	}

	var selectedUpstream *Upstream
	if shouldExplore && explorationTarget != nil {
		selectedUpstream = explorationTarget
		LogInfo("[STRATEGY] Fastest (%s): Exploring %s. Reason: %s", ruleName, selectedUpstream.String(), explorationReason)
	} else {
		selectedUpstream = best
	}

	resp, addr, rtt, err := selectedUpstream.executeExchange(ctx, req, reqCtx)
	if err != nil {
		LogWarn("[STRATEGY] Fastest (%s): Failed with %s (%s): %v, trying alternatives", ruleName, selectedUpstream.DynamicString(reqCtx), addr, err)
		for _, s := range stats {
			if s.upstream == selectedUpstream {
				continue
			}
			u := s.upstream
			resp, addr, rtt, err = u.executeExchange(ctx, req, reqCtx)
			if err == nil {
				logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
				LogInfo("[STRATEGY] Fastest (%s): Failover success with %s (RTT: %v)", ruleName, logStr, rtt)
				return resp, logStr, rtt, nil
			}
			if IsDebugEnabled() {
				LogDebug("[STRATEGY] Fastest (%s): Failover candidate %s (%s) failed: %v", ruleName, u.DynamicString(reqCtx), addr, err)
			}
		}
		return nil, "", 0, fmt.Errorf("all upstreams failed in fastest strategy")
	}

	logStr := fmt.Sprintf("%s (%s)", selectedUpstream.DynamicString(reqCtx), addr)
	return resp, logStr, rtt, nil
}

func raceStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	candidates := make([]*Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		if u.IsHealthy() && u.Allow() {
			candidates = append(candidates, u)
		}
	}

	if len(candidates) == 0 {
		return nil, "", 0, errors.New("all upstreams are unhealthy or busy")
	}

	if IsDebugEnabled() {
		LogDebug("[STRATEGY] Race (%s): Starting race among %d upstreams", ruleName, len(candidates))
	}

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

			resp, addr, rtt, err := upstream.executeExchange(ctx, req, reqCtx)
			var logStr string
			if err == nil {
				// Only build string on success or if needed
				logStr = fmt.Sprintf("%s (%s)", upstream.DynamicString(reqCtx), addr)
			} else {
				// On failure, construct partial string for debug logs
				logStr = upstream.String()
			}
			
			if err != nil {
				if !errors.Is(err, context.Canceled) && IsDebugEnabled() {
					LogDebug("[STRATEGY] Race (%s): Upstream %s (%s) failed: %v", ruleName, logStr, addr, err)
				}
			}
			select {
			case resCh <- result{msg: resp, name: logStr, rtt: rtt, err: err}:
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
					if IsDebugEnabled() {
						LogDebug("[STRATEGY] Race (%s): Winner is %s (RTT: %v)", ruleName, res.name, res.rtt)
					}
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

