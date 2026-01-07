/*
File: strategy.go
Version: 1.5.0
Last Update: 2026-01-07
Description: Implements upstream selection strategies (Round-Robin, Random, Failover, Fastest, Race)
             and the main forwarder logic.
             UPDATED: Added IP address logging when switching upstreams (Fastest Strategy) and on failures.
             UPDATED: Strategies now check upstream.Allow() (QPS limit) and skip busy upstreams.
             UPDATED: Strategies now capture and format the specific Upstream IP address used for logging.
             UPDATED: Added comparative logging to Fastest strategy to explain selection "why".
             UPDATED: All strategies now accept 'ruleName' for better context in logs.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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

	if len(upstreams) == 1 {
		u := upstreams[0]
		// Still check QPS for single upstream
		if !u.Allow() {
			return nil, "", 0, fmt.Errorf("upstream %s is rate limited (QPS exceeded)", u.String())
		}
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		return resp, fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr), rtt, err
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

		// Check QPS Limit
		if !u.Allow() {
			LogDebug("[STRATEGY] Round-Robin (%s): Skipping busy upstream %s", ruleName, u.String())
			continue
		}

		LogDebug("[STRATEGY] Round-Robin (%s): Selected #%d/%d: %s", ruleName, idx+1, n, u.String())
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			LogDebug("[STRATEGY] Round-Robin (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			return resp, logStr, rtt, nil
		}

		LogWarn("[STRATEGY] Round-Robin (%s): Failed with %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
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
			LogDebug("[STRATEGY] Random (%s): Skipping busy upstream %s", ruleName, u.String())
			continue
		}

		LogDebug("[STRATEGY] Random (%s): Trying #%d/%d: %s", ruleName, idx+1, n, u.String())
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			LogDebug("[STRATEGY] Random (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			return resp, logStr, rtt, nil
		}
		LogWarn("[STRATEGY] Random (%s): Failed with %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
	}

	return nil, "", 0, fmt.Errorf("all upstreams failed, busy, or unhealthy in random")
}

func failoverStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream, ruleName string, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	for i, u := range upstreams {
		if !u.IsHealthy() {
			continue
		}

		if !u.Allow() {
			LogDebug("[STRATEGY] Failover (%s): Skipping busy upstream %s", ruleName, u.String())
			continue
		}

		LogDebug("[STRATEGY] Failover (%s): Attempting #%d/%d: %s", ruleName, i+1, len(upstreams), u.String())
		resp, addr, rtt, err := u.executeExchange(ctx, req, reqCtx)
		if err == nil {
			logStr := fmt.Sprintf("%s (%s)", u.DynamicString(reqCtx), addr)
			LogDebug("[STRATEGY] Failover (%s): Success with %s (RTT: %v)", ruleName, logStr, rtt)
			return resp, logStr, rtt, nil
		}
		LogWarn("[STRATEGY] Failover (%s): Failed %s (%s): %v", ruleName, u.DynamicString(reqCtx), addr, err)
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
		
		// Note: We check Allow() here to filter candidates, but we will check it again
		// before execution in case of race/time-passed, though redundant it's safer for heavy load.
		// For statistics gathering, it's better to exclude busy ones entirely from consideration.
		if !u.Allow() {
			// Do not log here to avoid spamming for every request if an upstream is saturated
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

	// Sort by RTT (lowest first)
	sort.Slice(stats, func(i, j int) bool {
		rttI, rttJ := stats[i].rtt, stats[j].rtt
		staleI, staleJ := stats[i].isStale, stats[j].isStale
		if staleI != staleJ {
			return !staleI // Prefer non-stale
		}
		if rttI == 0 && rttJ == 0 {
			return stats[i].index < stats[j].index
		}
		if rttI == 0 {
			return false // Prefer proven RTT
		}
		if rttJ == 0 {
			return true
		}
		return rttI < rttJ
	})

	// --- Primary Selection Logic & Logging ---
	best := stats[0].upstream
	bestRTT := stats[0].rtt

	// Check if the primary upstream has changed
	prevURL, ok := lastFastestWinner.Load(ruleName)
	if !ok || prevURL.(string) != best.String() {
		// Calculate the "Why"
		reason := "Initial selection"
		if ok {
			// Find previous winner stats to compare
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
				// If previous winner isn't in stats, it was filtered out (unhealthy or busy)
				reason = "Previous upstream became unhealthy, busy, or removed"
			}
			
			// Log the switch at INFO level so it's visible
			// Include resolved IPs to track where we are switching to
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
		// Still the same winner, just debug log the current comparison
		if len(stats) > 1 {
			LogDebug("[STRATEGY] Fastest (%s) Top 2: 1. %s (%v) | 2. %s (%v)",
				ruleName,
				stats[0].upstream.String(), time.Duration(stats[0].rtt),
				stats[1].upstream.String(), time.Duration(stats[1].rtt))
		}
	}

	// --- Exploration Logic ---
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
	// "Competitive" exploration (if 2nd best is close to best)
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

	// Trigger background probes for really stale upstreams
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
		// Exploration is a deviation from the "Best", so we log it at INFO to explain the choice
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
			LogDebug("[STRATEGY] Fastest (%s): Failover candidate %s (%s) failed: %v", ruleName, u.DynamicString(reqCtx), addr, err)
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

	LogDebug("[STRATEGY] Race (%s): Starting race among %d upstreams", ruleName, len(candidates))

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
			logStr := upstream.DynamicString(reqCtx)
			if err == nil {
				logStr = fmt.Sprintf("%s (%s)", logStr, addr)
			}
			
			if err != nil {
				LogWarn("[STRATEGY] Race (%s): Upstream %s (%s) failed: %v", ruleName, upstream.DynamicString(reqCtx), addr, err)
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
					LogDebug("[STRATEGY] Race (%s): Winner is %s (RTT: %v)", ruleName, res.name, res.rtt)
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

