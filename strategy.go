/*
File: strategy.go
Version: 1.0.0
Description: Implements upstream selection strategies (Round-Robin, Random, Failover, Fastest, Race)
             and the main forwarder logic.
             Extracted from process.go for modularity.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var raceLimiter = make(chan struct{}, 4096)

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

