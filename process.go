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

// --- Singleflight ---

type callResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
	err         error
}

type call struct {
	wg  sync.WaitGroup
	val callResult
}

type RequestGroup struct {
	mu sync.Mutex
	m  map[string]*call
}

func (g *RequestGroup) Do(key string, fn func() callResult) (callResult, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, true
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, false
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

	if !*cacheDisabled && cacheKey != "" {
		if cachedResp := getFromCache(cacheKey, r.Id); cachedResp != nil {
			cleanResponse(cachedResp)
			logRequest(r.Id, reqCtx, qInfo, "CACHE_HIT", "CACHE", 0, time.Since(start), cachedResp)
			w.WriteMsg(cachedResp)
			return
		}
	}

	callResult, shared := requestGroup.Do(cacheKey, func() callResult {
		resp, upstreamStr, rtt, err := forwardToUpstreamsWithContext(ctx, msg, reqCtx)
		return callResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt, err: err}
	})

	if callResult.err != nil {
		log.Printf("Error forwarding %s from %s: %v", qInfo, ip, callResult.err)
		dns.HandleFailed(w, r)
		return
	}

	resp := callResult.msg

	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		cleanResponse(resp)
	}

	if !*cacheDisabled && resp != nil {
		addToCache(cacheKey, resp)
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	logRequest(r.Id, reqCtx, qInfo, status, callResult.upstreamStr, callResult.rtt, time.Since(start), resp)

	resp.Id = r.Id
	w.WriteMsg(resp)
}

// --- Strategies ---

func forwardToUpstreamsWithContext(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	selectedUpstreams, selectedStrategy := SelectUpstreams(reqCtx)
	return forwardToUpstreams(ctx, req, selectedUpstreams, selectedStrategy)
}

func forwardToUpstreams(ctx context.Context, req *dns.Msg, upstreams []*Upstream, strategy string) (*dns.Msg, string, time.Duration, error) {
	if len(upstreams) == 1 {
		u := upstreams[0]
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err
	}

	strat := strings.ToLower(strategy)

	switch strat {
	case "round-robin":
		idx := rrCounter.Add(1)
		u := upstreams[int(idx)%len(upstreams)]
		log.Printf("[STRATEGY] Round-Robin: Selected #%d %s", int(idx)%len(upstreams), u.String())
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err

	case "random":
		idx := rand.IntN(len(upstreams))
		u := upstreams[idx]
		log.Printf("[STRATEGY] Random: Selected %s", u.String())
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err

	case "failover":
		log.Printf("[STRATEGY] Failover: Starting sequence...")
		for i, u := range upstreams {
			log.Printf("[STRATEGY] Failover: Attempting #%d %s...", i, u.String())
			resp, rtt, err := u.executeExchange(ctx, req)
			if err == nil {
				log.Printf("[STRATEGY] Failover: Success with %s (RTT: %v)", u.String(), rtt)
				return resp, u.String(), rtt, nil
			}
			log.Printf("[STRATEGY] Failover: Failed %s: %v", u.String(), err)
		}
		return nil, "", 0, errors.New("all upstreams failed")

	case "fastest":
		return fastestStrategy(ctx, req, upstreams)

	case "race":
		return raceStrategy(ctx, req, upstreams)

	default:
		for _, u := range upstreams {
			resp, rtt, err := u.executeExchange(ctx, req)
			if err == nil {
				return resp, u.String(), rtt, nil
			}
		}
		return nil, "", 0, errors.New("all upstreams failed")
	}
}

func fastestStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	if rand.Float64() < 0.1 {
		idx := rand.IntN(len(upstreams))
		u := upstreams[idx]
		log.Printf("[STRATEGY] Fastest: Probing background upstream %s", u.String())
		go func() {
			u.executeExchange(context.Background(), req.Copy())
		}()
	}

	type uStat struct {
		u   *Upstream
		rtt int64
	}
	stats := make([]uStat, len(upstreams))
	for i, u := range upstreams {
		stats[i] = uStat{u, u.getRTT()}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].rtt == 0 && stats[j].rtt == 0 {
			return i < j
		}
		if stats[i].rtt == 0 {
			return true
		}
		if stats[j].rtt == 0 {
			return false
		}
		return stats[i].rtt < stats[j].rtt
	})

	best := stats[0].u
	log.Printf("[STRATEGY] Fastest: Selected %s (Current RTT: %v)", best.String(), time.Duration(best.getRTT()))

	resp, rtt, err := best.executeExchange(ctx, req)
	return resp, best.String(), rtt, err
}

func raceStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	log.Printf("[STRATEGY] Race: Starting race among %d upstreams", len(upstreams))

	type result struct {
		msg *dns.Msg
		str string
		rtt time.Duration
		err error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan result, len(upstreams))

	for _, u := range upstreams {
		go func(upstream *Upstream) {
			resp, rtt, err := upstream.executeExchange(ctx, req)
			select {
			case resCh <- result{msg: resp, str: upstream.String(), rtt: rtt, err: err}:
			case <-ctx.Done():
			}
		}(u)
	}

	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				log.Printf("[STRATEGY] Race: Winner %s (RTT: %v)", res.str, res.rtt)
				return res.msg, res.str, res.rtt, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, "", 0, lastErr
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

