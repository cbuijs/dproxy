/*
File: process.go
Version: 3.8.2
Last Update: 2026-01-10
Description: Handles the core processing logic for DNS requests.
             FIXED: Removed double-logging of query info string.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Serve Stale Configuration
const (
	StaleGracePeriod = 24 * time.Hour // How long to serve stale data after expiry
	StaleTTL         = 5              // TTL to serve for stale records (seconds)
)

type queryResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
}

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtxFromHandler *RequestContext) {
	// --- PANIC RECOVERY ---
	// Protect the main server loop from crashing due to unexpected panics in request processing
	defer func() {
		if rec := recover(); rec != nil {
			LogError("Panic in processDNSRequest: %v\nStack: %s", rec, debug.Stack())
			dns.HandleFailed(w, r)
		}
	}()

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

	var mac net.HardwareAddr
	if IsValidARPCandidate(ip) {
		mac = getMacFromCache(ip)
	}

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
		qInfo = buildQueryInfo(q)
	}

	// Only build log string if necessary
	if IsInfoEnabled() {
		// FIX: buildQueryInfo already returns the basic info string.
		// appendEDNSInfoToLog takes the builder, writes qInfo + extras to it, and returns the full string.
		// Previously, we did sb.WriteString(qInfo) THEN called append..., which caused duplication.
		sb.Reset()
		qInfo = appendEDNSInfoToLog(&sb, reqCtx, qInfo, r)
		sb.Reset()
	}

	if config.Server.DDR.Enabled && qType == dns.TypeSVCB && reqCtx.QueryName == "_dns.resolver.arpa" {
		if resp := generateDDRResponse(r, reqCtx.ServerIP); resp != nil {
			w.WriteMsg(resp) // Write first
			if IsInfoEnabled() {
				logRequest(r.Id, reqCtx, "DDR", qInfo, "", "NOERROR (DDR)", "INTERNAL", 0, time.Since(start), resp)
			}
			return
		}
	}

	selectedUpstreams, selectedStrategy, ruleName, hostsCache, hostsWildcard := SelectUpstreams(reqCtx)

	if len(r.Question) > 0 {
		q := r.Question[0]
		routingKey := ruleName
		
		// OPTIMIZATION: Efficient cache key generation
		// Avoids Sprintf/Format calls, effectively does concatenation via builder
		sb.Reset()
		sb.WriteString(reqCtx.QueryName)
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qtype)))
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qclass)))
		sb.WriteString("|")
		sb.WriteString(routingKey)
		cacheKey = sb.String()
	}

	// --- CACHE CHECK (First) ---
	// "Single Source of Truth": Check cache before checking Hosts or Upstreams.
	if config.Cache.Enabled && cacheKey != "" {
		if cachedResp, remainingTTL := getFromCacheWithTTL(cacheKey, r.Id); cachedResp != nil {
			// Hit! Serve immediately.
			serveCache(w, cachedResp, remainingTTL, r.Id, reqCtx, ruleName, qInfo, start)
			return // Exit prevents any cross-fetching logic below
		}
	}

	// --- HOSTS FILE CHECK (Second) ---
	if hostsCache != nil && len(r.Question) > 0 {
		var answers []dns.RR
		var found bool

		// Build client info string for logging
		clientInfo := reqCtx.ClientIP.String()
		if reqCtx.ClientMAC != nil {
			clientInfo = fmt.Sprintf("%s (%s)", clientInfo, reqCtx.ClientMAC.String())
		}

		if qType == dns.TypePTR {
			answers, found = hostsCache.LookupPTR(reqCtx.QueryName, clientInfo, ruleName)
		} else {
			answers, found = hostsCache.Lookup(reqCtx.QueryName, qType, hostsWildcard, clientInfo, ruleName)
		}

		if found {
			resp := new(dns.Msg)
			resp.SetReply(r)

			if config.Server.Response.CNAMEFlattening {
				flattenCNAMEs(resp)
			}
			applyTTLClamping(resp)
			applyTTLStrategy(resp)
			sortResponse(resp)

			if len(answers) > 0 {
				resp.Answer = answers

				if config.Cache.Enabled && cacheKey != "" {
					addToCache(cacheKey, resp)
				}

				w.WriteMsg(resp)
				// HOSTS lookup now logs internally, so we just log the final request summary here
				if IsInfoEnabled() {
					logRequest(r.Id, reqCtx, ruleName, qInfo, "", "NOERROR (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				}
			} else {
				resp.Rcode = dns.RcodeNameError

				if config.Cache.Enabled && cacheKey != "" {
					addToCache(cacheKey, resp)
				}

				w.WriteMsg(resp)
				// HOSTS lookup now logs internally
				if IsInfoEnabled() {
					logRequest(r.Id, reqCtx, ruleName, qInfo, "", "NXDOMAIN (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				}
			}
			return
		}
	}

	// --- HARDEN BELOW NXDOMAIN CHECK (Third) ---
	// If the parent of this domain is already known to be NXDOMAIN, assume this one is too.
	// This saves upstream resources and improves performance for random-subdomain attacks.
	if config.Cache.Enabled && config.Cache.HardenBelowNXDOMAIN && len(r.Question) > 0 {
		// FIX: Use FQDN (with trailing dot) for cache key to match how responses are likely stored/keyed in addToCache
		checkName := dns.Fqdn(reqCtx.QueryName)
		
		isNX, remainingTTL := CheckParentNXDomain(checkName, ruleName)
		
		if IsDebugEnabled() {
			// Helper to avoid map panic (just in case, though TypeToString is usually safe)
			typeName := "UNKNOWN"
			if t, ok := dns.TypeToString[qType]; ok {
				typeName = t
			} else {
				typeName = strconv.Itoa(int(qType))
			}
			LogDebug("[PROCESS] HardenNX Check: %s (%s) (Rule: %s) -> Hit: %v", checkName, typeName, ruleName, isNX)
		}

		if isNX {
			LogDebug("[PROCESS] HardenNX triggered for %s (Rule: %s)", checkName, ruleName)

			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Rcode = dns.RcodeNameError
			
			// We synthesize a basic NXDOMAIN response.
			// Ideally we would include the SOA, but for a proxy block, this is sufficient.
			// Clients will cache this result based on a default negative TTL or MinNegTTL.
			
			w.WriteMsg(resp)
			if IsInfoEnabled() {
				status := fmt.Sprintf("NXDOMAIN (HARDENED, TTL:%ds)", remainingTTL)
				logRequest(r.Id, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
			}
			return
		}
	}

	// --- UPSTREAM FORWARDING ---
	// This block executes ONLY on a CACHE MISS (or expiration).

	msg := r.Copy()
	addEDNS0Options(msg, ip, mac)

	// Only build upstream info if we log debug or if we log info
	upstreamQInfo := ""
	if IsDebugEnabled() || IsInfoEnabled() {
		upstreamQInfo = buildUpstreamInfo(msg)
	}

	if IsDebugEnabled() {
		logEDNSDebug(msg, r.Id)
	}

	// --- Singleflight Optimization with Pipelining Potential ---

	// Create a safe clone for the async singleflight operation
	safeReqCtx := reqCtx.Clone()

	// Use cacheKey as the suppression key
	ch := requestGroup.DoChan(cacheKey, func() (interface{}, error) {
		// STANDARD UPSTREAM FORWARDING
		upstreamTimeout := getTimeout()
		if upstreamTimeout == 0 {
			upstreamTimeout = 5 * time.Second
		}
		uCtx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		defer cancel()

		resp, upstreamStr, rtt, err := forwardToUpstreams(uCtx, msg, selectedUpstreams, selectedStrategy, ruleName, safeReqCtx)
		if err != nil {
			return nil, err
		}
		return queryResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt}, nil
	})

	var result singleflight.Result

	select {
	case <-ctx.Done():
		LogDebug("Query %s cancelled or timed out while waiting for singleflight", qInfo)
		return
	case res := <-ch:
		result = res
	}

	if result.Err != nil {
		if errors.Is(result.Err, context.DeadlineExceeded) || errors.Is(result.Err, context.Canceled) {
			LogWarn("Query timeout for %s from %s", qInfo, ip)
		} else {
			LogError("Error resolving %s from %s: %v", qInfo, ip, result.Err)
		}

		if config.Server.DropOnFailure {
			LogDebug("[PROCESS] Dropping query %s due to failure (drop_on_failure=true).", qInfo)
		} else {
			dns.HandleFailed(w, r)
		}
		return
	}

	qr := result.Val.(queryResult)
	resp := qr.msg
	shared := result.Shared

	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		// Post-processing
		cleanResponse(resp)

		if config.Server.Response.CNAMEFlattening {
			flattenCNAMEs(resp)
		}

		applyTTLClamping(resp)
		applyTTLStrategy(resp)
		sortResponse(resp)
	}

	if config.Cache.Enabled && resp != nil {
		addToCache(cacheKey, resp)

		// Prefetch Pipelining (Only for A/AAAA queries and Forwarding modes, not recursion usually needed)
		if config.Cache.Prefetch.CrossFetch.Enabled && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			mode := config.Cache.Prefetch.CrossFetch.Mode
			shouldPrefetch := false

			switch mode {
			case "on_a":
				shouldPrefetch = (qType == dns.TypeA)
			case "on_aaaa":
				shouldPrefetch = (qType == dns.TypeAAAA)
			case "both":
				shouldPrefetch = (qType == dns.TypeA || qType == dns.TypeAAAA)
			}

			if shouldPrefetch {
				req := prefetchReq{
					qName:      reqCtx.QueryName,
					qType:      qType,
					routingKey: ruleName,
					upstreams:  selectedUpstreams,
					strategy:   selectedStrategy,
					clientIP:   reqCtx.ClientIP,
					clientMAC:  reqCtx.ClientMAC,
				}
				AttemptCrossFetch(req)
			}
		}
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	resp.Id = r.Id

	w.WriteMsg(resp)

	if IsInfoEnabled() {
		logRequest(r.Id, reqCtx, ruleName, qInfo, upstreamQInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)
	}
}

// Helper to serve cache hits to avoid duplication
func serveCache(w dns.ResponseWriter, resp *dns.Msg, ttl uint32, id uint16, reqCtx *RequestContext, ruleName, qInfo string, start time.Time) {
	resp.Id = id
	w.WriteMsg(resp)

	// Optimization: Skip string building for log if not needed
	if IsInfoEnabled() {
		isNegative := resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0
		var status string
		if isNegative {
			status = fmt.Sprintf("CACHE_HIT (NEG, TTL:%ds)", ttl)
		} else {
			status = fmt.Sprintf("CACHE_HIT (TTL:%ds)", ttl)
		}
		logRequest(id, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
	}
}

func logRequest(qid uint16, reqCtx *RequestContext, ruleName, qInfo, upstreamQInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
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

	LogInfo("[QRY] QID:%d | Rule:%s | Client:%s | MAC:%s | Proto:%s | Ingress:%s | Query:%s",
		qid, ruleName, reqCtx.ClientIP, macStr, reqCtx.Protocol, ingress, qInfo)

	if upstream != "" && upstream != "CACHE" {
		useInfo := qInfo
		if upstreamQInfo != "" {
			useInfo = upstreamQInfo
		}
		LogInfo("[FWD] QID:%d | Rule:%s | Upstream:%s | RTT:%v | Query:%s | Response:%s", qid, ruleName, upstream, upstreamRTT, useInfo, status)
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

	LogInfo("[RSP] QID:%d | Status:%s | TotalTime:%v | Query:%s | Answers:[%s]", qid, status, duration, qInfo, ansStr)
}

