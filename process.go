/*
File: process.go
Version: 3.29.0 (Cache Key Correctness - Client Name)
Last Update: 2026-01-27
Description: Handles the core processing logic for DNS requests.
             UPDATED: Cache/Singleflight Key now includes client Identity ONLY if upstreams are dynamic.
             This ensures correctness for {client-*} tags while maintaining sharing for static upstreams.
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

const (
	StaleGracePeriod = 24 * time.Hour
	StaleTTL         = 5
)

// Singleflight group for coalescing identical requests.
var requestGroup = NewShardedGroup()

type queryResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
	upstreamQID uint16
}

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtxFromHandler *RequestContext) {
	defer func() {
		if rec := recover(); rec != nil {
			LogError("Panic in processDNSRequest: %v\nStack: %s", rec, debug.Stack())
			dns.HandleFailed(w, r)
		}
	}()

	start := time.Now()

	remoteAddr := w.RemoteAddr()
	clientIP := getIPFromAddr(remoteAddr)

	action, delay, reason := GlobalLimiter.Check(clientIP)

	if action == ActionDrop {
		LogWarn("[LIMIT] DROPPED request from %s | Reason: %s", clientIP, reason)
		return
	}

	if action == ActionDelay {
		if delay > 0 {
			LogInfo("[LIMIT] DELAYING request from %s by %v | Reason: %s", clientIP, delay, reason)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		}
	}

	originalID := r.Id

	reqCtx := reqCtxPool.Get().(*RequestContext)
	reqCtx.Reset()
	defer reqCtxPool.Put(reqCtx)

	reqCtx.ServerIP = reqCtxFromHandler.ServerIP
	reqCtx.ServerPort = reqCtxFromHandler.ServerPort
	reqCtx.Protocol = reqCtxFromHandler.Protocol
	reqCtx.ServerHostname = reqCtxFromHandler.ServerHostname
	reqCtx.ServerPath = reqCtxFromHandler.ServerPath

	var mac net.HardwareAddr
	if IsValidARPCandidate(clientIP) {
		mac = getMacFromCache(clientIP)
	}

	reqCtx.ClientIP = clientIP
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

	if IsDebugEnabled() {
		sb.Reset()
		qInfo = appendEDNSInfoToLog(&sb, reqCtx, qInfo, r)
		sb.Reset()
	}

	// --- STRICT PTR CHECK ---
	if qType == dns.TypePTR && config.Server.Response.PTRMode == "strict" {
		if ExtractIPFromPTR(reqCtx.QueryName) == nil {
			LogDebug("[PROCESS] Strict PTR: Discarding invalid PTR query '%s' from %s", reqCtx.QueryName, clientIP)
			
			resp := getMsg()
			resp.SetReply(r)
			resp.Id = originalID
			resp.Rcode = dns.RcodeNameError // NXDOMAIN informs client to stop asking
			
			w.WriteMsg(resp)
			logRequest(originalID, 0, reqCtx, "StrictPTR", qInfo, "", "NXDOMAIN (STRICT)", "INTERNAL", 0, time.Since(start), resp)
			putMsg(resp)
			return
		}
	}

	if config.Server.DDR.Enabled && qType == dns.TypeSVCB && reqCtx.QueryName == "_dns.resolver.arpa" {
		if resp := generateDDRResponse(r, reqCtx.ServerIP); resp != nil {
			resp.Id = originalID
			w.WriteMsg(resp)
			defer putMsg(resp)
			logRequest(originalID, 0, reqCtx, "DDR", qInfo, "", "NOERROR (DDR)", "INTERNAL", 0, time.Since(start), resp)
			return
		}
	}

	if config.Server.DDR.Enabled && config.Server.DDR.SpoofHostname && config.Server.DDR.HostName != "" {
		targetHost := strings.ToLower(strings.TrimSuffix(config.Server.DDR.HostName, "."))
		
		if reqCtx.QueryName == targetHost && (qType == dns.TypeA || qType == dns.TypeAAAA) {
			resp := getMsg()
			resp.SetReply(r)
			resp.Id = originalID
			resp.Authoritative = true
			resp.RecursionAvailable = true

			if reqCtx.ServerIP != nil {
				if qType == dns.TypeA {
					if ip4 := reqCtx.ServerIP.To4(); ip4 != nil {
						rr := new(dns.A)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(reqCtx.QueryName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
						rr.A = ip4
						resp.Answer = append(resp.Answer, rr)
					}
				} else if qType == dns.TypeAAAA {
					if ip4 := reqCtx.ServerIP.To4(); ip4 == nil {
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(reqCtx.QueryName), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
						rr.AAAA = reqCtx.ServerIP
						resp.Answer = append(resp.Answer, rr)
					}
				}
			}

			w.WriteMsg(resp)
			defer putMsg(resp)
			logRequest(originalID, 0, reqCtx, "DDR-SPOOF", qInfo, "", "NOERROR (SPOOF)", "INTERNAL", 0, time.Since(start), resp)
			return
		}
	}

	selectedUpstreams, selectedStrategy, ruleName, hostsCache, hostsWildcard, mlGuardMode := SelectUpstreams(reqCtx)

	if len(r.Question) > 0 {
		q := r.Question[0]
		routingKey := ruleName

		// CACHE KEY GENERATION
		sb.Reset()
		sb.WriteString(reqCtx.QueryName)
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qtype)))
		sb.WriteString("|")
		sb.WriteString(strconv.Itoa(int(q.Qclass)))
		sb.WriteString("|")
		sb.WriteString(routingKey)

		// CHECK: Are any upstreams dynamic?
		// If YES, we must append client identity to the key.
		// If we don't, Singleflight will coalesce multiple clients into one upstream request,
		// and the upstream will see the wrong client identity (Identity Leak / Cache Poisoning).
		isDynamic := false
		for _, u := range selectedUpstreams {
			if u != nil && u.IsDynamic {
				isDynamic = true
				break
			}
		}

		if isDynamic {
			sb.WriteString("|")
			sb.WriteString(reqCtx.ClientIP.String())
			if reqCtx.ClientMAC != nil {
				sb.WriteString("|")
				sb.WriteString(reqCtx.ClientMAC.String())
			}
			// Important: If dynamic tags include client-name, include resolved name in key
			// to differentiate clients sharing IPs but different resolved names (rare but possible)
			// or just to match upstream logic.
			// Resolving name here might be expensive if done repeatedly.
			// However, resolveClientName in upstream.go caches somewhat via hosts/system resolver.
			// To be safe and consistent with upstream.go logic:
			// (We rely on resolveClientName helper being efficient)
			name := resolveClientName(reqCtx.ClientIP)
			if name != "" {
				sb.WriteString("|")
				sb.WriteString(name)
			}
		}

		cacheKey = sb.String()
	}

	if config.Cache.Enabled && cacheKey != "" {
		if cachedResp, remainingTTL := getFromCacheWithTTL(cacheKey, originalID); cachedResp != nil {
			serveCache(w, cachedResp, remainingTTL, originalID, reqCtx, ruleName, qInfo, start)
			putMsg(cachedResp)

			if config.Cache.Prefetch.Predictive.Enabled {
				if IsDebugEnabled() {
					LogDebug("[PROCESS] Triggering Predictor on Cache Hit: %s", reqCtx.QueryName)
				}
				TrackAndPredict(reqCtx.ClientIP, reqCtx.QueryName, ruleName, selectedUpstreams, selectedStrategy, reqCtx)
			}
			return
		}
	}

	skipMLGuard := false

	if hostsCache != nil && len(r.Question) > 0 {
		var answers []dns.RR
		var matchFound bool
		var isExplicitAllow bool

		clientInfo := reqCtx.ClientIP.String()
		if reqCtx.ClientMAC != nil {
			clientInfo = fmt.Sprintf("%s (%s)", clientInfo, reqCtx.ClientMAC.String())
		}

		if qType == dns.TypePTR {
			answers, matchFound = hostsCache.LookupPTR(reqCtx.QueryName, clientInfo, ruleName)
			isExplicitAllow = false 
		} else {
			answers, matchFound, isExplicitAllow = hostsCache.Lookup(reqCtx.QueryName, qType, hostsWildcard, clientInfo, ruleName)
		}

		if matchFound {
			if isExplicitAllow {
				skipMLGuard = true
				LogDebug("[PROCESS] Explicit Allow for %s, skipping ML-Guard checks.", reqCtx.QueryName)
			} else {
				resp := getMsg()
				resp.SetReply(r)
				resp.Id = originalID

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
					logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", "NOERROR (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				} else {
					resp.Rcode = dns.RcodeNameError
					if config.Cache.Enabled && cacheKey != "" {
						addToCache(cacheKey, resp)
					}
					w.WriteMsg(resp)
					logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", "NXDOMAIN (HOSTS)", "HOSTS", 0, time.Since(start), resp)
				}
				putMsg(resp)
				return
			}
		}
	}

	if !skipMLGuard && config.MLGuard.Enabled && mlGuardMode != "disable" {
		typeStr := dns.TypeToString[qType]
		suspicious, prob, reason := GlobalMLGuard.Check(reqCtx.QueryName, typeStr, mlGuardMode, false)
		
		if suspicious && mlGuardMode == "block" {
			GlobalMLGuard.RecordScore(prob, true)
			
			LogInfo("[ML-GUARD] BLOCKED Query Domain: %s (Type: %s) (Prob: %.2f) | Reason: %s", reqCtx.QueryName, typeStr, prob, reason)

			resp := getMsg()
			resp.SetReply(r)
			resp.Id = originalID
			resp.Rcode = dns.RcodeNameError

			w.WriteMsg(resp)
			putMsg(resp)
			return
		} else {
			GlobalMLGuard.RecordScore(prob, false)
			
			if suspicious {
				LogInfo("[ML-GUARD] SUSPICIOUS Query Domain: %s (Type: %s) (Prob: %.2f) | Reason: %s", reqCtx.QueryName, typeStr, prob, reason)
			}
		}
	}

	if config.Cache.Enabled && config.Cache.HardenBelowNXDOMAIN && len(r.Question) > 0 {
		checkName := dns.Fqdn(reqCtx.QueryName)
		isNX, remainingTTL := CheckParentNXDomain(checkName, ruleName)

		if isNX {
			LogDebug("[PROCESS] HardenNX triggered for %s (Rule: %s)", checkName, ruleName)
			resp := getMsg()
			resp.SetReply(r)
			resp.Id = originalID
			resp.Rcode = dns.RcodeNameError
			w.WriteMsg(resp)
			status := fmt.Sprintf("NXDOMAIN (HARDENED, TTL:%ds)", remainingTTL)
			logRequest(originalID, 0, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
			putMsg(resp)
			return
		}
	}

	msg := r.Copy()
	randomID := dns.Id()
	msg.Id = randomID

	addEDNS0Options(msg, clientIP, mac)

	upstreamQInfo := ""
	if IsDebugEnabled() {
		upstreamQInfo = buildUpstreamInfo(msg)
		logEDNSDebug(msg, originalID)
	}

	safeReqCtx := reqCtx.Clone()

	if IsDebugEnabled() {
		LogDebug("[SF] Joining flight for query: %s (Key: %s)", qInfo, cacheKey)
	}

	// Use Sharded Group DoChan
	ch := requestGroup.DoChan(cacheKey, func() (interface{}, error) {
		if IsDebugEnabled() {
			LogDebug("[SF] Executing upstream lookup (Leader) for query: %s", qInfo)
		}

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
		return queryResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt, upstreamQID: randomID}, nil
	})

	var result singleflight.Result

	select {
	case <-ctx.Done():
		LogDebug("Query %s cancelled or timed out while waiting for singleflight", qInfo)
		return
	case res := <-ch:
		result = res
	}

	if IsDebugEnabled() {
		LogDebug("[SF] Flight completed for %s (Shared: %v, Err: %v)", qInfo, result.Shared, result.Err)
	}

	if result.Err != nil {
		if errors.Is(result.Err, context.DeadlineExceeded) || errors.Is(result.Err, context.Canceled) {
			LogWarn("Query timeout for %s from %s", qInfo, clientIP)
		} else {
			LogError("Error resolving %s from %s: %v", qInfo, clientIP, result.Err)
		}

		if config.Server.DropOnFailure {
			LogDebug("[PROCESS] Dropping query %s due to failure.", qInfo)
		} else {
			dns.HandleFailed(w, r)
		}
		return
	}

	qr := result.Val.(queryResult)
	resp := qr.msg
	shared := result.Shared
	actualUpstreamQID := qr.upstreamQID
	
	if shared && resp != nil {
		resp = resp.Copy()
	}

	if resp != nil {
		defer putMsg(resp)
		
		if hostsCache != nil {
			clientInfo := reqCtx.ClientIP.String()
			if reqCtx.ClientMAC != nil {
				clientInfo = fmt.Sprintf("%s (%s)", clientInfo, reqCtx.ClientMAC.String())
			}
			
			_, matchedAllow := hostsCache.FilterResponse(resp, reqCtx.QueryName, ruleName, clientInfo)
			
			if matchedAllow {
				skipMLGuard = true
				LogDebug("[PROCESS] Response contains explicit Allow domain, skipping ML-Guard checks.")
			}
		}

		if !skipMLGuard && config.MLGuard.Enabled && mlGuardMode != "disable" && resp.Rcode == dns.RcodeSuccess {
			blockedResponse := false

			checkTarget := func(target string, recType string) bool {
				target = strings.TrimSuffix(strings.ToLower(target), ".")
				if target == "" || target == reqCtx.QueryName {
					return false
				}

				suspicious, prob, reason := GlobalMLGuard.Check(target, recType, mlGuardMode, true)
				if suspicious && mlGuardMode == "block" {
					GlobalMLGuard.RecordScore(prob, true)
					LogInfo("[ML-GUARD] BLOCKED Response Target: %s (Record: %s, Query: %s) (Prob: %.2f) | Reason: %s", target, recType, reqCtx.QueryName, prob, reason)
					return true
				} else {
					GlobalMLGuard.RecordScore(prob, false)
					if suspicious {
						LogInfo("[ML-GUARD] SUSPICIOUS Response Target: %s (Record: %s, Query: %s) (Prob: %.2f) | Reason: %s", target, recType, reqCtx.QueryName, prob, reason)
					}
				}
				return false
			}

			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.CNAME:
					if checkTarget(v.Target, "CNAME") { blockedResponse = true }
				case *dns.MX:
					if checkTarget(v.Mx, "MX") { blockedResponse = true }
				case *dns.SRV:
					if checkTarget(v.Target, "SRV") { blockedResponse = true }
				case *dns.NS:
					if checkTarget(v.Ns, "NS") { blockedResponse = true }
				case *dns.PTR:
					if checkTarget(v.Ptr, "PTR") { blockedResponse = true }
				case *dns.DNAME:
					if checkTarget(v.Target, "DNAME") { blockedResponse = true }
				case *dns.SOA:
					if checkTarget(v.Ns, "SOA (NS)") { blockedResponse = true }
					if !blockedResponse && checkTarget(v.Mbox, "SOA (MBOX)") { blockedResponse = true }
				}

				if blockedResponse {
					break
				}
			}

			if blockedResponse {
				resp.Answer = nil
				resp.Ns = nil
				resp.Extra = nil
				resp.Rcode = dns.RcodeNameError
			}
		}

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

		if resp.Rcode == dns.RcodeSuccess && config.Cache.Prefetch.Predictive.Enabled {
			if IsDebugEnabled() {
				LogDebug("[PROCESS] Triggering Predictor on Upstream Success: %s", reqCtx.QueryName)
			}
			TrackAndPredict(reqCtx.ClientIP, reqCtx.QueryName, ruleName, selectedUpstreams, selectedStrategy, reqCtx)
		}
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	resp.Id = originalID
	w.WriteMsg(resp)

	logRequest(originalID, actualUpstreamQID, reqCtx, ruleName, qInfo, upstreamQInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)
}

func serveCache(w dns.ResponseWriter, resp *dns.Msg, ttl uint32, id uint16, reqCtx *RequestContext, ruleName, qInfo string, start time.Time) {
	resp.Id = id
	w.WriteMsg(resp)

	isNegative := resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0
	var status string
	if isNegative {
		status = fmt.Sprintf("CACHE_HIT (NEG, TTL:%ds)", ttl)
	} else {
		status = fmt.Sprintf("CACHE_HIT (TTL:%ds)", ttl)
	}
	logRequest(id, 0, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
}

func logRequest(clientQID, upstreamQID uint16, reqCtx *RequestContext, ruleName, qInfo, upstreamQInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
	clientIdentity := reqCtx.ClientIP.String()
	
	// OPTIMIZATION: Non-blocking client name resolution with context
	if config.Logging.LogClientName {
		resolvedName := resolveClientName(reqCtx.ClientIP)
		if resolvedName != "" {
			clientIdentity = fmt.Sprintf("%s (%s)", clientIdentity, resolvedName)
		}
	}

	if IsCompact() {
		upStr := upstream
		if upstream == "" || upstream == "CACHE" {
			upStr = "CACHE"
		} else {
			if idx := strings.Index(upStr, "://"); idx != -1 {
				upStr = upStr[idx+3:]
			}
			if idx := strings.Index(upStr, " ("); idx != -1 {
				upStr = upStr[:idx]
			}
		}
		LogInfo("[DNS] %s -> %s | %s | %v | %s", clientIdentity, qInfo, status, duration, upStr)
		return
	}

	macStr := "N/A"
	if reqCtx.ClientMAC != nil {
		macStr = reqCtx.ClientMAC.String()
	}

	if IsDebugEnabled() {
		var sb strings.Builder
		sb.WriteString(reqCtx.ServerIP.String())
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(reqCtx.ServerPort))
		if reqCtx.ServerHostname != "" {
			sb.WriteString(" | Host:")
			sb.WriteString(reqCtx.ServerHostname)
		}
		LogDebug("[QRY] QID:%d | Rule:%s | Client:%s | MAC:%s | Proto:%s | Ingress:%s | Query:%s",
			clientQID, ruleName, clientIdentity, macStr, reqCtx.Protocol, sb.String(), qInfo)

		if upstream != "" && upstream != "CACHE" {
			useInfo := qInfo
			if upstreamQInfo != "" {
				useInfo = upstreamQInfo
			}
			qidStr := fmt.Sprintf("%d", upstreamQID)
			if upstreamQID != clientQID {
				qidStr += "*"
			}
			LogDebug("[FWD] QID:%s | Rule:%s | Upstream:%s | RTT:%v | Query:%s | Response:%s", qidStr, ruleName, upstream, upstreamRTT, useInfo, status)
		}
	}

	var sb strings.Builder
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
	}
	ansStr := sb.String()
	if ansStr == "" {
		ansStr = "Empty"
	}

	LogInfo("[RSP] QID:%d | Rule:%s | Client:%s | MAC:%s | Proto:%s | Status:%s | Time:%v | Upstream:%s | Query:%s | Ans:[%s]", 
		clientQID, ruleName, clientIdentity, macStr, reqCtx.Protocol, status, duration, upstream, qInfo, ansStr)
}

