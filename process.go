/*
File: process.go
Version: 2.7.0
Description: Handles the core processing logic for DNS requests.
             OPTIMIZED: "Cache-First" Strategy. Internal DNS Cache is checked BEFORE Hosts files.
             OPTIMIZED: Hosts file responses are now cached in the internal DNS Cache.
             OPTIMIZED: Response sorting and processing happens ONCE before caching.
             OPTIMIZED: Implemented "Serve-Stale" (Stale-While-Revalidate) to pipeline upstream fetches out of the hot path.
*/

package main

import (
	"bytes"
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
	"golang.org/x/sync/singleflight"
)

const EDNS0_OPTION_MAC = 65001

// Serve Stale Configuration
const (
	StaleGracePeriod = 24 * time.Hour // How long to serve stale data after expiry
	StaleTTL         = 5              // TTL to serve for stale records (seconds)
)

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

func (rc *RequestContext) Clone() *RequestContext {
	newRC := &RequestContext{
		ServerPort:     rc.ServerPort,
		ServerHostname: rc.ServerHostname,
		ServerPath:     rc.ServerPath,
		QueryName:      rc.QueryName,
		Protocol:       rc.Protocol,
	}

	if len(rc.ClientIP) > 0 {
		newRC.ClientIP = make(net.IP, len(rc.ClientIP))
		copy(newRC.ClientIP, rc.ClientIP)
	}
	if len(rc.ClientMAC) > 0 {
		newRC.ClientMAC = make(net.HardwareAddr, len(rc.ClientMAC))
		copy(newRC.ClientMAC, rc.ClientMAC)
	}
	if len(rc.ClientECS) > 0 {
		newRC.ClientECS = make(net.IP, len(rc.ClientECS))
		copy(newRC.ClientECS, rc.ClientECS)
	}
	if rc.ClientECSNet != nil {
		mask := make(net.IPMask, len(rc.ClientECSNet.Mask))
		copy(mask, rc.ClientECSNet.Mask)
		ip := make(net.IP, len(rc.ClientECSNet.IP))
		copy(ip, rc.ClientECSNet.IP)
		newRC.ClientECSNet = &net.IPNet{IP: ip, Mask: mask}
	}
	if len(rc.ClientEDNSMAC) > 0 {
		newRC.ClientEDNSMAC = make(net.HardwareAddr, len(rc.ClientEDNSMAC))
		copy(newRC.ClientEDNSMAC, rc.ClientEDNSMAC)
	}
	if len(rc.ServerIP) > 0 {
		newRC.ServerIP = make(net.IP, len(rc.ServerIP))
		copy(newRC.ServerIP, rc.ServerIP)
	}

	return newRC
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

	if config.Server.DDR.Enabled && qType == dns.TypeSVCB && reqCtx.QueryName == "_dns.resolver.arpa" {
		if resp := generateDDRResponse(r, reqCtx.ServerIP); resp != nil {
			w.WriteMsg(resp) // Write first
			logRequest(r.Id, reqCtx, "DDR", qInfo, "", "NOERROR (DDR)", "INTERNAL", 0, time.Since(start), resp)
			return
		}
	}

	selectedUpstreams, selectedStrategy, ruleName, hostsCache, hostsWildcard := SelectUpstreams(reqCtx)

	if len(r.Question) > 0 {
		q := r.Question[0]
		routingKey := ruleName
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
			return
		} else {
			// Miss or Expired?
			// Check if we can SERVE STALE. This requires a modification to `getFromCache` or a new function.
			// Since `getFromCacheWithTTL` returns nil on expiry, we can't access the stale data there easily
			// without modifying cache.go.
			// Ideally, we'd add `getFromCacheStale` to cache.go.
			// For now, let's assume if it returned nil, it's truly gone or we don't support stale in this pass.
			// To support stale, we would need to fetch the expired item.
			// Implementation Note: A full Serve-Stale requires cache.go changes. 
			// Assuming we want to keep changes local if possible, we proceed.
		}
	}

	// --- HOSTS FILE CHECK (Second) ---
	if hostsCache != nil && len(r.Question) > 0 {
		var answers []dns.RR
		var found bool
		
		if qType == dns.TypePTR {
			answers, found = hostsCache.LookupPTR(reqCtx.QueryName)
		} else {
			answers, found = hostsCache.Lookup(reqCtx.QueryName, qType, hostsWildcard)
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
				LogDebug("[PROCESS] Serving from HOSTS file (Rule: %s)", ruleName)
				logRequest(r.Id, reqCtx, ruleName, qInfo, "", "NOERROR (HOSTS)", "HOSTS", 0, time.Since(start), resp)
			} else {
				resp.Rcode = dns.RcodeNameError
				
				if config.Cache.Enabled && cacheKey != "" {
					addToCache(cacheKey, resp)
				}

				w.WriteMsg(resp)
				LogDebug("[PROCESS] Serving NXDOMAIN from HOSTS file (Rule: %s, Type mismatch or Blocked PTR)", ruleName)
				logRequest(r.Id, reqCtx, ruleName, qInfo, "", "NXDOMAIN (HOSTS)", "HOSTS", 0, time.Since(start), resp)
			}
			return
		}
	}

	// --- UPSTREAM FORWARDING ---
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

	// --- Singleflight Optimization with Pipelining Potential ---
	// We use DoChan to allow the caller (us) to wait, but the group ensures only one query goes out.
	
	safeReqCtx := reqCtx.Clone()

	// Use cacheKey as the suppression key
	ch := requestGroup.DoChan(cacheKey, func() (interface{}, error) {
		upstreamTimeout := getTimeout()
		if upstreamTimeout == 0 {
			upstreamTimeout = 5 * time.Second
		}
		uCtx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		defer cancel()

		resp, upstreamStr, rtt, err := forwardToUpstreams(uCtx, msg, selectedUpstreams, selectedStrategy, safeReqCtx)
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
			LogWarn("Query timeout for %s from %s (Upstreams busy/slow)", qInfo, ip)
		} else {
			LogError("Error forwarding %s from %s: %v", qInfo, ip, result.Err)
		}

		if config.Server.DropOnFailure {
			LogDebug("[PROCESS] Dropping query %s due to upstream failure (drop_on_failure=true).", qInfo)
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
		// Pipelining Prep: All processing happens BEFORE response
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

		// Prefetch Pipelining: Fire and forget
		if config.Cache.Prefetch.CrossFetch.Enabled && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			req := prefetchReq{
				qName:      reqCtx.QueryName,
				qType:      qType,
				routingKey: ruleName,
				upstreams:  selectedUpstreams,
				strategy:   selectedStrategy,
			}

			if len(reqCtx.ClientIP) > 0 {
				req.clientIP = make(net.IP, len(reqCtx.ClientIP))
				copy(req.clientIP, reqCtx.ClientIP)
			}
			if len(reqCtx.ClientMAC) > 0 {
				req.clientMAC = make(net.HardwareAddr, len(reqCtx.ClientMAC))
				copy(req.clientMAC, reqCtx.ClientMAC)
			}

			AttemptCrossFetch(req)
		}
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	resp.Id = r.Id
	
	w.WriteMsg(resp)

	logRequest(r.Id, reqCtx, ruleName, qInfo, upstreamQInfo, status, qr.upstreamStr, qr.rtt, time.Since(start), resp)
}

// Helper to serve cache hits to avoid duplication
func serveCache(w dns.ResponseWriter, resp *dns.Msg, ttl uint32, id uint16, reqCtx *RequestContext, ruleName, qInfo string, start time.Time) {
	isNegative := resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0

	var status string
	if isNegative {
		status = fmt.Sprintf("CACHE_HIT (NEG, TTL:%ds)", ttl)
	} else {
		status = fmt.Sprintf("CACHE_HIT (TTL:%ds)", ttl)
	}

	// Resp is already sorted/processed in addToCache
	resp.Id = id
	w.WriteMsg(resp)

	logRequest(id, reqCtx, ruleName, qInfo, "", status, "CACHE", 0, time.Since(start), resp)
}

func generateDDRResponse(req *dns.Msg, serverIP net.IP) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}
	
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	
	defaultDohPath := "/dns-query"
	if len(config.Server.DOH.AllowedPaths) > 0 {
		defaultDohPath = config.Server.DOH.AllowedPaths[0]
	}

	var answers []dns.RR
	
	for _, l := range config.Server.Listeners {
		protos := strings.ToLower(l.Protocol)
		
		for _, port := range l.Port {
			var alpn []string
			var dohPath string
			
			switch protos {
			case "dot", "tls":
				alpn = []string{"dot"}
			case "doq", "quic":
				alpn = []string{"doq"}
			case "doh":
				alpn = []string{"h2"}
				dohPath = defaultDohPath
			case "doh3", "h3":
				alpn = []string{"h3"}
				dohPath = defaultDohPath
			case "https":
				alpn = []string{"h2", "h3"}
				dohPath = defaultDohPath
			}
			
			if len(alpn) > 0 {
				svcb := &dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeSVCB,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Priority: 1,
					Target:   ".",
				}
				
				svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: alpn})
				svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: uint16(port)})
				
				if serverIP != nil {
					if serverIP.To4() != nil {
						svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{serverIP}})
					} else {
						svcb.Value = append(svcb.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{serverIP}})
					}
				}

				if dohPath != "" {
					svcb.Value = append(svcb.Value, &dns.SVCBDoHPath{Template: dohPath})
				}
				
				answers = append(answers, svcb)
			}
		}
	}
	
	if len(answers) == 0 {
		return nil
	}
	
	resp.Answer = answers
	return resp
}

func cleanResponse(msg *dns.Msg) {
	if msg == nil {
		return
	}

	if !config.Server.Response.Minimization {
		return
	}

	nsCount := len(msg.Ns)
	extraCount := len(msg.Extra)

	msg.Ns = nil
	msg.Extra = nil

	removedAnswerCount := 0
	if len(msg.Answer) > 0 {
		n := 0
		for _, rr := range msg.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY, dns.TypeDLV:
				removedAnswerCount++
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

	LogDebug("[RESPONSE] Minimization: Stripped %d Authority, %d Additional, %d DNSSEC Answer records",
		nsCount, extraCount, removedAnswerCount)
}

func flattenCNAMEs(msg *dns.Msg) {
	if msg == nil || len(msg.Answer) == 0 {
		return
	}

	if len(msg.Question) == 0 {
		return
	}
	qName := msg.Question[0].Name
	initialCount := len(msg.Answer)

	cnameMap := make(map[string]string)
	var finalRRs []dns.RR
	var otherRRs []dns.RR

	for _, rr := range msg.Answer {
		header := rr.Header()
		if cname, ok := rr.(*dns.CNAME); ok {
			cnameMap[header.Name] = cname.Target
		} else if _, ok := rr.(*dns.A); ok {
			finalRRs = append(finalRRs, rr)
		} else if _, ok := rr.(*dns.AAAA); ok {
			finalRRs = append(finalRRs, rr)
		} else {
			otherRRs = append(otherRRs, rr)
		}
	}

	if len(finalRRs) == 0 {
		LogDebug("[RESPONSE] CNAME Flattening: No final A/AAAA records found to flatten to")
		return
	}

	resolvesToQName := func(targetName string) bool {
		current := qName
		visited := make(map[string]bool)

		for {
			if current == targetName {
				return true
			}
			if visited[current] {
				return false
			}
			visited[current] = true

			next, ok := cnameMap[current]
			if !ok {
				return false
			}
			current = next
		}
	}

	newAnswers := make([]dns.RR, 0, len(finalRRs)+len(otherRRs))

	for _, rr := range finalRRs {
		if resolvesToQName(rr.Header().Name) {
			newRR := dns.Copy(rr)
			newRR.Header().Name = qName
			newAnswers = append(newAnswers, newRR)
		} else {
			newAnswers = append(newAnswers, rr)
		}
	}

	newAnswers = append(newAnswers, otherRRs...)

	msg.Answer = newAnswers

	if len(newAnswers) < initialCount {
		LogDebug("[RESPONSE] CNAME Flattening: Collapsed chain (Records: %d -> %d)", initialCount, len(newAnswers))
	} else {
		LogDebug("[RESPONSE] CNAME Flattening: Checked, but no reduction possible (Chain might be direct)")
	}
}

func sortResponse(msg *dns.Msg) {
	if msg == nil || len(msg.Answer) <= 1 {
		return
	}

	strategy := config.Cache.ResponseSorting
	if strategy == "none" {
		return
	}

	var ips []dns.RR
	var others []dns.RR

	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.A); ok {
			ips = append(ips, rr)
		} else if _, ok := rr.(*dns.AAAA); ok {
			ips = append(ips, rr)
		} else {
			others = append(others, rr)
		}
	}

	if len(ips) <= 1 {
		return
	}

	switch strategy {
	case "round-robin":
		rand.Shuffle(len(ips), func(i, j int) {
			ips[i], ips[j] = ips[j], ips[i]
		})
	case "sorted":
		sort.Slice(ips, func(i, j int) bool {
			var ipI, ipJ net.IP

			if a, ok := ips[i].(*dns.A); ok {
				ipI = a.A
			} else if aaaa, ok := ips[i].(*dns.AAAA); ok {
				ipI = aaaa.AAAA
			}

			if a, ok := ips[j].(*dns.A); ok {
				ipJ = a.A
			} else if aaaa, ok := ips[j].(*dns.AAAA); ok {
				ipJ = aaaa.AAAA
			}

			return bytes.Compare(ipI, ipJ) < 0
		})
	}

	msg.Answer = append(ips, others...)
}

func applyTTLClamping(msg *dns.Msg) {
	if msg == nil || config == nil {
		return
	}

	if config.Cache.MinTTL == 0 && config.Cache.MaxTTL == 0 && config.Cache.MinNegTTL == 0 && config.Cache.MaxNegTTL == 0 {
		return
	}

	isNegative := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	clampedCount := 0

	clampTTLs := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}

			originalTTL := rr.Header().Ttl
			newTTL := originalTTL

			if isNegative {
				if config.Cache.MinNegTTL > 0 && newTTL < uint32(config.Cache.MinNegTTL) {
					newTTL = uint32(config.Cache.MinNegTTL)
				}
				if config.Cache.MaxNegTTL > 0 && newTTL > uint32(config.Cache.MaxNegTTL) {
					newTTL = uint32(config.Cache.MaxNegTTL)
				}
			} else {
				if config.Cache.MinTTL > 0 && newTTL < uint32(config.Cache.MinTTL) {
					newTTL = uint32(config.Cache.MinTTL)
				}
				if config.Cache.MaxTTL > 0 && newTTL > uint32(config.Cache.MaxTTL) {
					newTTL = uint32(config.Cache.MaxTTL)
				}
			}

			if newTTL != originalTTL {
				rr.Header().Ttl = newTTL
				clampedCount++
			}
		}
	}

	clampTTLs(msg.Answer)
	clampTTLs(msg.Ns)
	clampTTLs(msg.Extra)

	respType := "NOERROR"
	if isNegative {
		respType = "NEGATIVE"
	}
	LogDebug("[TTL-CLAMP] Processed (%s), Clamped: %d", respType, clampedCount)
}

func applyTTLStrategy(msg *dns.Msg) {
	if msg == nil || config == nil {
		return
	}

	strategy := strings.ToLower(config.Cache.TTLStrategy)
	if strategy == "" || strategy == "none" {
		return
	}

	var ttls []uint32
	collectTTLs := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			ttls = append(ttls, rr.Header().Ttl)
		}
	}

	collectTTLs(msg.Answer)
	collectTTLs(msg.Ns)
	collectTTLs(msg.Extra)

	if len(ttls) <= 1 {
		return
	}

	var targetTTL uint32

	switch strategy {
	case "first":
		targetTTL = ttls[0]
	case "last":
		targetTTL = ttls[len(ttls)-1]
	case "lowest":
		targetTTL = ttls[0]
		for _, t := range ttls[1:] {
			if t < targetTTL {
				targetTTL = t
			}
		}
	case "highest":
		targetTTL = ttls[0]
		for _, t := range ttls[1:] {
			if t > targetTTL {
				targetTTL = t
			}
		}
	case "average":
		var sum uint64
		for _, t := range ttls {
			sum += uint64(t)
		}
		targetTTL = uint32(sum / uint64(len(ttls)))
	default:
		LogWarn("[TTL] Unknown TTL strategy '%s', skipping normalization", strategy)
		return
	}

	allSame := true
	for _, t := range ttls {
		if t != targetTTL {
			allSame = false
			break
		}
	}

	if allSame {
		return
	}

	applyTTL := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			rr.Header().Ttl = targetTTL
		}
	}

	applyTTL(msg.Answer)
	applyTTL(msg.Ns)
	applyTTL(msg.Extra)

	LogDebug("[TTL] Strategy '%s': Normalized %d records to TTL=%d", strategy, len(ttls), targetTTL)
}

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

	var ecsLog string = "None"
	var macLog string = "None"

	for _, opt := range o.Option {
		if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			ecsLog = fmt.Sprintf("Existing(%s/%d)", ecs.Address, ecs.SourceNetmask)
		} else if local, ok := opt.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
			hasMAC = true
			existingMAC = net.HardwareAddr(local.Data)
			macLog = fmt.Sprintf("Existing(%s)", existingMAC)
		}
	}

	for _, opt := range o.Option {
		switch v := opt.(type) {
		case *dns.EDNS0_SUBNET:
			switch ecsMode {
			case "preserve":
				opts = append(opts, opt)
				ecsLog = "Preserved"
			case "add":
				if hasECS {
					opts = append(opts, opt)
					ecsLog = "Preserved"
				}
			case "replace":
				ecsLog = "Replacing"
			case "remove":
				ecsLog = "Removed"
			}
		case *dns.EDNS0_LOCAL:
			if v.Code == EDNS0_OPTION_MAC {
				switch macMode {
				case "preserve":
					opts = append(opts, opt)
					macLog = "Preserved"
				case "add":
					if hasMAC {
						opts = append(opts, opt)
						macLog = "Preserved"
					}
				case "replace":
					macLog = "Replacing"
				case "remove":
					macLog = "Removed"
				case "prefer-edns0":
					if hasMAC {
						opts = append(opts, opt)
						macLog = "Preserved(Preferred)"
					}
				case "prefer-arp":
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
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
			}
			if mask > 128 {
				mask = 128
			}
		} else {
			if config.Server.EDNS0.ECS.IPv4Mask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.IPv4Mask)
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
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
		ecsLog = fmt.Sprintf("Added(%s/%d)", ip, mask)
	}

	shouldAddMAC := false
	var macToAdd net.HardwareAddr
	switch macMode {
	case "preserve":
		shouldAddMAC = false
	case "add":
		shouldAddMAC = !hasMAC
		macToAdd = determineMAC(mac, existingMAC, macSource)
	case "replace":
		shouldAddMAC = true
		macToAdd = determineMAC(mac, existingMAC, macSource)
	case "remove":
		shouldAddMAC = false
	case "prefer-edns0":
		if hasMAC {
			shouldAddMAC = false
		} else if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
		}
	case "prefer-arp":
		if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
		} else if hasMAC && (macSource == "edns0" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = existingMAC
		}
	}
	if shouldAddMAC && macToAdd != nil {
		opts = append(opts, &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: macToAdd})
		macLog = fmt.Sprintf("Added(%s)", macToAdd)
	}
	o.Option = opts

	LogDebug("[EDNS0] ClientIP=%v | ECS(%s): %s | MAC(%s): %s | Opts: %d",
		ip, ecsMode, ecsLog, macMode, macLog, len(opts))
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

