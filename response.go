/*
File: response.go
Version: 1.1.2 (Fix Search Signature)
Description: Handles DNS response manipulation.
             FIXED: hosts.trie.Search signature to match 5 return values.
*/

package main

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// UnifiedResponseProcessor iterates the response ONCE and applies all active filters/logic.
// Returns: true if response is modified (records dropped/changed).
func UnifiedResponseProcessor(resp *dns.Msg, reqCtx *RequestContext, ruleName string, hosts *HostsCache, mlMode string) bool {
	if resp == nil {
		return false
	}

	originalCount := len(resp.Answer)
	if originalCount == 0 && len(resp.Ns) == 0 && len(resp.Extra) == 0 {
		return false
	}

	modified := false

	doMinimization := config.Server.Response.Minimization
	doCNAMEFlattening := config.Server.Response.CNAMEFlattening
	doHostsFilter := hosts != nil && hosts.filterResponses
	doMLGuard := config.MLGuard.Enabled && mlMode != "disable" && mlMode != ""

	minTTL := uint32(config.Cache.MinTTL)
	maxTTL := uint32(config.Cache.MaxTTL)

	// In-place filtering helper
	shouldKeep := func(rr dns.RR, section string) bool {
		header := rr.Header()

		// 1. Minimization
		if doMinimization && (section == "NS" || section == "EXTRA") {
			return false
		}
		if doMinimization && section == "ANSWER" {
			switch header.Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY:
				return false
			}
		}

		// 2. Hosts Filter
		if doHostsFilter && section == "ANSWER" {
			var ip net.IP
			if a, ok := rr.(*dns.A); ok {
				ip = a.A
			}
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ip = aaaa.AAAA
			}

			if ip != nil {
				if contains, _ := hosts.ipRanger.Contains(ip); contains {
					LogInfo("[FILTER] Dropped IP %s", ip)
					return false
				}
			}

			target := extractTarget(rr)
			if target != "" {
				target = strings.TrimSuffix(strings.ToLower(target), ".")
				// FIXED: Correct signature -> found, isAllowed, ips, sourceName, hitDomain
				found, isAllowed, _, sourceName, hitDomain := hosts.trie.Search(target, hosts.wildcard)
				if found {
					if !isAllowed {
						matchType := "Exact"
						if hitDomain != target {
							matchType = "Wildcard"
						}

						if IsCompact() {
							LogInfo("[FILTER] Dropped %s | Match: %s | Source: %s", target, matchType, sourceName)
						} else {
							LogInfo("[FILTER] Dropped Domain %s (Matched: %s, Source: %s)", target, matchType, sourceName)
						}
						return false
					}
				}
			}
		}

		// 3. ML Guard
		if doMLGuard && section == "ANSWER" {
			target := extractTarget(rr)
			if target != "" && target != reqCtx.QueryName {
				suspicious, prob, reason := GlobalMLGuard.Check(target, dns.TypeToString[header.Rrtype], mlMode, true)
				shouldBlock, shouldLog := GlobalMLGuard.DecideAction(mlMode, true, suspicious)

				if shouldBlock {
					GlobalMLGuard.RecordScore(prob, true)
					LogInfo("[ML-GUARD] BLOCKED Response Target: %s (Prob: %.2f) | %s", target, prob, reason)
					return false
				}
				if shouldLog {
					GlobalMLGuard.RecordScore(prob, false)
					LogInfo("[ML-GUARD] SUSPICIOUS Response Target: %s (Prob: %.2f) | %s", target, prob, reason)
				} else if suspicious {
					GlobalMLGuard.RecordScore(prob, false)
				}
			}
		}

		// 4. TTL Clamping
		if minTTL > 0 && header.Ttl < minTTL {
			header.Ttl = minTTL
			modified = true
		}
		if maxTTL > 0 && header.Ttl > maxTTL {
			header.Ttl = maxTTL
			modified = true
		}

		return true
	}

	filterSection := func(rrs []dns.RR, section string) []dns.RR {
		n := 0
		for _, rr := range rrs {
			if shouldKeep(rr, section) {
				rrs[n] = rr
				n++
			} else {
				modified = true
			}
		}
		for i := n; i < len(rrs); i++ {
			rrs[i] = nil
		}
		return rrs[:n]
	}

	resp.Answer = filterSection(resp.Answer, "ANSWER")
	resp.Ns = filterSection(resp.Ns, "NS")
	resp.Extra = filterSection(resp.Extra, "EXTRA")

	if originalCount > 0 && len(resp.Answer) == 0 {
		LogInfo("[FILTER] All records filtered for %s, injecting block record.", reqCtx.QueryName)
		if len(resp.Question) > 0 {
			q := resp.Question[0]
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(0, 0, 0, 0),
				})
			} else if q.Qtype == dns.TypeAAAA {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.IPv6zero,
				})
			} else {
				resp.Rcode = dns.RcodeNameError
			}
		}
	}

	if doCNAMEFlattening {
		flattenCNAMEs(resp)
	}
	applyTTLStrategy(resp)
	sortResponse(resp)

	return modified
}

func extractTarget(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.CNAME:
		return v.Target
	case *dns.MX:
		return v.Mx
	case *dns.SRV:
		return v.Target
	case *dns.NS:
		return v.Ns
	case *dns.PTR:
		return v.Ptr
	case *dns.DNAME:
		return v.Target
	}
	return ""
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

	if IsDebugEnabled() {
		respType := "NOERROR"
		if isNegative {
			respType = "NEGATIVE"
		}
		
		var qInfo string
		if len(msg.Question) > 0 {
			qInfo = fmt.Sprintf("%s (%s)", msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
		} else {
			qInfo = "unknown"
		}

		LogDebug("[TTL-CLAMP] Processed (%s) | Query: %s | Answers: %d | Clamped: %d", respType, qInfo, len(msg.Answer), clampedCount)
	}
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

	target := "."
	if config.Server.DDR.HostName != "" {
		target = config.Server.DDR.HostName
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
					Target:   target,
				}

				svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: alpn})
				svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: uint16(port)})

				// Add IP Hints to the SVCB Record (Action Section)
				if serverIP != nil {
					if ip4 := serverIP.To4(); ip4 != nil {
						svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ip4}})
					} else {
						svcb.Value = append(svcb.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{serverIP}})
					}
				}

				if dohPath != "" {
					// Ensure URI Template for GET support is present
					if !strings.Contains(dohPath, "{?dns}") {
						dohPath += "{?dns}"
					}
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

	// NEW: Add Additional Section with A/AAAA records for the DDR Hostname
	if target != "." && serverIP != nil {
		if ip4 := serverIP.To4(); ip4 != nil {
			resp.Extra = append(resp.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(target),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: ip4,
			})
		} else {
			resp.Extra = append(resp.Extra, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(target),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: serverIP,
			})
		}
	}

	return resp
}

