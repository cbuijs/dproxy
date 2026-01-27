/*
File: routing.go
Version: 1.9.0 (Generic Trie Implementation)
Description: High-performance routing logic using the shared generic Domain Trie.
             OPTIMIZED: Removed duplicate Trie definitions. Now uses trie.go's DomainTrie[RoutingRule].
             UPDATED: SelectUpstreams adapted for generic Trie return values.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// --- Globals ---

var (
	// Use the generic DomainTrie with RoutingRule as the value type
	domainRouter *DomainTrie[RoutingRule]
	genericRules []RoutingRule // Generic rules (IP, MAC, etc.) linear scan
)

// --- Initialization called from Config Load ---

func BuildRoutingTable(rules []RoutingRule) {
	// Instantiate the generic Trie
	trie := NewDomainTrie[RoutingRule]()
	var generic []RoutingRule

	for i := range rules {
		// We copy the rule by value into the trie/slice to avoid pointer issues with loop vars
		rule := rules[i]

		if len(rule.Match.QueryDomain) > 0 {
			for _, domain := range rule.Match.QueryDomain {
				// Insert into Trie. keys are lowercased.
				trie.Insert(strings.ToLower(domain), rule)
			}

			// If the rule ONLY has domains, we don't need it in the generic linear scan list.
			// If it has IP/MAC/etc, we ALSO add it to generic so it can match even if the domain doesn't.
			if !hasNonDomainConditions(&rule.Match) {
				continue
			}
		}

		generic = append(generic, rule)
	}

	domainRouter = trie
	genericRules = generic
	LogInfo("[ROUTING] Built routing table: Domain Trie built, %d generic rules", len(genericRules))
}

func hasNonDomainConditions(m *MatchConditions) bool {
	return len(m.ClientIP) > 0 ||
		len(m.ClientCIDR) > 0 ||
		len(m.ClientMAC) > 0 ||
		len(m.rawClientMACs) > 0 ||
		len(m.ClientECS) > 0 ||
		len(m.ClientEDNSMAC) > 0 ||
		len(m.rawClientEDNSMACs) > 0 ||
		len(m.ServerIP) > 0 ||
		len(m.ServerPort) > 0 ||
		len(m.ServerHostname) > 0 ||
		len(m.ServerPath) > 0
}

// SelectUpstreams optimized with generic Trie lookup.
// UPDATED: Now returns MLGuardMode as the last argument
func SelectUpstreams(ctx *RequestContext) ([]*Upstream, string, string, *HostsCache, bool, string) {
	if config == nil {
		log.Fatal("Config not loaded")
		return nil, "", "", nil, false, ""
	}

	// 1. Fast Path: Domain Trie Lookup
	if domainRouter != nil && ctx.QueryName != "" {
		// Search returns (value, found, isWildcard)
		// We ignore isWildcard here as we just want the rule
		if rule, found, _ := domainRouter.Search(ctx.QueryName); found {
			LogDebug("[ROUTING] HIT Trie Rule: '%s' | Domain: %s", rule.Name, ctx.QueryName)
			return rule.parsedUpstreams, rule.Strategy, rule.Name, rule.parsedHosts, rule.HostsWildcard, rule.MLGuardMode
		}
	}

	// 2. Slow Path: Linear scan of generic rules
	for _, rule := range genericRules {
		matched, reason := matchRule(&rule.Match, ctx)
		if matched {
			LogDebug("[ROUTING] HIT Generic Rule: '%s' | Trigger: %s", rule.Name, reason)
			return rule.parsedUpstreams, rule.Strategy, rule.Name, rule.parsedHosts, rule.HostsWildcard, rule.MLGuardMode
		}
	}

	return config.Routing.DefaultRule.parsedUpstreams,
		config.Routing.DefaultRule.Strategy,
		"DEFAULT",
		config.Routing.DefaultRule.parsedHosts,
		config.Routing.DefaultRule.HostsWildcard,
		config.Routing.DefaultRule.MLGuardMode
}

func matchRule(m *MatchConditions, ctx *RequestContext) (bool, string) {
	effectiveIP := ctx.ClientIP
	if ctx.ClientECS != nil {
		effectiveIP = ctx.ClientECS
	}

	effectiveMAC := ctx.ClientMAC
	if ctx.ClientEDNSMAC != nil {
		effectiveMAC = ctx.ClientEDNSMAC
	}

	conditionsChecked := 0

	// Check Client IPs
	if len(m.parsedClientIPs) > 0 {
		conditionsChecked++
		for _, ip := range m.parsedClientIPs {
			if effectiveIP != nil && ip.Equal(effectiveIP) {
				return true, fmt.Sprintf("ClientIP=%s", effectiveIP)
			}
		}
	}

	// Check Client CIDRs
	if len(m.parsedClientCIDRs) > 0 {
		conditionsChecked++
		for _, cidr := range m.parsedClientCIDRs {
			if effectiveIP != nil && cidr.Contains(effectiveIP) {
				return true, fmt.Sprintf("ClientCIDR=%s (matched %s)", cidr.String(), effectiveIP)
			}
		}
	}

	// Check Client MACs (Exact)
	if len(m.parsedClientMACs) > 0 {
		conditionsChecked++
		for _, mac := range m.parsedClientMACs {
			if effectiveMAC != nil && macEqual(mac, effectiveMAC) {
				return true, fmt.Sprintf("ClientMAC=%s", effectiveMAC)
			}
		}
	}

	// Check Client MACs (Wildcard)
	if len(m.rawClientMACs) > 0 {
		conditionsChecked++
		macStr := effectiveMAC.String()
		for _, pattern := range m.rawClientMACs {
			if effectiveMAC != nil && matchWildcard(macStr, pattern) {
				return true, fmt.Sprintf("ClientMACPattern=%s (matched %s)", pattern, macStr)
			}
		}
	}

	// Check Client ECS
	if len(m.parsedClientECSs) > 0 {
		conditionsChecked++
		for _, ecs := range m.parsedClientECSs {
			if ctx.ClientECS != nil && ecs.Contains(ctx.ClientECS) {
				return true, fmt.Sprintf("ClientECS=%s", ctx.ClientECS)
			}
		}
	}

	// Check Client EDNS MACs (Exact)
	if len(m.parsedClientEDNSMACs) > 0 {
		conditionsChecked++
		for _, mac := range m.parsedClientEDNSMACs {
			if ctx.ClientEDNSMAC != nil && macEqual(mac, ctx.ClientEDNSMAC) {
				return true, fmt.Sprintf("EDNS0MAC=%s", ctx.ClientEDNSMAC)
			}
		}
	}

	// Check Client EDNS MACs (Wildcard)
	if len(m.rawClientEDNSMACs) > 0 {
		conditionsChecked++
		macStr := ctx.ClientEDNSMAC.String()
		for _, pattern := range m.rawClientEDNSMACs {
			if ctx.ClientEDNSMAC != nil && matchWildcard(macStr, pattern) {
				return true, fmt.Sprintf("EDNS0MACPattern=%s (matched %s)", pattern, macStr)
			}
		}
	}

	// Check Server IPs
	if len(m.parsedServerIPs) > 0 {
		conditionsChecked++
		for _, ip := range m.parsedServerIPs {
			if ctx.ServerIP != nil && ip.Equal(ctx.ServerIP) {
				return true, fmt.Sprintf("ServerIP=%s", ctx.ServerIP)
			}
		}
	}

	// Check Server Ports
	if len(m.ServerPort) > 0 {
		conditionsChecked++
		for _, port := range m.ServerPort {
			if ctx.ServerPort == port {
				return true, fmt.Sprintf("ServerPort=%d", ctx.ServerPort)
			}
		}
	}

	// Check Server Hostnames
	if len(m.ServerHostname) > 0 {
		conditionsChecked++
		for _, hostname := range m.ServerHostname {
			if strings.EqualFold(ctx.ServerHostname, hostname) {
				return true, fmt.Sprintf("Hostname=%s", hostname)
			}
		}
	}

	// Check Server Paths
	if len(m.ServerPath) > 0 {
		conditionsChecked++
		for _, path := range m.ServerPath {
			if ctx.ServerPath == path {
				return true, fmt.Sprintf("Path=%s", path)
			}
		}
	}

	// Check Query Domain (Linear Scan fallback for regex-like or legacy non-trie wildcard needs)
	// Note: Most domain matching is handled by Trie now, but this remains for regex-style wildcards if implemented,
	// or simple list matching if not using Trie for everything.
	if len(m.QueryDomain) > 0 {
		conditionsChecked++
		for _, domain := range m.QueryDomain {
			if matchDomain(ctx.QueryName, strings.ToLower(domain)) {
				return true, fmt.Sprintf("QueryDomain=%s", domain)
			}
		}
	}

	if conditionsChecked == 0 {
		return false, ""
	}

	return false, ""
}

func matchDomain(queryName, pattern string) bool {
	if queryName == pattern {
		return true
	}
	if strings.HasPrefix(pattern, ".") {
		if strings.HasSuffix(queryName, pattern) {
			return true
		}
		if queryName == pattern[1:] {
			return true
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		if strings.HasSuffix(queryName, pattern[1:]) {
			return true
		}
	}
	return false
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Simple wildcard matcher for strings (supports * and ?)
func matchWildcard(s, pattern string) bool {
	if s == pattern {
		return true
	}

	lenS := len(s)
	lenP := len(pattern)
	si := 0
	pi := 0
	starIdx := -1
	matchIdx := 0

	for si < lenS {
		if pi < lenP && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
		} else if pi < lenP && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for pi < lenP && pattern[pi] == '*' {
		pi++
	}

	return pi == lenP
}

