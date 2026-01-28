/*
File: routing.go
Version: 1.9.1 (Dead Code Removed)
Description: High-performance routing logic using the shared generic Domain Trie and CIDR Ranger.
             OPTIMIZED: Removed duplicate Trie definitions. Now uses trie.go's DomainTrie[RoutingRule].
             OPTIMIZED: Added IPRouter using cidranger for O(1) IP matching instead of linear scan.
             FIXED: Removed duplicate resolveUpstreams (handled in config.go).
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/yl2chen/cidranger"
)

// --- IP Router Implementation (cidranger) ---

type ipRuleEntry struct {
	network net.IPNet
	rule    *RoutingRule
}

func (e *ipRuleEntry) Network() net.IPNet {
	return e.network
}

type IPRouter struct {
	ranger cidranger.Ranger
}

func NewIPRouter() *IPRouter {
	return &IPRouter{
		ranger: cidranger.NewPCTrieRanger(),
	}
}

func (r *IPRouter) Insert(ipNet net.IPNet, rule *RoutingRule) error {
	return r.ranger.Insert(&ipRuleEntry{network: ipNet, rule: rule})
}

func (r *IPRouter) Search(ip net.IP) *RoutingRule {
	if ip == nil {
		return nil
	}
	
	entries, err := r.ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return nil
	}

	var bestMatch *RoutingRule
	maxOnes := -1

	// Find the most specific match (longest prefix)
	for _, e := range entries {
		entry, ok := e.(*ipRuleEntry)
		if !ok { continue }
		
		ones, _ := entry.network.Mask.Size()
		if ones > maxOnes {
			maxOnes = ones
			bestMatch = entry.rule
		}
	}
	
	return bestMatch
}

// --- Globals ---

var (
	// Use the generic DomainTrie from trie.go with RoutingRule as the value type
	domainRouter *DomainTrie[RoutingRule]
	ipRouter     *IPRouter
	genericRules []RoutingRule // Generic rules (MAC, ECS, etc.) linear scan
)

// --- Initialization called from Config Load ---

func BuildRoutingTable(rules []RoutingRule) {
	// Instantiate the generic Trie
	trie := NewDomainTrie[RoutingRule]()
	ipRanger := NewIPRouter()
	var generic []RoutingRule

	for i := range rules {
		// We copy the rule by value into the trie/slice to avoid pointer issues with loop vars
		// However, trie stores T, so we store RoutingRule (struct) directly.
		rule := rules[i]
		
		// Flag to track if this rule was handled by optimized lookups
		// If a rule has complex conditions (MAC, Port, etc), it MUST go to generic fallback
		// even if it is also indexed in Trie/Ranger, to ensure ALL conditions are met.
		isComplex := hasComplexConditions(&rule.Match)

		// 1. Build Domain Trie
		if len(rule.Match.QueryDomain) > 0 {
			for _, domain := range rule.Match.QueryDomain {
				// Insert into Trie. keys are lowercased.
				trie.Insert(strings.ToLower(domain), rule)
			}
		}

		// 2. Build IP Ranger
		// Handle CIDRs
		for _, cidr := range rule.Match.parsedClientCIDRs {
			if cidr != nil {
				// We store a pointer to the rule in the IP entry to avoid copying huge structs
				_ = ipRanger.Insert(*cidr, &rule)
			}
		}
		// Handle Single IPs (convert to /32 or /128)
		for _, ip := range rule.Match.parsedClientIPs {
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				_ = ipRanger.Insert(net.IPNet{IP: ip, Mask: mask}, &rule)
			}
		}

		// 3. Fallback / Complex Rules
		// If a rule has ANY condition that isn't just "Client IP" or "Query Domain",
		// it must be processed by the linear scanner to check those extra conditions.
		// Also, if it has NO specific IP/Domain triggers (e.g. match-all *), it might end up here.
		if isComplex {
			generic = append(generic, rule)
		} else {
			// If it wasn't complex, did we index it?
			hasDomain := len(rule.Match.QueryDomain) > 0
			hasIP := len(rule.Match.parsedClientIPs) > 0 || len(rule.Match.parsedClientCIDRs) > 0
			
			if !hasDomain && !hasIP {
				// Catch-all rules or empty matches go to generic
				generic = append(generic, rule)
			}
		}
	}

	domainRouter = trie
	ipRouter = ipRanger
	genericRules = generic
	LogInfo("[ROUTING] Built routing table: Domain Trie, IP Ranger, %d generic rules", len(genericRules))
}

func hasComplexConditions(m *MatchConditions) bool {
	// If any of these are present, the rule cannot be satisfied purely by looking up
	// Domain or ClientIP. It requires context inspection.
	return len(m.ClientMAC) > 0 ||
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

	// 2. Fast Path: IP Ranger Lookup (Client IP)
	if ipRouter != nil && ctx.ClientIP != nil {
		if rule := ipRouter.Search(ctx.ClientIP); rule != nil {
			LogDebug("[ROUTING] HIT IP Rule: '%s' | ClientIP: %s", rule.Name, ctx.ClientIP)
			return rule.parsedUpstreams, rule.Strategy, rule.Name, rule.parsedHosts, rule.HostsWildcard, rule.MLGuardMode
		}
	}

	// 3. Slow Path: Linear scan of generic rules
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

	// Fallback IP Check (for ECS or complex rules not caught by Ranger)
	// We check this if present in generic rules.
	if len(m.parsedClientIPs) > 0 {
		conditionsChecked++
		for _, ip := range m.parsedClientIPs {
			if effectiveIP != nil && ip.Equal(effectiveIP) {
				return true, fmt.Sprintf("ClientIP=%s", effectiveIP)
			}
		}
	}

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

	// Check Client ECS (Explicit range check)
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

	// Fallback Query Domain check 
	// (Only if somehow we are in generic loop but have a domain rule, e.g. complex regex not supported by Trie)
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

