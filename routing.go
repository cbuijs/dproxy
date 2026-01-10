/*
File: routing.go
Version: 1.6.0
Description: High-performance routing logic using Domain Trie (Radix-style) for rapid lookups.
             OPTIMIZED: Removed "RECURSIVE" upstream resolution handling.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// --- Domain Trie Implementation ---

type TrieNode struct {
	Children map[string]*TrieNode
	Rule     *RoutingRule // Non-nil if a rule terminates here
	Wildcard *RoutingRule // Non-nil if a *.domain rule exists here
}

func NewTrieNode() *TrieNode {
	return &TrieNode{}
}

type DomainTrie struct {
	Root *TrieNode
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{Root: NewTrieNode()}
}

// Insert adds a domain rule. Handles "example.com", ".example.com", "*.example.com"
func (t *DomainTrie) Insert(domain string, rule *RoutingRule) {
	parts := strings.Split(domain, ".")

	isWildcard := false
	if parts[0] == "*" {
		isWildcard = true
		parts = parts[1:]
	} else if parts[0] == "" {
		isWildcard = true
		parts = parts[1:]
	}

	node := t.Root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		if node.Children == nil {
			node.Children = make(map[string]*TrieNode)
		}

		if node.Children[part] == nil {
			node.Children[part] = NewTrieNode()
		}
		node = node.Children[part]
	}

	if isWildcard {
		node.Wildcard = rule
		if strings.HasPrefix(domain, ".") {
			node.Rule = rule
		}
	} else {
		node.Rule = rule
	}
}

// Search finds the most specific rule for a query name
// OPTIMIZED: Uses string indices to walk backward from TLD to subdomain without allocation.
func (t *DomainTrie) Search(qName string) *RoutingRule {
	node := t.Root
	var lastValidRule *RoutingRule

	// We iterate from the end of the string backwards to the beginning
	// qName: "www.example.com" -> "com", "example", "www"

	end := len(qName)
	for end > 0 {
		// Find the dot preceding the current part
		start := strings.LastIndexByte(qName[:end], '.')

		// Extract part: qName[start+1 : end]
		// If start is -1, it means we are at the first label (e.g. "www" in "www.example.com")
		part := qName[start+1 : end]

		// Update Wildcard match if present at this node
		if node.Wildcard != nil {
			lastValidRule = node.Wildcard
		}

		if node.Children == nil {
			return lastValidRule
		}

		next, ok := node.Children[part]
		if !ok {
			return lastValidRule
		}
		node = next

		// Move pointers for next iteration
		if start == -1 {
			break // We just processed the last part (left-most label)
		}
		end = start
	}

	// Final check at the leaf
	if node.Rule != nil {
		return node.Rule
	}

	if node.Wildcard != nil {
		return node.Wildcard
	}

	return lastValidRule
}

// --- Globals ---

var (
	domainRouter *DomainTrie
	genericRules []RoutingRule // Rules without query_domain
)

// --- Initialization called from Config Load ---

func BuildRoutingTable(rules []RoutingRule) {
	trie := NewDomainTrie()
	var generic []RoutingRule

	for i := range rules {
		rule := &rules[i]

		if len(rule.Match.QueryDomain) > 0 {
			for _, domain := range rule.Match.QueryDomain {
				trie.Insert(strings.ToLower(domain), rule)
			}

			if !hasNonDomainConditions(&rule.Match) {
				continue
			}
		}

		generic = append(generic, *rule)
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

// --- Main Logic ---

func resolveUpstreams(upstreams interface{}, groups map[string][]string) ([]string, error) {
	switch v := upstreams.(type) {
	case string:
		group, exists := groups[v]
		if !exists {
			return nil, fmt.Errorf("upstream group '%s' not found", v)
		}
		return group, nil
	case []interface{}:
		var urls []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				urls = append(urls, str)
			} else {
				return nil, fmt.Errorf("invalid upstream entry: %v", item)
			}
		}
		return urls, nil
	default:
		return nil, fmt.Errorf("upstreams must be string (group name) or list")
	}
}

// SelectUpstreams optimized with Trie lookup.
func SelectUpstreams(ctx *RequestContext) ([]*Upstream, string, string, *HostsCache, bool) {
	if config == nil {
		log.Fatal("Config not loaded")
		return nil, "", "", nil, false
	}

	// 1. Fast Path: Domain Trie Lookup
	if domainRouter != nil && ctx.QueryName != "" {
		if rule := domainRouter.Search(ctx.QueryName); rule != nil {
			LogDebug("[ROUTING] HIT Trie Rule: '%s' | Domain: %s", rule.Name, ctx.QueryName)
			return rule.parsedUpstreams, rule.Strategy, rule.Name, rule.parsedHosts, rule.HostsWildcard
		}
	}

	// 2. Slow Path: Linear scan of generic rules
	for _, rule := range genericRules {
		matched, reason := matchRule(&rule.Match, ctx)
		if matched {
			LogDebug("[ROUTING] HIT Generic Rule: '%s' | Trigger: %s", rule.Name, reason)
			return rule.parsedUpstreams, rule.Strategy, rule.Name, rule.parsedHosts, rule.HostsWildcard
		}
	}

	return config.Routing.DefaultRule.parsedUpstreams,
		config.Routing.DefaultRule.Strategy,
		"DEFAULT",
		config.Routing.DefaultRule.parsedHosts,
		config.Routing.DefaultRule.HostsWildcard
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
// OPTIMIZED: Works on bytes for ASCII strings (MACs/Hex) to avoid rune allocation.
func matchWildcard(s, pattern string) bool {
	// Fast path for exact match
	if s == pattern {
		return true
	}

	lenS := len(s)
	lenP := len(pattern)

	// Index in string, Index in pattern
	si := 0
	pi := 0

	// Last star positions
	starIdx := -1
	matchIdx := 0

	for si < lenS {
		// Single character match or exact match
		if pi < lenP && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
		} else if pi < lenP && pattern[pi] == '*' {
			// Star match - record position and assume zero chars first
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			// Backtrack: If prev was a star, try to consume one more char from string
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	// Consume remaining stars in pattern
	for pi < lenP && pattern[pi] == '*' {
		pi++
	}

	return pi == lenP
}

