/*
File: routing.go
Description: High-performance routing logic using Domain Trie (Radix-style) for rapid lookups.
OPTIMIZED: Uses lazy map initialization to save memory on sparse nodes.
UPDATED: Support for multiple values per match condition type.
UPDATED: SelectUpstreams now returns Hosts configuration alongside upstreams.
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
func (t *DomainTrie) Search(qName string) *RoutingRule {
	parts := strings.Split(qName, ".")
	node := t.Root

	var lastValidRule *RoutingRule

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

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
	}

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
		
		// Check if rule has any query_domain conditions
		if len(rule.Match.QueryDomain) > 0 {
			// Insert each domain into the trie
			for _, domain := range rule.Match.QueryDomain {
				trie.Insert(strings.ToLower(domain), rule)
			}
			
			// If rule ONLY has query_domain conditions, don't add to generic
			// But if it has other conditions too, we need it in generic as well
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

// hasNonDomainConditions checks if match has conditions other than query_domain
func hasNonDomainConditions(m *MatchConditions) bool {
	return len(m.ClientIP) > 0 ||
		len(m.ClientCIDR) > 0 ||
		len(m.ClientMAC) > 0 ||
		len(m.ClientECS) > 0 ||
		len(m.ClientEDNSMAC) > 0 ||
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
// Returns: Upstreams, Strategy, RuleName, HostsCache, HostsWildcardBool
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

	// 2. Slow Path: Linear scan of generic rules (IP, MAC, etc.)
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

// matchRule checks if any condition matches (OR logic across all conditions)
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

	// --- OR Logic Checks - Multiple values per condition type ---

	// Check Client IPs (any match)
	if len(m.parsedClientIPs) > 0 {
		conditionsChecked++
		for _, ip := range m.parsedClientIPs {
			if effectiveIP != nil && ip.Equal(effectiveIP) {
				return true, fmt.Sprintf("ClientIP=%s", effectiveIP)
			}
		}
	}

	// Check Client CIDRs (any match)
	if len(m.parsedClientCIDRs) > 0 {
		conditionsChecked++
		for _, cidr := range m.parsedClientCIDRs {
			if effectiveIP != nil && cidr.Contains(effectiveIP) {
				return true, fmt.Sprintf("ClientCIDR=%s (matched %s)", cidr.String(), effectiveIP)
			}
		}
	}

	// Check Client MACs (any match)
	if len(m.parsedClientMACs) > 0 {
		conditionsChecked++
		for _, mac := range m.parsedClientMACs {
			if effectiveMAC != nil && macEqual(mac, effectiveMAC) {
				return true, fmt.Sprintf("ClientMAC=%s", effectiveMAC)
			}
		}
	}

	// Check Client ECS (any match)
	if len(m.parsedClientECSs) > 0 {
		conditionsChecked++
		for _, ecs := range m.parsedClientECSs {
			if ctx.ClientECS != nil && ecs.Contains(ctx.ClientECS) {
				return true, fmt.Sprintf("ClientECS=%s", ctx.ClientECS)
			}
		}
	}

	// Check Client EDNS MACs (any match)
	if len(m.parsedClientEDNSMACs) > 0 {
		conditionsChecked++
		for _, mac := range m.parsedClientEDNSMACs {
			if ctx.ClientEDNSMAC != nil && macEqual(mac, ctx.ClientEDNSMAC) {
				return true, fmt.Sprintf("EDNS0MAC=%s", ctx.ClientEDNSMAC)
			}
		}
	}

	// Check Server IPs (any match)
	if len(m.parsedServerIPs) > 0 {
		conditionsChecked++
		for _, ip := range m.parsedServerIPs {
			if ctx.ServerIP != nil && ip.Equal(ctx.ServerIP) {
				return true, fmt.Sprintf("ServerIP=%s", ctx.ServerIP)
			}
		}
	}

	// Check Server Ports (any match)
	if len(m.ServerPort) > 0 {
		conditionsChecked++
		for _, port := range m.ServerPort {
			if ctx.ServerPort == port {
				return true, fmt.Sprintf("ServerPort=%d", ctx.ServerPort)
			}
		}
	}

	// Check Server Hostnames (any match, case-insensitive)
	if len(m.ServerHostname) > 0 {
		conditionsChecked++
		for _, hostname := range m.ServerHostname {
			if strings.EqualFold(ctx.ServerHostname, hostname) {
				return true, fmt.Sprintf("Hostname=%s", hostname)
			}
		}
	}

	// Check Server Paths (any match)
	if len(m.ServerPath) > 0 {
		conditionsChecked++
		for _, path := range m.ServerPath {
			if ctx.ServerPath == path {
				return true, fmt.Sprintf("Path=%s", path)
			}
		}
	}

	// QueryDomain is handled by Trie, but check here for rules with mixed conditions
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

// matchDomain checks if queryName matches the domain pattern
func matchDomain(queryName, pattern string) bool {
	// Exact match
	if queryName == pattern {
		return true
	}

	// Wildcard match: ".example.com" or "*.example.com" matches "sub.example.com"
	if strings.HasPrefix(pattern, ".") {
		suffix := pattern // ".example.com"
		if strings.HasSuffix(queryName, suffix) {
			return true
		}
		// Also match exact domain without the dot
		if queryName == pattern[1:] {
			return true
		}
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(queryName, suffix) {
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

