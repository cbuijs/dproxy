/*
File: routing.go
Description: High-performance routing logic using Domain Trie (Radix-style) for rapid lookups.
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
	return &TrieNode{Children: make(map[string]*TrieNode)}
}

type DomainTrie struct {
	Root *TrieNode
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{Root: NewTrieNode()}
}

// Insert adds a domain rule. Handles "example.com", ".example.com", "*.example.com"
// Domain parts are inserted in REVERSE order (com -> example -> www)
func (t *DomainTrie) Insert(domain string, rule *RoutingRule) {
	parts := strings.Split(domain, ".")

	// Handle wildcard prefix "*.example.com" or ".example.com"
	isWildcard := false
	if parts[0] == "*" {
		isWildcard = true
		parts = parts[1:] // Remove "*"
	} else if parts[0] == "" {
		// Starts with dot ".example.com" -> treat as wildcard for subdomains + exact match
		isWildcard = true
		parts = parts[1:] // Remove empty start
	}

	node := t.Root
	// Reverse iteration
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		if node.Children[part] == nil {
			node.Children[part] = NewTrieNode()
		}
		node = node.Children[part]
	}

	// If it was "*.example.com", set Wildcard rule
	if isWildcard {
		node.Wildcard = rule
		// Also set exact match if the syntax was ".example.com" (usually implies both)
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

	// Reverse iteration
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		// Before moving down, check if current node has a wildcard that applies to the rest
		if node.Wildcard != nil {
			lastValidRule = node.Wildcard
		}

		next, ok := node.Children[part]
		if !ok {
			// No deeper match. Return the last wildcard found (if any)
			return lastValidRule
		}
		node = next
	}

	// Exact match at the leaf
	if node.Rule != nil {
		return node.Rule
	}

	// If exact match not found, but this node had a wildcard (unlikely for leaf but possible)
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
		// We use a pointer to the rule in the slice to avoid copying
		rule := &rules[i]
		if rule.Match.QueryDomain != "" {
			trie.Insert(strings.ToLower(rule.Match.QueryDomain), rule)
		} else {
			generic = append(generic, *rule)
		}
	}

	domainRouter = trie
	genericRules = generic
	LogInfo("[ROUTING] Built routing table: Domain Trie built, %d generic rules", len(genericRules))
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

// SelectUpstreams optimized with Trie lookup
func SelectUpstreams(ctx *RequestContext) ([]*Upstream, string, string) {
	if config == nil {
		log.Fatal("Config not loaded")
		return nil, "", ""
	}

	// 1. Fast Path: Domain Trie Lookup
	if domainRouter != nil && ctx.QueryName != "" {
		if rule := domainRouter.Search(ctx.QueryName); rule != nil {
			LogDebug("[ROUTING] HIT Trie Rule: '%s' | Domain: %s", rule.Name, ctx.QueryName)
			return rule.parsedUpstreams, rule.Strategy, rule.Name
		}
	}

	// 2. Slow Path: Linear scan of generic rules (IP, MAC, etc.)
	for _, rule := range genericRules {
		matched, reason := matchRule(&rule.Match, ctx)
		if matched {
			LogDebug("[ROUTING] HIT Generic Rule: '%s' | Trigger: %s", rule.Name, reason)
			return rule.parsedUpstreams, rule.Strategy, rule.Name
		}
	}

	return config.Routing.DefaultRule.parsedUpstreams, config.Routing.DefaultRule.Strategy, "DEFAULT"
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

	// --- OR Logic Checks ---

	if m.parsedClientIP != nil {
		conditionsChecked++
		if effectiveIP != nil && m.parsedClientIP.Equal(effectiveIP) {
			return true, fmt.Sprintf("ClientIP=%s", effectiveIP)
		}
	}

	if m.parsedClientCIDR != nil {
		conditionsChecked++
		if effectiveIP != nil && m.parsedClientCIDR.Contains(effectiveIP) {
			return true, fmt.Sprintf("ClientCIDR=%s (matched %s)", m.ClientCIDR, effectiveIP)
		}
	}

	if m.parsedClientMAC != nil {
		conditionsChecked++
		if effectiveMAC != nil && macEqual(m.parsedClientMAC, effectiveMAC) {
			return true, fmt.Sprintf("ClientMAC=%s", effectiveMAC)
		}
	}

	if m.parsedClientECS != nil {
		conditionsChecked++
		if ctx.ClientECS != nil && m.parsedClientECS.Contains(ctx.ClientECS) {
			return true, fmt.Sprintf("ClientECS=%s", ctx.ClientECS)
		}
	}

	if m.parsedClientEDNSMAC != nil {
		conditionsChecked++
		if ctx.ClientEDNSMAC != nil && macEqual(m.parsedClientEDNSMAC, ctx.ClientEDNSMAC) {
			return true, fmt.Sprintf("EDNS0MAC=%s", ctx.ClientEDNSMAC)
		}
	}

	if m.parsedServerIP != nil {
		conditionsChecked++
		if ctx.ServerIP != nil && m.parsedServerIP.Equal(ctx.ServerIP) {
			return true, fmt.Sprintf("ServerIP=%s", ctx.ServerIP)
		}
	}

	if m.ServerPort != 0 {
		conditionsChecked++
		if ctx.ServerPort == m.ServerPort {
			return true, fmt.Sprintf("ServerPort=%d", ctx.ServerPort)
		}
	}

	if m.ServerHostname != "" {
		conditionsChecked++
		if strings.EqualFold(ctx.ServerHostname, m.ServerHostname) {
			return true, fmt.Sprintf("Hostname=%s", m.ServerHostname)
		}
	}

	if m.ServerPath != "" {
		conditionsChecked++
		if ctx.ServerPath == m.ServerPath {
			return true, fmt.Sprintf("Path=%s", m.ServerPath)
		}
	}

	// QueryDomain check removed here as it is handled by Trie

	if conditionsChecked == 0 {
		return false, ""
	}

	return false, ""
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

