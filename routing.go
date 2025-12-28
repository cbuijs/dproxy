/*
File: routing.go
Description: Logic for evaluating routing rules against request context and selecting the appropriate upstream group.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

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

func SelectUpstreams(ctx *RequestContext) ([]*Upstream, string) {
	if config == nil || config.Routing.RoutingRules == nil {
		log.Fatal("Config not loaded - this should never happen")
		return nil, ""
	}

	for _, rule := range config.Routing.RoutingRules {
		matched, reason := matchRule(&rule.Match, ctx)
		if matched {
			log.Printf("[ROUTING] HIT Rule: '%s' | Trigger: %s | Client: %s",
				rule.Name, reason, ctx.ClientIP)
			return rule.parsedUpstreams, rule.Strategy
		}
	}

	return config.Routing.DefaultRule.parsedUpstreams, config.Routing.DefaultRule.Strategy
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

	if m.QueryDomain != "" {
		conditionsChecked++
		ruleDom := strings.ToLower(m.QueryDomain)
		qDom := ctx.QueryName

		match := false
		if strings.HasPrefix(ruleDom, "*.") {
			base := ruleDom[2:]
			if strings.HasSuffix(qDom, "."+base) {
				match = true
			}
		} else if strings.HasPrefix(ruleDom, ".") {
			base := ruleDom[1:]
			if qDom == base || strings.HasSuffix(qDom, "."+base) {
				match = true
			}
		} else {
			if qDom == ruleDom {
				match = true
			}
		}

		if match {
			return true, fmt.Sprintf("QueryDomain=%s", m.QueryDomain)
		}
	}

	if conditionsChecked == 0 {
		return true, "NoConditions/MatchAll"
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

