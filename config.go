/*
File: config.go
Description: Defines configuration structures and handles YAML parsing and validation.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// --- Configuration Structures ---

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Cache     CacheConfig     `yaml:"cache"`
	Routing   RoutingConfig   `yaml:"routing"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Ports      struct {
		UDP   int `yaml:"udp"`
		TLS   int `yaml:"tls"`
		HTTPS int `yaml:"https"`
	} `yaml:"ports"`
	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	DOH struct {
		AllowedPaths []string `yaml:"allowed_paths"`
		StrictPath   bool     `yaml:"strict_path"`
	} `yaml:"doh"`
	EDNS0 struct {
		ECS struct {
			Mode       string `yaml:"mode"`         // "preserve", "add", "replace", "remove"
			SourceMask int    `yaml:"source_mask"`  // Override mask bits for both IPv4/IPv6 (0 = auto)
			IPv4Mask   int    `yaml:"ipv4_mask"`    // Override mask for IPv4 only (0 = use source_mask)
			IPv6Mask   int    `yaml:"ipv6_mask"`    // Override mask for IPv6 only (0 = use source_mask)
		} `yaml:"ecs"`
		MAC struct {
			Mode   string `yaml:"mode"`   // "preserve", "add", "replace", "remove", "prefer-edns0", "prefer-arp"
			Source string `yaml:"source"` // "arp", "edns0", "both"
		} `yaml:"mac"`
	} `yaml:"edns0"`
	Timeout          string `yaml:"timeout"`
	InsecureUpstream bool   `yaml:"insecure_upstream"`
}

type BootstrapConfig struct {
	Servers   []string `yaml:"servers"`
	IPVersion string   `yaml:"ip_version"`
}

type CacheConfig struct {
	Enabled bool `yaml:"enabled"`
	Size    int  `yaml:"size"`
}

type RoutingConfig struct {
	UpstreamGroups map[string][]string `yaml:"upstream_groups"`
	RoutingRules   []RoutingRule       `yaml:"routing_rules"`
	DefaultRule    DefaultRule         `yaml:"default"`
}

type DefaultRule struct {
	Upstreams interface{} `yaml:"upstreams"`
	Strategy  string      `yaml:"strategy"`

	parsedUpstreams []*Upstream
}

type RoutingRule struct {
	Name            string          `yaml:"name"`
	Match           MatchConditions `yaml:"match"`
	Upstreams       interface{}     `yaml:"upstreams"`
	Strategy        string          `yaml:"strategy"`
	parsedUpstreams []*Upstream
}

type MatchConditions struct {
	ClientIP       string `yaml:"client_ip"`
	ClientCIDR     string `yaml:"client_cidr"`
	ClientMAC      string `yaml:"client_mac"`
	ClientECS      string `yaml:"client_ecs"`
	ClientEDNSMAC  string `yaml:"client_edns_mac"`
	ServerIP       string `yaml:"server_ip"`
	ServerPort     int    `yaml:"server_port"`
	ServerHostname string `yaml:"server_hostname"`
	ServerPath     string `yaml:"server_path"`
	QueryDomain    string `yaml:"query_domain"`

	parsedClientIP      net.IP
	parsedClientCIDR    *net.IPNet
	parsedClientMAC     net.HardwareAddr
	parsedClientECS     *net.IPNet
	parsedClientEDNSMAC net.HardwareAddr
	parsedServerIP      net.IP
}

// --- Configuration Loading ---

func LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = "0.0.0.0"
	}
	if cfg.Server.Ports.UDP == 0 {
		cfg.Server.Ports.UDP = 53
	}
	if cfg.Server.Ports.TLS == 0 {
		cfg.Server.Ports.TLS = 853
	}
	if cfg.Server.Ports.HTTPS == 0 {
		cfg.Server.Ports.HTTPS = 443
	}

	// DoH Defaults
	if len(cfg.Server.DOH.AllowedPaths) == 0 {
		cfg.Server.DOH.AllowedPaths = []string{"/dns-query"}
	}

	// EDNS0 Defaults
	if cfg.Server.EDNS0.ECS.Mode == "" {
		cfg.Server.EDNS0.ECS.Mode = "add"
	}
	if cfg.Server.EDNS0.MAC.Mode == "" {
		cfg.Server.EDNS0.MAC.Mode = "prefer-arp"
	}
	if cfg.Server.EDNS0.MAC.Source == "" {
		cfg.Server.EDNS0.MAC.Source = "arp"
	}

	// Validate EDNS0 ECS mode
	validECSModes := map[string]bool{"preserve": true, "add": true, "replace": true, "remove": true}
	if !validECSModes[cfg.Server.EDNS0.ECS.Mode] {
		return fmt.Errorf("invalid edns0.ecs.mode: %s (must be: preserve, add, replace, or remove)", cfg.Server.EDNS0.ECS.Mode)
	}

	// Validate EDNS0 MAC mode
	validMACModes := map[string]bool{"preserve": true, "add": true, "replace": true, "remove": true, "prefer-edns0": true, "prefer-arp": true}
	if !validMACModes[cfg.Server.EDNS0.MAC.Mode] {
		return fmt.Errorf("invalid edns0.mac.mode: %s (must be: preserve, add, replace, remove, prefer-edns0, or prefer-arp)", cfg.Server.EDNS0.MAC.Mode)
	}

	// Validate EDNS0 MAC source
	validMACSources := map[string]bool{"arp": true, "edns0": true, "both": true}
	if !validMACSources[cfg.Server.EDNS0.MAC.Source] {
		return fmt.Errorf("invalid edns0.mac.source: %s (must be: arp, edns0, or both)", cfg.Server.EDNS0.MAC.Source)
	}

	// Validate ECS mask values
	if cfg.Server.EDNS0.ECS.SourceMask < 0 || cfg.Server.EDNS0.ECS.SourceMask > 128 {
		return fmt.Errorf("invalid edns0.ecs.source_mask: %d (must be 0-128)", cfg.Server.EDNS0.ECS.SourceMask)
	}
	if cfg.Server.EDNS0.ECS.IPv4Mask < 0 || cfg.Server.EDNS0.ECS.IPv4Mask > 32 {
		return fmt.Errorf("invalid edns0.ecs.ipv4_mask: %d (must be 0-32)", cfg.Server.EDNS0.ECS.IPv4Mask)
	}
	if cfg.Server.EDNS0.ECS.IPv6Mask < 0 || cfg.Server.EDNS0.ECS.IPv6Mask > 128 {
		return fmt.Errorf("invalid edns0.ecs.ipv6_mask: %d (must be 0-128)", cfg.Server.EDNS0.ECS.IPv6Mask)
	}

	// Log EDNS0 configuration
	log.Println("=== EDNS0 Configuration ===")
	log.Printf("ECS Mode: %s", cfg.Server.EDNS0.ECS.Mode)
	if cfg.Server.EDNS0.ECS.SourceMask > 0 {
		log.Printf("ECS Source Mask (both): /%d", cfg.Server.EDNS0.ECS.SourceMask)
	}
	if cfg.Server.EDNS0.ECS.IPv4Mask > 0 {
		log.Printf("ECS IPv4 Mask: /%d", cfg.Server.EDNS0.ECS.IPv4Mask)
	}
	if cfg.Server.EDNS0.ECS.IPv6Mask > 0 {
		log.Printf("ECS IPv6 Mask: /%d", cfg.Server.EDNS0.ECS.IPv6Mask)
	}
	log.Printf("MAC Mode: %s", cfg.Server.EDNS0.MAC.Mode)
	log.Printf("MAC Source: %s", cfg.Server.EDNS0.MAC.Source)
	log.Println("===========================")

	// Bootstrap Defaults
	if len(cfg.Bootstrap.Servers) == 0 {
		cfg.Bootstrap.Servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	} else {
		for i, bs := range cfg.Bootstrap.Servers {
			if !strings.Contains(bs, ":") {
				cfg.Bootstrap.Servers[i] = bs + ":53"
			}
		}
	}
	if cfg.Bootstrap.IPVersion == "" {
		cfg.Bootstrap.IPVersion = "both"
	}
	bootstrapServers = cfg.Bootstrap.Servers

	if cfg.Cache.Size == 0 {
		cfg.Cache.Size = 10000
	}

	// Parse routing rules
	log.Println("--- Loading Routing Rules ---")
	for i := range cfg.Routing.RoutingRules {
		rule := &cfg.Routing.RoutingRules[i]

		if err := parseMatchConditions(&rule.Match); err != nil {
			return fmt.Errorf("rule '%s': %w", rule.Name, err)
		}

		upstreamURLs, err := resolveUpstreams(rule.Upstreams, cfg.Routing.UpstreamGroups)
		if err != nil {
			return fmt.Errorf("rule '%s': %w", rule.Name, err)
		}

		for _, urlStr := range upstreamURLs {
			upstream, err := parseUpstream(urlStr, cfg.Bootstrap.IPVersion, cfg.Server.InsecureUpstream, cfg.Server.Timeout)
			if err != nil {
				return fmt.Errorf("rule '%s': invalid upstream %s: %w", rule.Name, urlStr, err)
			}
			rule.parsedUpstreams = append(rule.parsedUpstreams, upstream)
		}

		if len(rule.parsedUpstreams) == 0 {
			return fmt.Errorf("rule '%s': no valid upstreams", rule.Name)
		}

		if rule.Strategy == "" {
			rule.Strategy = "failover"
		}

		// --- Detailed Logging of Loaded Rules ---
		log.Printf("[RULE] Loaded '%s' (Strategy: %s)", rule.Name, rule.Strategy)
		m := rule.Match
		if m.ClientIP != "" {
			log.Printf("   ├─ Match OR: Client IP = %s", m.ClientIP)
		}
		if m.ClientCIDR != "" {
			log.Printf("   ├─ Match OR: Client CIDR = %s", m.ClientCIDR)
		}
		if m.ClientMAC != "" {
			log.Printf("   ├─ Match OR: Client MAC = %s", m.ClientMAC)
		}
		if m.ClientECS != "" {
			log.Printf("   ├─ Match OR: Client ECS = %s", m.ClientECS)
		}
		if m.ClientEDNSMAC != "" {
			log.Printf("   ├─ Match OR: Client EDNS0 MAC = %s", m.ClientEDNSMAC)
		}
		if m.ServerIP != "" {
			log.Printf("   ├─ Match OR: Server IP = %s", m.ServerIP)
		}
		if m.ServerPort != 0 {
			log.Printf("   ├─ Match OR: Server Port = %d", m.ServerPort)
		}
		if m.ServerHostname != "" {
			log.Printf("   ├─ Match OR: Hostname = %s", m.ServerHostname)
		}
		if m.ServerPath != "" {
			log.Printf("   ├─ Match OR: Path = %s", m.ServerPath)
		}
		if m.QueryDomain != "" {
			log.Printf("   ├─ Match OR: Query Domain = %s", m.QueryDomain)
		}

		log.Printf("   └─ Upstreams (%d):", len(rule.parsedUpstreams))
		for _, u := range rule.parsedUpstreams {
			log.Printf("      - %s", u.String())
		}
	}

	// Parse default rule
	if cfg.Routing.DefaultRule.Upstreams == nil {
		return fmt.Errorf("default upstreams are required")
	}

	upstreamURLs, err := resolveUpstreams(cfg.Routing.DefaultRule.Upstreams, cfg.Routing.UpstreamGroups)
	if err != nil {
		return fmt.Errorf("default: %w", err)
	}

	for _, urlStr := range upstreamURLs {
		upstream, err := parseUpstream(urlStr, cfg.Bootstrap.IPVersion, cfg.Server.InsecureUpstream, cfg.Server.Timeout)
		if err != nil {
			return fmt.Errorf("default: invalid upstream %s: %w", urlStr, err)
		}
		cfg.Routing.DefaultRule.parsedUpstreams = append(cfg.Routing.DefaultRule.parsedUpstreams, upstream)
	}

	if len(cfg.Routing.DefaultRule.parsedUpstreams) == 0 {
		return fmt.Errorf("default: no valid upstreams")
	}

	if cfg.Routing.DefaultRule.Strategy == "" {
		cfg.Routing.DefaultRule.Strategy = "failover"
	}

	// --- Log Default Rule ---
	log.Printf("[RULE] Loaded 'DEFAULT' (Strategy: %s)", cfg.Routing.DefaultRule.Strategy)
	log.Printf("   ├─ Match: * (Catch-All)")
	log.Printf("   └─ Upstreams (%d):", len(cfg.Routing.DefaultRule.parsedUpstreams))
	for _, u := range cfg.Routing.DefaultRule.parsedUpstreams {
		log.Printf("      - %s", u.String())
	}
	log.Println("-----------------------------")

	config = &cfg
	return nil
}

func parseMatchConditions(m *MatchConditions) error {
	if m.ClientIP != "" {
		ip := net.ParseIP(m.ClientIP)
		if ip == nil {
			return fmt.Errorf("invalid client_ip: %s", m.ClientIP)
		}
		m.parsedClientIP = ip
	}

	if m.ClientCIDR != "" {
		_, ipnet, err := net.ParseCIDR(m.ClientCIDR)
		if err != nil {
			return fmt.Errorf("invalid client_cidr: %s", m.ClientCIDR)
		}
		m.parsedClientCIDR = ipnet
	}

	if m.ClientMAC != "" {
		mac, err := net.ParseMAC(m.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client_mac: %s", m.ClientMAC)
		}
		m.parsedClientMAC = mac
	}

	if m.ClientECS != "" {
		_, ipnet, err := net.ParseCIDR(m.ClientECS)
		if err != nil {
			return fmt.Errorf("invalid client_ecs: %s", m.ClientECS)
		}
		m.parsedClientECS = ipnet
	}

	if m.ClientEDNSMAC != "" {
		mac, err := net.ParseMAC(m.ClientEDNSMAC)
		if err != nil {
			return fmt.Errorf("invalid client_edns_mac: %s", m.ClientEDNSMAC)
		}
		m.parsedClientEDNSMAC = mac
	}

	if m.ServerIP != "" {
		ip := net.ParseIP(m.ServerIP)
		if ip == nil {
			return fmt.Errorf("invalid server_ip: %s", m.ServerIP)
		}
		m.parsedServerIP = ip
	}

	return nil
}

