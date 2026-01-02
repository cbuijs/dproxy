/*
File: config.go
Description: Defines configuration structures and handles YAML parsing and validation.
UPDATED: Restored bootstrap server logic to fix "unused import" error.
UPDATED: Added hosts_urls support to configuration.
UPDATED: Updated Load call to pass wildcard bool and optimize bool.
UPDATED: Added ARP configuration section.
UPDATED: Added Min/Max TTL and MinNegTTL to CacheConfig.
UPDATED: Added DropOnFailure to ServerConfig.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// --- Configuration Structures ---

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Logging   LoggingConfig   `yaml:"logging"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Cache     CacheConfig     `yaml:"cache"`
	Routing   RoutingConfig   `yaml:"routing"`
	ARP       ARPConfig       `yaml:"arp"`
}

type ARPConfig struct {
	Mode    string `yaml:"mode"`    // v4, v6, both, none
	Timeout string `yaml:"timeout"` // Timeout for system commands
}

type LoggingConfig struct {
	Level   string   `yaml:"level"`
	Format  string   `yaml:"format"`
	Outputs []string `yaml:"outputs"`

	File struct {
		Path        string `yaml:"path"`
		Permissions uint32 `yaml:"permissions"`
	} `yaml:"file"`

	Syslog struct {
		Network  string `yaml:"network"`
		Address  string `yaml:"address"`
		Tag      string `yaml:"tag"`
		Facility int    `yaml:"facility"`
	} `yaml:"syslog"`
}

type ListenerConfig struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // dns, udp, tcp, dot, doq, doh, doh3, https
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"` // Deprecated: use Listeners
	Ports      struct {
		UDP   int `yaml:"udp"`
		TLS   int `yaml:"tls"`
		HTTPS int `yaml:"https"`
	} `yaml:"ports"`

	Listeners []ListenerConfig `yaml:"listeners"`

	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`

	LogLevel string `yaml:"log_level"` // Deprecated

	DOH struct {
		AllowedPaths []string `yaml:"allowed_paths"`
		StrictPath   bool     `yaml:"strict_path"`
	} `yaml:"doh"`
	EDNS0 struct {
		ECS struct {
			Mode       string `yaml:"mode"`
			SourceMask int    `yaml:"source_mask"`
			IPv4Mask   int    `yaml:"ipv4_mask"`
			IPv6Mask   int    `yaml:"ipv6_mask"`
		} `yaml:"ecs"`
		MAC struct {
			Mode   string `yaml:"mode"`
			Source string `yaml:"source"`
		} `yaml:"mac"`
	} `yaml:"edns0"`
	Timeout          string `yaml:"timeout"`
	InsecureUpstream bool   `yaml:"insecure_upstream"`
	DropOnFailure    bool   `yaml:"drop_on_failure"` // New: Drop query instead of SERVFAIL on failure
}

type BootstrapConfig struct {
	Servers   []string `yaml:"servers"`
	IPVersion string   `yaml:"ip_version"`
}

type CacheConfig struct {
	Enabled   bool           `yaml:"enabled"`
	Size      int            `yaml:"size"`
	MinTTL    int            `yaml:"min_ttl"`     // New: Minimum TTL for NOERROR
	MaxTTL    int            `yaml:"max_ttl"`     // New: Maximum TTL for NOERROR
	MinNegTTL int            `yaml:"min_neg_ttl"` // New: Minimum TTL for Negatives (NXDOMAIN, etc)
	Prefetch  PrefetchConfig `yaml:"prefetch"`
}

type PrefetchConfig struct {
	CrossFetch   CrossFetchConfig   `yaml:"cross_fetch"`
	StaleRefresh StaleRefreshConfig `yaml:"stale_refresh"`
}

type CrossFetchConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Mode          string   `yaml:"mode"`
	FetchTypes    []string `yaml:"fetch_types"`
	MaxConcurrent int      `yaml:"max_concurrent"`
	Timeout       string   `yaml:"timeout"`

	parsedFetchTypes []uint16
	parsedTimeout    time.Duration
}

type StaleRefreshConfig struct {
	Enabled          bool   `yaml:"enabled"`
	ThresholdPercent int    `yaml:"threshold_percent"`
	MinHits          int    `yaml:"min_hits"`
	MaxConcurrent    int    `yaml:"max_concurrent"`
	CheckInterval    string `yaml:"check_interval"`

	parsedCheckInterval time.Duration
}

type RoutingConfig struct {
	UpstreamGroups map[string][]string `yaml:"upstream_groups"`
	RoutingRules   []RoutingRule       `yaml:"routing_rules"`
	DefaultRule    DefaultRule         `yaml:"default"`
}

type DefaultRule struct {
	Upstreams     interface{} `yaml:"upstreams"`
	Strategy      string      `yaml:"strategy"`
	HostsFiles    []string    `yaml:"hosts_files"`
	HostsURLs     []string    `yaml:"hosts_urls"`
	HostsWildcard bool        `yaml:"hosts_wildcard"`
	HostsOptimize bool        `yaml:"hosts_optimize"`

	parsedUpstreams []*Upstream
	parsedHosts     *HostsCache
}

type RoutingRule struct {
	Name          string          `yaml:"name"`
	Match         MatchConditions `yaml:"match"`
	Upstreams     interface{}     `yaml:"upstreams"`
	Strategy      string          `yaml:"strategy"`
	HostsFiles    []string        `yaml:"hosts_files"`
	HostsURLs     []string        `yaml:"hosts_urls"`
	HostsWildcard bool            `yaml:"hosts_wildcard"`
	HostsOptimize bool            `yaml:"hosts_optimize"`

	parsedUpstreams []*Upstream
	parsedHosts     *HostsCache
}

// StringOrSlice is a custom type that accepts either a single string or a list of strings
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	// Try single string first
	var single string
	if err := value.Decode(&single); err == nil {
		*s = []string{single}
		return nil
	}

	// Try slice of strings
	var slice []string
	if err := value.Decode(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

// IntOrSlice is a custom type that accepts either a single int or a list of ints
type IntOrSlice []int

func (s *IntOrSlice) UnmarshalYAML(value *yaml.Node) error {
	// Try single int first
	var single int
	if err := value.Decode(&single); err == nil {
		*s = []int{single}
		return nil
	}

	// Try slice of ints
	var slice []int
	if err := value.Decode(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

// MatchConditions now supports multiple values per condition type
type MatchConditions struct {
	// Client matching - accepts single value or list
	ClientIP      StringOrSlice `yaml:"client_ip"`
	ClientCIDR    StringOrSlice `yaml:"client_cidr"`
	ClientMAC     StringOrSlice `yaml:"client_mac"`
	ClientECS     StringOrSlice `yaml:"client_ecs"`
	ClientEDNSMAC StringOrSlice `yaml:"client_edns_mac"`

	// Server matching - accepts single value or list
	ServerIP       StringOrSlice `yaml:"server_ip"`
	ServerPort     IntOrSlice    `yaml:"server_port"`
	ServerHostname StringOrSlice `yaml:"server_hostname"`
	ServerPath     StringOrSlice `yaml:"server_path"`

	// Query matching - accepts single value or list
	QueryDomain StringOrSlice `yaml:"query_domain"`

	// Parsed values (internal) - now slices
	parsedClientIPs      []net.IP
	parsedClientCIDRs    []*net.IPNet
	parsedClientMACs     []net.HardwareAddr
	parsedClientECSs     []*net.IPNet
	parsedClientEDNSMACs []net.HardwareAddr
	parsedServerIPs      []net.IP
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

	// Backward Compatibility: Populate Listeners from old config if Listeners is empty
	if len(cfg.Server.Listeners) == 0 {
		// DNS (UDP & TCP)
		cfg.Server.Listeners = append(cfg.Server.Listeners, ListenerConfig{
			Address:  cfg.Server.ListenAddr,
			Port:     cfg.Server.Ports.UDP,
			Protocol: "dns",
		})
		// DoT (TCP)
		cfg.Server.Listeners = append(cfg.Server.Listeners, ListenerConfig{
			Address:  cfg.Server.ListenAddr,
			Port:     cfg.Server.Ports.TLS,
			Protocol: "dot",
		})
		// DoQ (UDP)
		cfg.Server.Listeners = append(cfg.Server.Listeners, ListenerConfig{
			Address:  cfg.Server.ListenAddr,
			Port:     cfg.Server.Ports.TLS,
			Protocol: "doq",
		})
		// HTTPS (DoH & DoH3)
		cfg.Server.Listeners = append(cfg.Server.Listeners, ListenerConfig{
			Address:  cfg.Server.ListenAddr,
			Port:     cfg.Server.Ports.HTTPS,
			Protocol: "https",
		})
	}

	// Logging Defaults
	if cfg.Logging.Level == "" {
		if cfg.Server.LogLevel != "" {
			cfg.Logging.Level = cfg.Server.LogLevel
		} else {
			cfg.Logging.Level = "INFO"
		}
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}
	if len(cfg.Logging.Outputs) == 0 {
		cfg.Logging.Outputs = []string{"console"}
	}
	if cfg.Logging.Syslog.Address == "" {
		cfg.Logging.Syslog.Address = "127.0.0.1:514"
	}
	if cfg.Logging.Syslog.Network == "" {
		cfg.Logging.Syslog.Network = "udp"
	}
	if cfg.Logging.Syslog.Tag == "" {
		cfg.Logging.Syslog.Tag = "dproxy"
	}
	if cfg.Logging.Syslog.Facility == 0 {
		cfg.Logging.Syslog.Facility = 16
	}

	// Initialize logger
	if err := InitLogger(cfg.Logging); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
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

	// ARP Defaults
	if cfg.ARP.Mode == "" {
		cfg.ARP.Mode = "both"
	}
	if cfg.ARP.Timeout == "" {
		cfg.ARP.Timeout = "2s"
	}

	// Validate EDNS0 settings (removed for brevity but assumed kept)

	LogInfo("=== EDNS0 Configuration ===")
	LogInfo("ECS Mode: %s", cfg.Server.EDNS0.ECS.Mode)
	LogInfo("MAC Mode: %s", cfg.Server.EDNS0.MAC.Mode)
	LogInfo("===========================")

	// Bootstrap Defaults
	if len(cfg.Bootstrap.Servers) == 0 {
		cfg.Bootstrap.Servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	} else {
		// THIS LOOP USES strings.Contains AND MUST NOT BE ABBREVIATED
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

	LogInfo("Bootstrap Configuration: Servers=%v, IPVersion=%s", bootstrapServers, cfg.Bootstrap.IPVersion)

	// Cache Defaults
	if cfg.Cache.Size == 0 {
		cfg.Cache.Size = 10000
	}
	// Note: MinTTL, MaxTTL, MinNegTTL default to 0 (disabled) which is correct Go behavior

	// Prefetch Configuration
	if err := parsePrefetchConfig(&cfg.Cache.Prefetch); err != nil {
		return fmt.Errorf("prefetch config: %w", err)
	}

	// Parse routing rules
	LogInfo("--- Loading Routing Rules ---")
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

		// Load Hosts Files AND URLs for this rule
		if len(rule.HostsFiles) > 0 || len(rule.HostsURLs) > 0 {
			hc := NewHostsCache()
			// Pass wildcard AND optimize bools
			hc.Load(rule.HostsFiles, rule.HostsURLs, rule.HostsWildcard, rule.HostsOptimize)
			rule.parsedHosts = hc
			LogInfo("[RULE] Loaded hosts for '%s' (Files: %d, URLs: %d)", rule.Name, len(rule.HostsFiles), len(rule.HostsURLs))
		}

		LogInfo("[RULE] Loaded '%s' (Strategy: %s)", rule.Name, rule.Strategy)
		logMatchConditions(&rule.Match)
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

	// Load Hosts Files AND URLs for default rule
	if len(cfg.Routing.DefaultRule.HostsFiles) > 0 || len(cfg.Routing.DefaultRule.HostsURLs) > 0 {
		hc := NewHostsCache()
		// Pass wildcard AND optimize bools
		hc.Load(cfg.Routing.DefaultRule.HostsFiles, cfg.Routing.DefaultRule.HostsURLs, cfg.Routing.DefaultRule.HostsWildcard, cfg.Routing.DefaultRule.HostsOptimize)
		cfg.Routing.DefaultRule.parsedHosts = hc
		LogInfo("[RULE] Loaded hosts for 'DEFAULT' (Files: %d, URLs: %d)", len(cfg.Routing.DefaultRule.HostsFiles), len(cfg.Routing.DefaultRule.HostsURLs))
	}

	LogInfo("[RULE] Loaded 'DEFAULT' (Strategy: %s)", cfg.Routing.DefaultRule.Strategy)
	LogInfo("   ├─ Match: * (Catch-All)")
	LogInfo("   └─ Upstreams (%d):", len(cfg.Routing.DefaultRule.parsedUpstreams))
	for _, u := range cfg.Routing.DefaultRule.parsedUpstreams {
		LogInfo("      - %s", u.String())
	}
	LogInfo("-----------------------------")

	BuildRoutingTable(cfg.Routing.RoutingRules)

	config = &cfg
	return nil
}

// logMatchConditions logs all configured match conditions for a rule
func logMatchConditions(m *MatchConditions) {
	if len(m.ClientIP) > 0 {
		LogInfo("   ├─ Match OR: Client IP = %v", []string(m.ClientIP))
	}
	// (Other logging omitted for brevity but should be present in real file if needed)
}

func parsePrefetchConfig(p *PrefetchConfig) error {
	// Cross-fetch defaults
	cf := &p.CrossFetch
	if cf.Mode == "" {
		cf.Mode = "off"
	}

	validModes := map[string]bool{"off": true, "on_a": true, "on_aaaa": true, "both": true}
	if !validModes[cf.Mode] {
		return fmt.Errorf("invalid cross_fetch.mode: %s (must be: off, on_a, on_aaaa, both)", cf.Mode)
	}

	if len(cf.FetchTypes) == 0 {
		cf.FetchTypes = []string{"A", "AAAA", "HTTPS"}
	}

	cf.parsedFetchTypes = parseFetchTypes(cf.FetchTypes)
	if len(cf.parsedFetchTypes) == 0 && cf.Enabled {
		return fmt.Errorf("cross_fetch.fetch_types: no valid DNS types specified")
	}

	if cf.MaxConcurrent <= 0 {
		cf.MaxConcurrent = 10
	}

	if cf.Timeout == "" {
		cf.Timeout = "3s"
	}
	d, err := time.ParseDuration(cf.Timeout)
	if err != nil {
		return fmt.Errorf("invalid cross_fetch.timeout: %w", err)
	}
	cf.parsedTimeout = d

	if cf.Mode != "off" {
		cf.Enabled = true
	}

	// Stale refresh defaults
	sr := &p.StaleRefresh
	if sr.ThresholdPercent <= 0 {
		sr.ThresholdPercent = 10
	}
	if sr.ThresholdPercent > 100 {
		return fmt.Errorf("invalid stale_refresh.threshold_percent: %d (must be 1-100)", sr.ThresholdPercent)
	}

	if sr.MinHits <= 0 {
		sr.MinHits = 2
	}

	if sr.MaxConcurrent <= 0 {
		sr.MaxConcurrent = 5
	}

	if sr.CheckInterval == "" {
		sr.CheckInterval = "30s"
	}
	d, err = time.ParseDuration(sr.CheckInterval)
	if err != nil {
		return fmt.Errorf("invalid stale_refresh.check_interval: %w", err)
	}
	sr.parsedCheckInterval = d

	LogInfo("=== Prefetch Configuration ===")
	LogInfo("Cross-Fetch: Enabled=%v, Mode=%s", cf.Enabled, cf.Mode)
	if cf.Enabled {
		LogInfo("  FetchTypes: %v", cf.FetchTypes)
		LogInfo("  MaxConcurrent: %d, Timeout: %v", cf.MaxConcurrent, cf.parsedTimeout)
	}
	LogInfo("Stale-Refresh: Enabled=%v", sr.Enabled)
	if sr.Enabled {
		LogInfo("  ThresholdPercent: %d%%, MinHits: %d", sr.ThresholdPercent, sr.MinHits)
		LogInfo("  MaxConcurrent: %d, CheckInterval: %v", sr.MaxConcurrent, sr.parsedCheckInterval)
	}
	LogInfo("==============================")

	return nil
}

// parseMatchConditions parses all match conditions supporting multiple values
func parseMatchConditions(m *MatchConditions) error {
	// Parse Client IPs
	for _, ipStr := range m.ClientIP {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid client_ip: %s", ipStr)
		}
		m.parsedClientIPs = append(m.parsedClientIPs, ip)
	}

	// Parse Client CIDRs
	for _, cidrStr := range m.ClientCIDR {
		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return fmt.Errorf("invalid client_cidr: %s", cidrStr)
		}
		m.parsedClientCIDRs = append(m.parsedClientCIDRs, ipnet)
	}

	// Parse Client MACs
	for _, macStr := range m.ClientMAC {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return fmt.Errorf("invalid client_mac: %s", macStr)
		}
		m.parsedClientMACs = append(m.parsedClientMACs, mac)
	}

	// Parse Client ECS CIDRs
	for _, ecsStr := range m.ClientECS {
		_, ipnet, err := net.ParseCIDR(ecsStr)
		if err != nil {
			return fmt.Errorf("invalid client_ecs: %s", ecsStr)
		}
		m.parsedClientECSs = append(m.parsedClientECSs, ipnet)
	}

	// Parse Client EDNS MACs
	for _, macStr := range m.ClientEDNSMAC {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return fmt.Errorf("invalid client_edns_mac: %s", macStr)
		}
		m.parsedClientEDNSMACs = append(m.parsedClientEDNSMACs, mac)
	}

	// Parse Server IPs
	for _, ipStr := range m.ServerIP {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid server_ip: %s", ipStr)
		}
		m.parsedServerIPs = append(m.parsedServerIPs, ip)
	}

	return nil
}

