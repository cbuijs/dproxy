/*
File: config.go
Version: 3.16.1 (Nil Fix)
Description: Deduplicated rule assembly logic with full struct definitions.
             FIXED: Added nil checks and error handling when parsing upstreams to prevent
             nil pointers from entering the routing table.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	MLGuard   MLGuardConfig   `yaml:"ml_guard"`
}

type MLGuardConfig struct {
	Enabled       bool    `yaml:"enabled"`
	Threshold     float64 `yaml:"threshold"`      // 0.0 to 1.0
	AutoThreshold string  `yaml:"auto_threshold"` // "off", "startup", "on"
	MinLength     int     `yaml:"min_length"`     // Minimum domain length
	StateFile     string  `yaml:"state_file"`     // Path to save/load dynamic threshold state
	SaveInterval  string  `yaml:"save_interval"`  // How often to save state (default "30m")

	// Tranco Integration
	TrancoFile string `yaml:"tranco_file"`  // Path to Tranco/Top-1M CSV file
	TrancoTopN int    `yaml:"tranco_top_n"` // Limit training to top N domains (0 = all)

	parsedSaveInterval time.Duration
}

type RateLimitConfig struct {
	Enabled             bool   `yaml:"enabled"`
	ClientQPS           int    `yaml:"client_qps"`
	ClientBurst         int    `yaml:"client_burst"`
	MaxGoroutines       int    `yaml:"max_goroutines"`
	HardMaxGoroutines   int    `yaml:"hard_max_goroutines"`
	BaseDelay           string `yaml:"base_delay"`
	MaxDelay            string `yaml:"max_delay"`
	CleanupInterval     string `yaml:"cleanup_interval"`
	ClientExpiration    string `yaml:"client_expiration"`

	parsedBaseDelay        time.Duration
	parsedMaxDelay         time.Duration
	parsedCleanupInterval  time.Duration
	parsedClientExpiration time.Duration
}

type ARPConfig struct {
	Mode    string `yaml:"mode"`
	Timeout string `yaml:"timeout"`
}

type LoggingConfig struct {
	Level         string   `yaml:"level"`
	Format        string   `yaml:"format"`
	Mode          string   `yaml:"mode"` // "full" (default) or "compact"
	Outputs       []string `yaml:"outputs"`
	LogClientName bool     `yaml:"log_client_name"`

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
	Address  StringOrSlice `yaml:"address"`
	Port     IntOrSlice    `yaml:"port"`
	Protocol string        `yaml:"protocol"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
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

	LogLevel string `yaml:"log_level"`

	DDR struct {
		Enabled       bool   `yaml:"enabled"`
		HostName      string `yaml:"host_name"`
		SpoofHostname bool   `yaml:"spoof_hostname"` // New: Intercept A/AAAA for HostName
	} `yaml:"ddr"`

	DOH struct {
		AllowedPaths     []string `yaml:"allowed_paths"`
		StrictPath       bool     `yaml:"strict_path"`
		MismatchBehavior string   `yaml:"mismatch_behavior"`
		MismatchBackoff  string   `yaml:"mismatch_backoff"` // Delay before drop/404
		MismatchText     string   `yaml:"mismatch_text"`    // Custom text for error response
		RobotsTxt        bool     `yaml:"robots_txt"`       // Enable /robots.txt handler

		parsedMismatchBackoff time.Duration
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
	DropOnFailure    bool   `yaml:"drop_on_failure"`

	Response struct {
		Minimization    bool   `yaml:"minimization"`
		CNAMEFlattening bool   `yaml:"cname_flattening"`
		PTRMode         string `yaml:"ptr_mode"` // "off" (default) or "strict"
	} `yaml:"response"`
}

type BootstrapConfig struct {
	Servers   []string `yaml:"servers"`
	IPVersion string   `yaml:"ip_version"`
}

type CacheConfig struct {
	Enabled             bool           `yaml:"enabled"`
	Size                int            `yaml:"size"`
	HostsCacheDir       string         `yaml:"hosts_cache_dir"`
	MinTTL              int            `yaml:"min_ttl"`
	MaxTTL              int            `yaml:"max_ttl"`
	MinNegTTL           int            `yaml:"min_neg_ttl"`
	MaxNegTTL           int            `yaml:"max_neg_ttl"`
	HostsTTL            int            `yaml:"hosts_ttl"`
	TTLStrategy         string         `yaml:"ttl_strategy"`
	ResponseSorting     string         `yaml:"response_sorting"`
	HardenBelowNXDOMAIN bool           `yaml:"harden_below_nxdomain"`
	Prefetch            PrefetchConfig `yaml:"prefetch"`
}

type PrefetchConfig struct {
	Predictive   PredictiveConfig   `yaml:"predictive"`
	StaleRefresh StaleRefreshConfig `yaml:"stale_refresh"`
	LoadShedding LoadSheddingConfig `yaml:"load_shedding"`
}

type LoadSheddingConfig struct {
	Enabled          bool `yaml:"enabled"`
	MaxGoroutines    int  `yaml:"max_goroutines"`
	MaxQueueUsagePct int  `yaml:"max_queue_usage_pct"`
}

type PredictiveConfig struct {
	Enabled        bool    `yaml:"enabled"`
	Threshold      float64 `yaml:"threshold"`
	MaxMemory      int     `yaml:"max_memory"`
	LearningWindow string  `yaml:"learning_window"`
	MaxConcurrent  int     `yaml:"max_concurrent"`
	Timeout        string  `yaml:"timeout"`

	parsedWindow  time.Duration
	parsedTimeout time.Duration
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
	Upstreams         interface{}   `yaml:"upstreams"`
	Strategy          string        `yaml:"strategy"`
	HostsFiles        []string      `yaml:"hosts_files"`
	HostsURLs         []string      `yaml:"hosts_urls"`
	HostFilesSingular []string      `yaml:"host_files"`
	HostURLsSingular  []string      `yaml:"host_urls"`
	HostsWildcard     bool          `yaml:"hosts_wildcard"`
	HostsOptimize     bool          `yaml:"hosts_optimize"`
	HostsOptimizeTLD  bool          `yaml:"hosts_optimize_tld"`
	HostsResponses    bool          `yaml:"hosts_responses"`
	RefreshInterval   string        `yaml:"refresh_interval"`
	MLGuardMode       string        `yaml:"ml_guard_mode"`
	SafeSearch        string        `yaml:"safe_search"` // "none", "moderate", "full"
	parsedUpstreams   []*Upstream
	parsedHosts       *HostsCache
	parsedRefresh     time.Duration
}

type RoutingRule struct {
	Name              string          `yaml:"name"`
	Match             MatchConditions `yaml:"match"`
	Upstreams         interface{}     `yaml:"upstreams"`
	Strategy          string          `yaml:"strategy"`
	HostsFiles        []string        `yaml:"hosts_files"`
	HostsURLs         []string        `yaml:"hosts_urls"`
	HostFilesSingular []string        `yaml:"host_files"`
	HostURLsSingular  []string        `yaml:"host_urls"`
	HostsWildcard     bool            `yaml:"hosts_wildcard"`
	HostsOptimize     bool            `yaml:"hosts_optimize"`
	HostsOptimizeTLD  bool            `yaml:"hosts_optimize_tld"`
	HostsResponses    bool            `yaml:"hosts_responses"`
	RefreshInterval   string          `yaml:"refresh_interval"`
	MLGuardMode       string          `yaml:"ml_guard_mode"`
	SafeSearch        string          `yaml:"safe_search"` // "none", "moderate", "full"
	parsedUpstreams   []*Upstream
	parsedHosts       *HostsCache
	parsedRefresh     time.Duration
}

type StringOrSlice []string

func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	var single string
	if err := value.Decode(&single); err == nil {
		*s = []string{single}
		return nil
	}
	var slice []string
	if err := value.Decode(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

type IntOrSlice []int

func (s *IntOrSlice) UnmarshalYAML(value *yaml.Node) error {
	var single int
	if err := value.Decode(&single); err == nil {
		*s = []int{single}
		return nil
	}
	var slice []int
	if err := value.Decode(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

type MatchConditions struct {
	ClientIP      StringOrSlice `yaml:"client_ip"`
	ClientCIDR    StringOrSlice `yaml:"client_cidr"`
	ClientMAC     StringOrSlice `yaml:"client_mac"`
	ClientECS     StringOrSlice `yaml:"client_ecs"`
	ClientEDNSMAC StringOrSlice `yaml:"client_edns_mac"`
	ServerIP       StringOrSlice `yaml:"server_ip"`
	ServerPort     IntOrSlice    `yaml:"server_port"`
	ServerHostname StringOrSlice `yaml:"server_hostname"`
	ServerPath     StringOrSlice `yaml:"server_path"`
	QueryDomain    StringOrSlice `yaml:"query_domain"`

	parsedClientIPs      []net.IP
	parsedClientCIDRs    []*net.IPNet
	parsedClientMACs     []net.HardwareAddr
	parsedClientECSs     []*net.IPNet
	parsedClientEDNSMACs []net.HardwareAddr
	parsedServerIPs      []net.IP
	rawClientMACs     []string
	rawClientEDNSMACs []string
}

// --- Configuration Loading ---

func LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil { return fmt.Errorf("failed to read config: %w", err) }

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil { return fmt.Errorf("failed to parse config: %w", err) }

	// Set defaults
	if cfg.Server.ListenAddr == "" { cfg.Server.ListenAddr = "0.0.0.0" }
	if cfg.Server.Ports.UDP == 0 { cfg.Server.Ports.UDP = 53 }
	if len(cfg.Server.Listeners) == 0 {
		cfg.Server.Listeners = append(cfg.Server.Listeners, ListenerConfig{Address: StringOrSlice{cfg.Server.ListenAddr}, Port: IntOrSlice{cfg.Server.Ports.UDP}, Protocol: "dns"})
	}
	if cfg.Logging.Level == "" { cfg.Logging.Level = "INFO" }
	if cfg.Logging.Mode == "" { cfg.Logging.Mode = "full" } 
	if len(cfg.Logging.Outputs) == 0 { cfg.Logging.Outputs = []string{"console"} }

	// Parse DoH Mismatch Backoff
	if cfg.Server.DOH.MismatchBackoff != "" {
		d, err := time.ParseDuration(cfg.Server.DOH.MismatchBackoff)
		if err == nil {
			cfg.Server.DOH.parsedMismatchBackoff = d
		} else {
			LogWarn("[CONFIG] Invalid doh.mismatch_backoff '%s', defaulting to 0", cfg.Server.DOH.MismatchBackoff)
		}
	}

	// Initialize Logger
	if err := InitLogger(cfg.Logging); err != nil { return fmt.Errorf("failed to initialize logger: %w", err) }

	// ML Guard
	if cfg.MLGuard.Enabled {
		if cfg.MLGuard.Threshold <= 0 { cfg.MLGuard.Threshold = 0.90 }
		if cfg.MLGuard.MinLength <= 0 { cfg.MLGuard.MinLength = 6 }
		if cfg.MLGuard.AutoThreshold == "" { cfg.MLGuard.AutoThreshold = "off" }
		if cfg.MLGuard.SaveInterval == "" { cfg.MLGuard.SaveInterval = "30m" }
		dur, err := time.ParseDuration(cfg.MLGuard.SaveInterval)
		if err != nil {
			LogWarn("[CONFIG] Invalid ML Guard save_interval '%s', defaulting to 30m", cfg.MLGuard.SaveInterval)
			dur = 30 * time.Minute
		}
		cfg.MLGuard.parsedSaveInterval = dur
		InitMLGuard(cfg.MLGuard)
	}

	// Normalization: Merge singular host fields into plural fields
	for i := range cfg.Routing.RoutingRules {
		r := &cfg.Routing.RoutingRules[i]
		if len(r.HostFilesSingular) > 0 {
			r.HostsFiles = append(r.HostsFiles, r.HostFilesSingular...)
		}
		if len(r.HostURLsSingular) > 0 {
			r.HostsURLs = append(r.HostsURLs, r.HostURLsSingular...)
		}
	}
	// Normalization for Default Rule
	if len(cfg.Routing.DefaultRule.HostFilesSingular) > 0 {
		cfg.Routing.DefaultRule.HostsFiles = append(cfg.Routing.DefaultRule.HostsFiles, cfg.Routing.DefaultRule.HostFilesSingular...)
	}
	if len(cfg.Routing.DefaultRule.HostURLsSingular) > 0 {
		cfg.Routing.DefaultRule.HostsURLs = append(cfg.Routing.DefaultRule.HostsURLs, cfg.Routing.DefaultRule.HostURLsSingular...)
	}

	bootstrapServers = cfg.Bootstrap.Servers

	// Load Hosts Sources
	uniquePaths, uniqueUrls := collectSources(&cfg)
	sourceCache := BatchLoadSources(uniquePaths, uniqueUrls, cfg.Cache.HostsCacheDir)

	if cfg.MLGuard.Enabled {
		GlobalMLGuard.TrainFromCache(sourceCache)
	}

	// Assemble Rules
	var wg sync.WaitGroup
	
	// Helper to assemble any rule type
	assemble := func(ruleName string, match *MatchConditions, upstreams interface{}, 
		strategy string, hostsFiles, hostsUrls []string, 
		hostsWildcard, hostsOpt, hostsOptTLD, hostsResp bool, safeSearch string,
		outUpstreams *[]*Upstream, outHosts **HostsCache) {
		
		if ruleName != "DEFAULT" && match != nil {
			parseMatchConditions(match)
		}

		uList, _ := resolveUpstreams(upstreams, cfg.Routing.UpstreamGroups)
		for _, u := range uList {
			up, err := parseUpstream(u, cfg.Bootstrap.IPVersion, cfg.Server.InsecureUpstream, cfg.Server.Timeout)
			if err != nil {
				LogWarn("[CONFIG] Error parsing upstream '%s' for rule '%s': %v. Skipping.", u, ruleName, err)
				continue
			}
			if up != nil {
				*outUpstreams = append(*outUpstreams, up)
			}
		}

		if len(hostsFiles) > 0 || len(hostsUrls) > 0 || safeSearch != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hc := NewHostsCache()
				hc.SetTTL(uint32(cfg.Cache.HostsTTL))
				hc.LoadFromCache(hostsFiles, hostsUrls, sourceCache, hostsWildcard, hostsOpt, hostsOptTLD, hostsResp)
				if safeSearch != "" { hc.LoadSafeSearch(safeSearch) }
				*outHosts = hc
			}()
		}
	}

	// Assemble Custom Rules
	for i := range cfg.Routing.RoutingRules {
		r := &cfg.Routing.RoutingRules[i]
		if r.RefreshInterval != "" {
			r.parsedRefresh, _ = time.ParseDuration(r.RefreshInterval)
		}
		assemble(r.Name, &r.Match, r.Upstreams, r.Strategy, r.HostsFiles, r.HostsURLs,
			r.HostsWildcard, r.HostsOptimize, r.HostsOptimizeTLD, r.HostsResponses, r.SafeSearch,
			&r.parsedUpstreams, &r.parsedHosts)
	}

	// Assemble Default Rule
	d := &cfg.Routing.DefaultRule
	if d.RefreshInterval != "" {
		d.parsedRefresh, _ = time.ParseDuration(d.RefreshInterval)
	}
	assemble("DEFAULT", nil, d.Upstreams, d.Strategy, d.HostsFiles, d.HostsURLs,
		d.HostsWildcard, d.HostsOptimize, d.HostsOptimizeTLD, d.HostsResponses, d.SafeSearch,
		&d.parsedUpstreams, &d.parsedHosts)

	wg.Wait()
	BuildRoutingTable(cfg.Routing.RoutingRules)

	config = &cfg
	return nil
}

func collectSources(cfg *Config) ([]string, []string) {
	pMap := make(map[string]bool)
	uMap := make(map[string]bool)
	var paths, urls []string

	add := func(fs, us []string) {
		for _, f := range fs { if !pMap[f] { pMap[f]=true; paths=append(paths, f) } }
		for _, u := range us { if !uMap[u] { uMap[u]=true; urls=append(urls, u) } }
	}

	for _, r := range cfg.Routing.RoutingRules {
		add(r.HostsFiles, r.HostsURLs)
		add(r.HostFilesSingular, r.HostURLsSingular)
	}
	d := cfg.Routing.DefaultRule
	add(d.HostsFiles, d.HostsURLs)
	add(d.HostFilesSingular, d.HostURLsSingular)
	
	return paths, urls
}

func parseMatchConditions(m *MatchConditions) error {
	for _, ipStr := range m.ClientIP { m.parsedClientIPs = append(m.parsedClientIPs, net.ParseIP(ipStr)) }
	for _, cidrStr := range m.ClientCIDR { _, ipnet, _ := net.ParseCIDR(cidrStr); m.parsedClientCIDRs = append(m.parsedClientCIDRs, ipnet) }
	for _, macStr := range m.ClientMAC {
		if strings.ContainsAny(macStr, "*?") { m.rawClientMACs = append(m.rawClientMACs, strings.ToLower(macStr))
		} else { mac, _ := net.ParseMAC(macStr); m.parsedClientMACs = append(m.parsedClientMACs, mac) }
	}
	for _, ecsStr := range m.ClientECS { _, ipnet, _ := net.ParseCIDR(ecsStr); m.parsedClientECSs = append(m.parsedClientECSs, ipnet) }
	for _, macStr := range m.ClientEDNSMAC {
		if strings.ContainsAny(macStr, "*?") { m.rawClientEDNSMACs = append(m.rawClientEDNSMACs, strings.ToLower(macStr))
		} else { mac, _ := net.ParseMAC(macStr); m.parsedClientEDNSMACs = append(m.parsedClientEDNSMACs, mac) }
	}
	for _, ipStr := range m.ServerIP { m.parsedServerIPs = append(m.parsedServerIPs, net.ParseIP(ipStr)) }
	return nil
}

// resolveUpstreams handles normal groups + BLOCK/DROP keywords
func resolveUpstreams(upstreams interface{}, groups map[string][]string) ([]string, error) {
	switch v := upstreams.(type) {
	case string:
		upper := strings.ToUpper(v)
		if upper == "BLOCK" || upper == "DROP" {
			return []string{upper}, nil
		}
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

