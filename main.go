/*
File: main.go
Version: 2.6.0
Author: Chris Buijs (2025), Refactored with OR-logic routing, enhanced logging, Stub-Resolver Optimization, and Configurable DoH Paths
Description: A high-performance, multi-protocol DNS Proxy supporting UDP, TCP, DoT, DoH, DoH3, and DoQ upstreams.
             Features client-aware routing, domain-based routing, response stripping for stub-resolvers, and flexible DoH path validation.
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"gopkg.in/yaml.v3"
)

// --- Configuration & Flags ---

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	configFile    = flag.String("config", "", "Path to configuration file (YAML)")
	ipVersion     = flag.String("ip", "both", "IP version to use for bootstrap (ipv4, ipv6, both)")
	cacheDisabled = flag.Bool("no-cache", false, "Disable DNS caching")
	queryTimeout  = flag.Duration("timeout", 5*time.Second, "Global query timeout")
)

const EDNS0_OPTION_MAC = 65001

// --- Globals & Pools ---

var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}

var (
	windowsARPRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})`)
	darwinARPRegex  = regexp.MustCompile(`\((.*?)\) at ([0-9a-fA-F:]+)`)
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

type RequestContext struct {
	ClientIP       net.IP
	ClientMAC      net.HardwareAddr
	ClientECS      net.IP
	ClientECSNet   *net.IPNet
	ClientEDNSMAC  net.HardwareAddr
	ServerIP       net.IP
	ServerPort     int
	ServerHostname string
	ServerPath     string
	QueryName      string
	Protocol       string
}

// --- Upstream Structures ---

type Upstream struct {
	URL         *url.URL
	Proto       string
	Host        string
	Port        string
	BootstrapIP string
	Path        string
	ResolvedIPs []net.IP
	rtt         int64
	httpClient  *http.Client
	h3Client    *http.Client
}

func (u *Upstream) String() string {
	s := fmt.Sprintf("%s://%s:%s%s", u.Proto, u.Host, u.Port, u.Path)
	if u.BootstrapIP != "" {
		s += fmt.Sprintf("#%s", u.BootstrapIP)
	}
	return s
}

func (u *Upstream) updateRTT(d time.Duration) {
	newVal := int64(d)
	old := atomic.LoadInt64(&u.rtt)
	if old == 0 {
		atomic.StoreInt64(&u.rtt, newVal)
		return
	}
	avg := int64(float64(old)*0.7 + float64(newVal)*0.3)
	atomic.StoreInt64(&u.rtt, avg)
}

func (u *Upstream) getRTT() int64 { return atomic.LoadInt64(&u.rtt) }

var rrCounter atomic.Uint64

// Global configuration
var config *Config

// Bootstrap DNS servers
var bootstrapServers []string

// --- DoQ Connection Pool ---

type DoQPool struct {
	mu       sync.RWMutex
	sessions map[string]*doqSession
}

type doqSession struct {
	conn     quic.Connection
	lastUsed time.Time
	mu       sync.Mutex
}

var doqPool = &DoQPool{sessions: make(map[string]*doqSession)}

func (p *DoQPool) Get(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	p.mu.RLock()
	sess, exists := p.sessions[addr]
	p.mu.RUnlock()

	if exists {
		sess.mu.Lock()
		select {
		case <-sess.conn.Context().Done():
			sess.mu.Unlock()
			p.mu.Lock()
			delete(p.sessions, addr)
			p.mu.Unlock()
		default:
			sess.lastUsed = time.Now()
			sess.mu.Unlock()
			return sess.conn, nil
		}
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.sessions[addr] = &doqSession{conn: conn, lastUsed: time.Now()}
	p.mu.Unlock()

	return conn, nil
}

func (p *DoQPool) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		p.mu.Lock()
		for addr, sess := range p.sessions {
			sess.mu.Lock()
			if time.Since(sess.lastUsed) > 2*time.Minute {
				sess.conn.CloseWithError(0, "idle timeout")
				delete(p.sessions, addr)
			}
			sess.mu.Unlock()
		}
		p.mu.Unlock()
	}
}

// --- ARP Cache ---

type ARPCache struct {
	sync.RWMutex
	table map[string]net.HardwareAddr
}

var arpCache = &ARPCache{table: make(map[string]net.HardwareAddr)}

// --- DNS Cache ---

type CacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
	LastAccess time.Time
}

type DNSCache struct {
	sync.RWMutex
	items map[string]*CacheEntry
}

var dnsCache = &DNSCache{items: make(map[string]*CacheEntry)}

// --- Singleflight ---

type callResult struct {
	msg         *dns.Msg
	upstreamStr string
	rtt         time.Duration
	err         error
}

type call struct {
	wg  sync.WaitGroup
	val callResult
}

type RequestGroup struct {
	mu sync.Mutex
	m  map[string]*call
}

func (g *RequestGroup) Do(key string, fn func() callResult) (callResult, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, true
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, false
}

var requestGroup RequestGroup

// --- Main ---

func main() {
	flag.Usage = func() {
		const usage = `High-Performance Multi-Protocol DNS Proxy

Usage: %s -config <config.yaml>
`
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *configFile == "" {
		log.Fatal("Error: -config flag is required.")
	}

	// Load configuration
	if err := LoadConfig(*configFile); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	go maintainARPCache()
	go doqPool.cleanup()

	if config.Cache.Enabled {
		log.Println("Caching: Enabled")
		go maintainDNSCache()
	} else {
		log.Println("Caching: Disabled")
	}

	tlsConfig, err := getTLSConfig(config.Server.TLS.CertFile, config.Server.TLS.KeyFile, config.Server.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	var wg sync.WaitGroup
	startServers(&wg, tlsConfig)
	wg.Wait()
}

func startServers(wg *sync.WaitGroup, tlsConfig *tls.Config) {
	listenAddr := config.Server.ListenAddr
	udpPort := config.Server.Ports.UDP
	tlsPort := config.Server.Ports.TLS
	httpsPort := config.Server.Ports.HTTPS

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "udp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "UDP",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DNS UDP on %s:%d", listenAddr, udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "tcp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "TCP",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DNS TCP on %s:%d", listenAddr, udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{
			Addr: fmt.Sprintf("%s:%d", listenAddr, tlsPort),
			Net:  "tcp-tls", TLSConfig: tlsConfig,
		}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "DoT",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DoT on %s:%d", listenAddr, tlsPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("DoT server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", listenAddr, tlsPort)
		log.Printf("Starting DoQ on %s", addr)
		listener, err := quic.ListenAddr(addr, tlsConfig, nil)
		if err != nil {
			log.Printf("DoQ listen error: %v", err)
			return
		}
		for {
			sess, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("DoQ accept error: %v", err)
				continue
			}
			go handleDoQSession(sess)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", listenAddr, httpsPort)
		
		// Catch-all handler for path validation inside handleDoH
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleDoH)

		h3Server := &http3.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}
		h1Server := &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}

		log.Printf("Starting DoH/DoH3 on %s", addr)
		go func() {
			if err := h3Server.ListenAndServe(); err != nil {
				log.Printf("DoH3 server error: %v", err)
			}
		}()
		if err := h1Server.ListenAndServeTLS("", ""); err != nil {
			log.Printf("DoH server error: %v", err)
		}
	}()
}

func getTimeout() time.Duration {
	if config.Server.Timeout == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(config.Server.Timeout)
	if err != nil {
		return 5 * time.Second
	}
	return d
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
	// cfg.Server.DOH.StrictPath defaults to false (bool default)

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
	log.Println("-----------------------------")

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

	config = &cfg
	return nil
}

// --- Routing Functions ---

func resolveHostnameWithBootstrap(hostname string) ([]net.IP, error) {
	var allIPs []net.IP
	var lastErr error

	useIPv4 := *ipVersion == "ipv4" || *ipVersion == "both"
	useIPv6 := *ipVersion == "ipv6" || *ipVersion == "both"

	for _, bootstrap := range bootstrapServers {
		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

		if useIPv4 {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
			resp, _, err := c.Exchange(msg, bootstrap)
			if err == nil && resp != nil {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						allIPs = append(allIPs, a.A)
					}
				}
			} else {
				lastErr = err
			}
		}

		if useIPv6 {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
			resp, _, err := c.Exchange(msg, bootstrap)
			if err == nil && resp != nil {
				for _, ans := range resp.Answer {
					if aaaa, ok := ans.(*dns.AAAA); ok {
						allIPs = append(allIPs, aaaa.AAAA)
					}
				}
			} else {
				lastErr = err
			}
		}

		if len(allIPs) > 0 {
			break
		}
	}

	if len(allIPs) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("failed to resolve %s: %w", hostname, lastErr)
		}
		return nil, fmt.Errorf("no IPs found for %s", hostname)
	}

	return allIPs, nil
}

// --- Upstream Parsing ---

func parseUpstream(raw string, ipVersion string, insecure bool, timeout string) (*Upstream, error) {
	parts := strings.Split(raw, "#")
	uString := parts[0]
	bootstrap := ""
	if len(parts) > 1 {
		bootstrap = parts[1]
	}

	u, err := url.Parse(uString)
	if err != nil {
		return nil, err
	}

	proto := strings.ToLower(u.Scheme)
	switch proto {
	case "tls":
		proto = "dot"
	case "https":
		proto = "doh"
	case "h3":
		proto = "doh3"
	case "quic":
		proto = "doq"
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch proto {
		case "udp", "tcp":
			port = "53"
		case "dot", "doq":
			port = "853"
		case "doh", "doh3":
			port = "443"
		}
	}

	path := u.Path
	if (proto == "doh" || proto == "doh3") && path == "" {
		path = "/dns-query"
	}

	up := &Upstream{
		URL: u, Proto: proto, Host: host,
		Port: port, BootstrapIP: bootstrap, Path: path,
	}

	// Resolve hostname to IPs
	if bootstrap != "" {
		up.ResolvedIPs = []net.IP{net.ParseIP(bootstrap)}
		log.Printf("Upstream %s using bootstrap IP: %s", up.String(), bootstrap)
	} else if net.ParseIP(host) != nil {
		up.ResolvedIPs = []net.IP{net.ParseIP(host)}
		log.Printf("Upstream %s using direct IP: %s", up.String(), host)
	} else {
		log.Printf("Resolving hostname %s using bootstrap servers...", host)
		ips, err := resolveHostnameWithBootstrap(host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve upstream hostname %s: %w", host, err)
		}
		up.ResolvedIPs = ips
		log.Printf("Upstream %s resolved to %d IPs: %v", up.String(), len(ips), ips)
	}

	timeoutDuration := 5 * time.Second
	if timeout != "" {
		d, err := time.ParseDuration(timeout)
		if err == nil {
			timeoutDuration = d
		}
	}

	if proto == "doh" {
		up.httpClient = &http.Client{
			Timeout: timeoutDuration,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure, ServerName: host},
				ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if len(up.ResolvedIPs) > 0 {
						ip := up.ResolvedIPs[rand.IntN(len(up.ResolvedIPs))]
						target := net.JoinHostPort(ip.String(), port)
						var d net.Dialer
						return d.DialContext(ctx, network, target)
					}
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			},
		}
	}

	if proto == "doh3" {
		up.h3Client = &http.Client{
			Timeout: timeoutDuration,
			Transport: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, ServerName: host},
				Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					if len(up.ResolvedIPs) > 0 {
						ip := up.ResolvedIPs[rand.IntN(len(up.ResolvedIPs))]
						target := net.JoinHostPort(ip.String(), port)
						return quic.DialAddrEarly(ctx, target, tlsConf, cfg)
					}
					return quic.DialAddrEarly(ctx, addr, tlsConf, cfg)
				},
			},
		}
	}

	return up, nil
}

// --- Exchange with Context ---

func (u *Upstream) executeExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	targetHost := u.Host
	if len(u.ResolvedIPs) > 0 {
		targetHost = u.ResolvedIPs[rand.IntN(len(u.ResolvedIPs))].String()
	}
	targetAddr := net.JoinHostPort(targetHost, u.Port)

	type result struct {
		resp *dns.Msg
		err  error
	}
	done := make(chan result, 1)

	go func() {
		resp, err := u.doExchange(ctx, req, targetAddr)
		done <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		return nil, time.Since(start), ctx.Err()
	case r := <-done:
		rtt := time.Since(start)
		if r.err == nil {
			u.updateRTT(rtt)
		}
		return r.resp, rtt, r.err
	}
}

func (u *Upstream) doExchange(ctx context.Context, req *dns.Msg, targetAddr string) (*dns.Msg, error) {
	timeout := getTimeout()
	insecure := config.Server.InsecureUpstream

	switch u.Proto {
	case "udp", "tcp":
		c := &dns.Client{Net: u.Proto, Timeout: timeout}
		resp, _, err := c.ExchangeContext(ctx, req, targetAddr)
		return resp, err

	case "dot":
		c := &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeout,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: insecure,
				ServerName:         u.Host,
			},
		}
		resp, _, err := c.ExchangeContext(ctx, req, targetAddr)
		return resp, err

	case "doq":
		return u.exchangeDoQ(ctx, req, targetAddr)

	case "doh", "doh3":
		return u.exchangeDoH(ctx, req)
	}

	return nil, errors.New("unsupported protocol")
}

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetAddr string) (*dns.Msg, error) {
	insecure := config.Server.InsecureUpstream

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         u.Host,
		NextProtos:         []string{"doq"},
	}

	sess, err := doqPool.Get(ctx, targetAddr, tlsConf)
	if err != nil {
		return nil, err
	}

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	buf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	fullLen := 2 + len(buf)
	sendBuf := bufPool.Get().([]byte)
	if cap(sendBuf) < fullLen {
		sendBuf = make([]byte, fullLen)
	} else {
		sendBuf = sendBuf[:fullLen]
	}
	defer bufPool.Put(sendBuf)

	binary.BigEndian.PutUint16(sendBuf[:2], uint16(len(buf)))
	copy(sendBuf[2:], buf)

	if _, err := stream.Write(sendBuf); err != nil {
		return nil, err
	}

	lBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lBuf)

	respBuf := bufPool.Get().([]byte)
	if cap(respBuf) < int(length) {
		respBuf = make([]byte, length)
	} else {
		respBuf = respBuf[:length]
	}
	defer bufPool.Put(respBuf)

	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		return nil, err
	}
	return resp, nil
}

func (u *Upstream) exchangeDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	client := u.httpClient
	if u.Proto == "doh3" {
		client = u.h3Client
	}

	buf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("https://%s:%s%s", u.Host, u.Port, u.Path)
	hReq, err := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")

	hResp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH error: %d", hResp.StatusCode)
	}

	respBody, err := io.ReadAll(hResp.Body)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBody); err != nil {
		return nil, err
	}
	return resp, nil
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
			// Syntax: *.domain.name.com -> Just the sub-domains.
			base := ruleDom[2:]
			if strings.HasSuffix(qDom, "."+base) {
				match = true
			}
		} else if strings.HasPrefix(ruleDom, ".") {
			// Syntax: .domain.name.com -> The domain-name and sub-domains.
			base := ruleDom[1:]
			if qDom == base || strings.HasSuffix(qDom, "."+base) {
				match = true
			}
		} else {
			// Syntax: domain.name.com -> Just the domain-name.
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

func forwardToUpstreamsWithContext(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	selectedUpstreams, selectedStrategy := SelectUpstreams(reqCtx)
	return forwardToUpstreams(ctx, req, selectedUpstreams, selectedStrategy)
}

// --- Strategy Logic ---

func forwardToUpstreams(ctx context.Context, req *dns.Msg, upstreams []*Upstream, strategy string) (*dns.Msg, string, time.Duration, error) {
	if len(upstreams) == 1 {
		u := upstreams[0]
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err
	}

	strat := strings.ToLower(strategy)

	switch strat {
	case "round-robin":
		idx := rrCounter.Add(1)
		u := upstreams[int(idx)%len(upstreams)]
		log.Printf("[STRATEGY] Round-Robin: Selected #%d %s", int(idx)%len(upstreams), u.String())
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err

	case "random":
		idx := rand.IntN(len(upstreams))
		u := upstreams[idx]
		log.Printf("[STRATEGY] Random: Selected %s", u.String())
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err

	case "failover":
		log.Printf("[STRATEGY] Failover: Starting sequence...")
		for i, u := range upstreams {
			log.Printf("[STRATEGY] Failover: Attempting #%d %s...", i, u.String())
			resp, rtt, err := u.executeExchange(ctx, req)
			if err == nil {
				log.Printf("[STRATEGY] Failover: Success with %s (RTT: %v)", u.String(), rtt)
				return resp, u.String(), rtt, nil
			}
			log.Printf("[STRATEGY] Failover: Failed %s: %v", u.String(), err)
		}
		return nil, "", 0, errors.New("all upstreams failed")

	case "fastest":
		return fastestStrategy(ctx, req, upstreams)

	case "race":
		return raceStrategy(ctx, req, upstreams)

	default:
		for _, u := range upstreams {
			resp, rtt, err := u.executeExchange(ctx, req)
			if err == nil {
				return resp, u.String(), rtt, nil
			}
		}
		return nil, "", 0, errors.New("all upstreams failed")
	}
}

func fastestStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	if rand.Float64() < 0.1 {
		idx := rand.IntN(len(upstreams))
		u := upstreams[idx]
		// Probe in background to update RTT without blocking the current request
		log.Printf("[STRATEGY] Fastest: Probing background upstream %s", u.String())
		go func() {
			// Use a background context for the probe so it doesn't get cancelled by the main request returning
			u.executeExchange(context.Background(), req.Copy())
		}()
	}

	type uStat struct {
		u   *Upstream
		rtt int64
	}
	stats := make([]uStat, len(upstreams))
	for i, u := range upstreams {
		stats[i] = uStat{u, u.getRTT()}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].rtt == 0 && stats[j].rtt == 0 {
			return i < j
		}
		if stats[i].rtt == 0 {
			return true
		}
		if stats[j].rtt == 0 {
			return false
		}
		return stats[i].rtt < stats[j].rtt
	})

	best := stats[0].u
	log.Printf("[STRATEGY] Fastest: Selected %s (Current RTT: %v)", best.String(), time.Duration(best.getRTT()))

	resp, rtt, err := best.executeExchange(ctx, req)
	return resp, best.String(), rtt, err
}

func raceStrategy(ctx context.Context, req *dns.Msg, upstreams []*Upstream) (*dns.Msg, string, time.Duration, error) {
	log.Printf("[STRATEGY] Race: Starting race among %d upstreams", len(upstreams))

	type result struct {
		msg *dns.Msg
		str string
		rtt time.Duration
		err error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan result, len(upstreams))

	for _, u := range upstreams {
		go func(upstream *Upstream) {
			resp, rtt, err := upstream.executeExchange(ctx, req)
			select {
			case resCh <- result{msg: resp, str: upstream.String(), rtt: rtt, err: err}:
			case <-ctx.Done():
			}
		}(u)
	}

	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				log.Printf("[STRATEGY] Race: Winner %s (RTT: %v)", res.str, res.rtt)
				return res.msg, res.str, res.rtt, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, "", 0, lastErr
	}
	return nil, "", 0, errors.New("all upstreams failed in race")
}

// --- Core Request Processing ---

func cleanResponse(msg *dns.Msg) {
	if msg == nil {
		return
	}

	// 1. Remove Authority Section
	msg.Ns = nil

	// 2. Remove Additional Section (includes OPT/EDNS0)
	msg.Extra = nil

	// 3. Filter Answer Section for DNSSEC records
	if len(msg.Answer) > 0 {
		newAnswer := make([]dns.RR, 0, len(msg.Answer))
		for _, rr := range msg.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY, dns.TypeDLV:
				continue
			default:
				newAnswer = append(newAnswer, rr)
			}
		}
		msg.Answer = newAnswer
	}
}

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, reqCtx *RequestContext) {
	start := time.Now()

	remoteAddr := w.RemoteAddr()
	ip := getIPFromAddr(remoteAddr)
	mac := getMacFromCache(ip)

	reqCtx.ClientIP = ip
	reqCtx.ClientMAC = mac

	extractEDNS0ClientInfo(r, reqCtx)

	msg := r.Copy()
	addEDNS0Options(msg, ip, mac)

	var qInfo, cacheKey, ecsSubnet string
	if len(r.Question) > 0 {
		q := r.Question[0]
		reqCtx.QueryName = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		qInfo = fmt.Sprintf("%s (%s)", q.Name, dns.TypeToString[q.Qtype])
	}

	if reqCtx.ClientECS != nil {
		if reqCtx.ClientECSNet != nil {
			mask, _ := reqCtx.ClientECSNet.Mask.Size()
			ecsSubnet = fmt.Sprintf("%s/%d", reqCtx.ClientECS.String(), mask)
		} else {
			ecsSubnet = reqCtx.ClientECS.String()
		}
	}

	if opt := r.IsEdns0(); opt != nil {
		var extra []string
		if reqCtx.ClientECS != nil {
			extra = append(extra, fmt.Sprintf("ECS:%s", ecsSubnet))
		}
		if reqCtx.ClientEDNSMAC != nil {
			extra = append(extra, fmt.Sprintf("MAC65001:%s", reqCtx.ClientEDNSMAC.String()))
		}
		if len(extra) > 0 {
			qInfo += fmt.Sprintf(" [%s]", strings.Join(extra, " "))
		}
	}

	if len(r.Question) > 0 {
		q := r.Question[0]

		effectiveIP := reqCtx.ClientIP
		if reqCtx.ClientECS != nil {
			effectiveIP = reqCtx.ClientECS
		}

		effectiveMAC := reqCtx.ClientMAC
		if reqCtx.ClientEDNSMAC != nil {
			effectiveMAC = reqCtx.ClientEDNSMAC
		}

		routingKey := fmt.Sprintf("%s:%d:%s:%s:%s:%s",
			reqCtx.ServerIP, reqCtx.ServerPort, reqCtx.ServerHostname, reqCtx.ServerPath,
			effectiveIP, effectiveMAC)
		cacheKey = fmt.Sprintf("%s|%d|%d|%s", q.Name, q.Qtype, q.Qclass, routingKey)
	}

	if !*cacheDisabled && cacheKey != "" {
		if cachedResp := getFromCache(cacheKey, r.Id); cachedResp != nil {
			cleanResponse(cachedResp) // Ensure cached response is minimal
			logRequest(r.Id, ip, mac, reqCtx.Protocol, reqCtx.ServerHostname, qInfo, "CACHE_HIT", "CACHE", 0, time.Since(start), cachedResp)
			w.WriteMsg(cachedResp)
			return
		}
	}

	callResult, shared := requestGroup.Do(cacheKey, func() callResult {
		resp, upstreamStr, rtt, err := forwardToUpstreamsWithContext(ctx, msg, reqCtx)
		return callResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt, err: err}
	})

	if callResult.err != nil {
		log.Printf("Error forwarding %s from %s: %v", qInfo, ip, callResult.err)
		dns.HandleFailed(w, r)
		return
	}

	resp := callResult.msg

	// Fix shared pointer race condition and allow safe modification
	if shared && resp != nil {
		resp = resp.Copy()
	}

	// Clean the response (Strip Authority, Additional, DNSSEC)
	if resp != nil {
		cleanResponse(resp)
	}

	if !*cacheDisabled && resp != nil {
		addToCache(cacheKey, resp)
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	logRequest(r.Id, ip, mac, reqCtx.Protocol, reqCtx.ServerHostname, qInfo, status, callResult.upstreamStr, callResult.rtt, time.Since(start), resp)

	resp.Id = r.Id
	w.WriteMsg(resp)
}

func logRequest(qid uint16, ip net.IP, mac net.HardwareAddr, proto, meta, qInfo, status, upstream string, upstreamRTT, duration time.Duration, resp *dns.Msg) {
	macStr := "N/A"
	if mac != nil {
		macStr = mac.String()
	}

	protoLog := proto
	if meta != "" {
		protoLog = fmt.Sprintf("%s(%s)", proto, meta)
	}

	log.Printf("[QRY] QID:%d | Client:%s | MAC:%s | Proto:%s | Query:%s", qid, ip, macStr, protoLog, qInfo)

	if upstream != "" && upstream != "CACHE" {
		log.Printf("[FWD] QID:%d | Upstream:%s | RTT:%v | Query:%s | Response:%s", qid, upstream, upstreamRTT, qInfo, status)
	}

	var answers []string
	if resp != nil {
		addRRs := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				parts := strings.Fields(rr.String())
				if len(parts) >= 4 {
					s := parts[3]
					if len(parts) > 4 {
						s += " " + strings.Join(parts[4:], " ")
					}
					answers = append(answers, s)
				}
			}
		}
		addRRs(resp.Answer)
		addRRs(resp.Ns)
		addRRs(resp.Extra)
	}

	ansStr := strings.Join(answers, ", ")
	if ansStr == "" {
		ansStr = "Empty"
	}

	log.Printf("[RSP] QID:%d | Status:%s | TotalTime:%v | Answers:[%s]", qid, status, duration, ansStr)
}

// --- Cache Functions ---

func maintainDNSCache() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		pruneCache()
	}
}

func getFromCache(key string, reqID uint16) *dns.Msg {
	if !config.Cache.Enabled {
		return nil
	}

	dnsCache.RLock()
	entry, found := dnsCache.items[key]
	dnsCache.RUnlock()

	if !found {
		// log.Printf("[CACHE] MISS: Key=%s", key)
		return nil
	}

	now := time.Now()
	if now.After(entry.Expiration) {
		// log.Printf("[CACHE] EXPIRED: Key=%s", key)
		return nil
	}

	dnsCache.Lock()
	if e, ok := dnsCache.items[key]; ok {
		e.LastAccess = now
	}
	dnsCache.Unlock()

	msg := entry.Msg.Copy()
	msg.Id = reqID

	ttlDiff := uint32(entry.Expiration.Sub(now).Seconds())
	if ttlDiff <= 0 {
		return nil
	}

	// log.Printf("[CACHE] HIT: Key=%s | Adjusted TTL: %ds", key, ttlDiff)

	updateTTL := func(rrs []dns.RR) {
		for _, rr := range rrs {
			rr.Header().Ttl = ttlDiff
		}
	}
	updateTTL(msg.Answer)
	updateTTL(msg.Ns)
	updateTTL(msg.Extra)
	return msg
}

func addToCache(key string, msg *dns.Msg) {
	if !config.Cache.Enabled {
		return
	}

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	minTTL := uint32(3600)
	foundTTL := false
	checkRR := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			foundTTL = true
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}
	checkRR(msg.Answer)
	checkRR(msg.Ns)
	checkRR(msg.Extra)

	if minTTL == 0 {
		return
	}
	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		minTTL = 60
	} else if !foundTTL {
		return
	}

	dnsCache.Lock()
	defer dnsCache.Unlock()

	if len(dnsCache.items) >= config.Cache.Size {
		now := time.Now()
		for k, v := range dnsCache.items {
			if now.After(v.Expiration) {
				delete(dnsCache.items, k)
			}
		}

		if len(dnsCache.items) >= config.Cache.Size {
			evictSmartLRU()
		}
	}

	now := time.Now()
	dnsCache.items[key] = &CacheEntry{
		Msg:        msg,
		Expiration: now.Add(time.Duration(minTTL) * time.Second),
		LastAccess: now,
	}
	// log.Printf("[CACHE] ADD: Key=%s | MinTTL: %ds", key, minTTL)
}

func evictSmartLRU() {
	toRemove := config.Cache.Size / 20
	if toRemove < 10 {
		toRemove = 10
	}

	const sampleSize = 50

	for i := 0; i < toRemove; i++ {
		if len(dnsCache.items) == 0 {
			break
		}

		var oldestKey string
		var oldestTime time.Time
		first := true
		count := 0

		for k, v := range dnsCache.items {
			if first || v.LastAccess.Before(oldestTime) {
				oldestTime = v.LastAccess
				oldestKey = k
				first = false
			}
			count++
			if count >= sampleSize {
				break
			}
		}

		if oldestKey != "" {
			delete(dnsCache.items, oldestKey)
		}
	}
}

func pruneCache() {
	dnsCache.Lock()
	defer dnsCache.Unlock()
	now := time.Now()
	for k, v := range dnsCache.items {
		if now.After(v.Expiration) {
			delete(dnsCache.items, k)
		}
	}
}

// --- Handlers ---

func handleDoH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), *queryTimeout)
	defer cancel()

	// --- PATH VALIDATION LOGIC ---
	// If strict checking is enabled, verify request path matches one of the allowed paths.
	if config.Server.DOH.StrictPath {
		allowed := false
		for _, path := range config.Server.DOH.AllowedPaths {
			if r.URL.Path == path {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}
	// -----------------------------

	var msg *dns.Msg
	var err error

	proto := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		data, _ := io.ReadAll(r.Body)
		msg = new(dns.Msg)
		err = msg.Unpack(data)
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		data, e := base64.RawURLEncoding.DecodeString(b64)
		if e != nil {
			http.Error(w, "Invalid base64", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		err = msg.Unpack(data)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	localAddr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	reqCtx := &RequestContext{
		ServerIP:       getLocalIP(localAddr),
		ServerPort:     getLocalPort(localAddr),
		ServerHostname: r.Host,
		ServerPath:     r.URL.Path,
		Protocol:       proto,
	}
	dw := &dohResponseWriter{w: w, r: r, localAddr: localAddr}
	processDNSRequest(ctx, dw, msg, reqCtx)
}

func handleDoQSession(sess quic.Connection) {
	sni := sess.ConnectionState().TLS.ServerName
	localAddr := sess.LocalAddr()

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(str quic.Stream) {
			defer str.Close()

			ctx, cancel := context.WithTimeout(context.Background(), *queryTimeout)
			defer cancel()

			lBuf := make([]byte, 2)
			if _, err := io.ReadFull(str, lBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lBuf)

			buf := bufPool.Get().([]byte)
			if cap(buf) < int(length) {
				buf = make([]byte, length)
			} else {
				buf = buf[:length]
			}
			defer bufPool.Put(buf)

			if _, err := io.ReadFull(str, buf); err != nil {
				return
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(buf); err != nil {
				return
			}

			reqCtx := &RequestContext{
				ServerIP:       getLocalIP(localAddr),
				ServerPort:     getLocalPort(localAddr),
				ServerHostname: sni,
				Protocol:       "DoQ",
			}

			dw := &doqResponseWriter{stream: str, remoteAddr: sess.RemoteAddr()}
			processDNSRequest(ctx, dw, msg, reqCtx)
		}(stream)
	}
}

// --- ARP ---

func maintainARPCache() {
	refreshARP()
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		refreshARP()
	}
}

func getMacFromCache(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}
	arpCache.RLock()
	defer arpCache.RUnlock()
	return arpCache.table[ip.String()]
}

func refreshARP() {
	newTable := make(map[string]net.HardwareAddr)
	switch runtime.GOOS {
	case "linux":
		parseLinuxARP(newTable)
	case "windows":
		parseWindowsARP(newTable)
		parseWindowsNDP(newTable)
	case "darwin":
		parseDarwinARP(newTable)
		parseDarwinNDP(newTable)
	default:
		parseDarwinARP(newTable)
	}
	arpCache.Lock()
	arpCache.table = newTable
	arpCache.Unlock()
}

func parseLinuxARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("ip", "neigh", "show")
	out, err := cmd.Output()
	if err != nil {
		// log.Printf("ARP refresh error: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip := f[0]
		for i, v := range f {
			if v == "lladdr" && i+1 < len(f) {
				if mac, err := net.ParseMAC(f[i+1]); err == nil {
					table[ip] = mac
				}
			}
		}
	}
}

func parseWindowsARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("arp", "-a")
	out, err := cmd.Output()
	if err != nil {
		// log.Printf("ARP refresh error: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := windowsARPRegex.FindStringSubmatch(sc.Text())
		if len(m) == 3 {
			if mac, err := net.ParseMAC(strings.ReplaceAll(m[2], "-", ":")); err == nil {
				table[m[1]] = mac
			}
		}
	}
}

func parseWindowsNDP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("netsh", "interface", "ipv6", "show", "neighbors")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			if mac, err := net.ParseMAC(strings.ReplaceAll(f[1], "-", ":")); err == nil {
				if ip := net.ParseIP(f[0]); ip != nil {
					table[ip.String()] = mac
				}
			}
		}
	}
}

func parseDarwinARP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("arp", "-an")
	out, err := cmd.Output()
	if err != nil {
		// log.Printf("ARP refresh error: %v", err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := darwinARPRegex.FindStringSubmatch(sc.Text())
		if len(m) == 3 && m[2] != "ff:ff:ff:ff:ff:ff" && m[2] != "(incomplete)" {
			if mac, err := net.ParseMAC(m[2]); err == nil {
				table[m[1]] = mac
			}
		}
	}
}

func parseDarwinNDP(table map[string]net.HardwareAddr) {
	cmd := exec.Command("ndp", "-an")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			ipStr := f[0]
			if idx := strings.Index(ipStr, "%"); idx != -1 {
				ipStr = ipStr[:idx]
			}
			if mac, err := net.ParseMAC(f[1]); err == nil {
				if ip := net.ParseIP(ipStr); ip != nil {
					table[ip.String()] = mac
				}
			}
		}
	}
}

// --- EDNS0 ---

func extractEDNS0ClientInfo(msg *dns.Msg, reqCtx *RequestContext) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}

	for _, option := range opt.Option {
		switch o := option.(type) {
		case *dns.EDNS0_SUBNET:
			reqCtx.ClientECS = o.Address

			family := o.Family
			mask := o.SourceNetmask

			var ipNet *net.IPNet
			if family == 1 {
				if mask > 32 {
					mask = 32
				}
				maskBytes := net.CIDRMask(int(mask), 32)
				ipNet = &net.IPNet{
					IP:   o.Address,
					Mask: maskBytes,
				}
			} else if family == 2 {
				if mask > 128 {
					mask = 128
				}
				maskBytes := net.CIDRMask(int(mask), 128)
				ipNet = &net.IPNet{
					IP:   o.Address,
					Mask: maskBytes,
				}
			}

			reqCtx.ClientECSNet = ipNet

			log.Printf("[EDNS0] Extracted ECS: %s/%d (family: %d)",
				o.Address.String(), mask, family)

		case *dns.EDNS0_LOCAL:
			if o.Code == EDNS0_OPTION_MAC && len(o.Data) > 0 {
				reqCtx.ClientEDNSMAC = net.HardwareAddr(o.Data)
				log.Printf("[EDNS0] Extracted MAC from Option 65001: %s",
					reqCtx.ClientEDNSMAC.String())
			}
		}
	}
}

func addEDNS0Options(msg *dns.Msg, ip net.IP, mac net.HardwareAddr) {
	o := msg.IsEdns0()
	if o == nil {
		msg.SetEdns0(4096, true)
		o = msg.IsEdns0()
	}

	var opts []dns.EDNS0
	var hasECS bool

	for _, opt := range o.Option {
		if _, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			opts = append(opts, opt)
		} else if local, ok := opt.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
			continue
		} else {
			opts = append(opts, opt)
		}
	}

	if !hasECS && ip != nil {
		family := uint16(1)
		mask := uint8(32)
		if ip.To4() == nil {
			family = 2
			mask = 128
		}
		opts = append(opts, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: family,
			SourceNetmask: mask, Address: ip,
		})
	}

	if mac != nil {
		opts = append(opts, &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: mac})
	}

	o.Option = opts
}

func getIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		if addr == nil {
			return nil
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

func getLocalIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}

	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}

func getLocalPort(addr net.Addr) int {
	if addr == nil {
		return 0
	}

	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.Port
	case *net.TCPAddr:
		return v.Port
	default:
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0
		}
		var p int
		fmt.Sscanf(port, "%d", &p)
		return p
	}
}

// --- Response Writers ---

type doqResponseWriter struct {
	stream     quic.Stream
	remoteAddr net.Addr
}

func (w *doqResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *doqResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	fullLen := 2 + len(buf)
	sendBuf := bufPool.Get().([]byte)
	if cap(sendBuf) < fullLen {
		sendBuf = make([]byte, fullLen)
	} else {
		sendBuf = sendBuf[:fullLen]
	}
	defer bufPool.Put(sendBuf)

	binary.BigEndian.PutUint16(sendBuf[:2], uint16(len(buf)))
	copy(sendBuf[2:], buf)

	_, err = w.stream.Write(sendBuf)
	return err
}
func (w *doqResponseWriter) Write(b []byte) (int, error) { return w.stream.Write(b) }
func (w *doqResponseWriter) Close() error                { return w.stream.Close() }
func (w *doqResponseWriter) TsigStatus() error           { return nil }
func (w *doqResponseWriter) TsigTimersOnly(bool)         {}
func (w *doqResponseWriter) Hijack()                     {}

type dohResponseWriter struct {
	w         http.ResponseWriter
	r         *http.Request
	localAddr net.Addr
}

func (w *dohResponseWriter) LocalAddr() net.Addr { return w.localAddr }
func (w *dohResponseWriter) RemoteAddr() net.Addr {
	host, _, _ := net.SplitHostPort(w.r.RemoteAddr)
	addr, _ := net.ResolveIPAddr("ip", host)
	return addr
}
func (w *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	w.w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.w.Write(buf)
	return err
}
func (w *dohResponseWriter) Write(b []byte) (int, error) { return w.w.Write(b) }
func (w *dohResponseWriter) Close() error                { return nil }
func (w *dohResponseWriter) TsigStatus() error           { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)         {}
func (w *dohResponseWriter) Hijack()                     {}

// --- TLS ---

func getTLSConfig(certPath, keyPath, listenIP string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certPath != "" && keyPath != "" {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates: %w", err)
		}
	} else {
		log.Println("Generating self-signed certificate...")
		cert, err = generateSelfSignedCert(listenIP)
		if err != nil {
			return nil, fmt.Errorf("failed to generate certificate: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "doq", "h2", "http/1.1"},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSignedCert(listenIP string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(listenIP); ip != nil {
		ips = append(ips, ip)
	}

	hostnames := []string{"localhost"}
	if h, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, h)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"DNS Proxy"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hostnames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

