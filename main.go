/*
File: main.go
Version: 2.1.0
Author: Chris Buijs (2025), Refactored with optimizations
Description: A high-performance, multi-protocol DNS Proxy supporting UDP, TCP, DoT, DoH, DoH3, and DoQ upstreams.
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
)

// --- Configuration & Flags ---

// stringSlice allows passing the -upstream flag multiple times.
// e.g., -upstream 1.1.1.1 -upstream 8.8.8.8
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	upstreamFlags    stringSlice
	listenAddr       = flag.String("addr", "0.0.0.0", "Bind address for all protocols")
	udpPort          = flag.Int("udp", 53, "UDP/TCP listening port")
	tlsPort          = flag.Int("tls", 853, "DoT/DoQ listening port")
	httpsPort        = flag.Int("https", 443, "DoH/DoH3 listening port")
	certFile         = flag.String("cert", "", "Path to TLS certificate file")
	keyFile          = flag.String("key", "", "Path to TLS key file")
	insecureUpstream = flag.Bool("insecure", false, "Allow unverifiable hostnames (DANGEROUS: MITM risk)")
	cacheDisabled    = flag.Bool("no-cache", false, "Disable DNS response caching")
	cacheSize        = flag.Int("cache-size", 10000, "Maximum number of cached entries")
	strategy         = flag.String("strategy", "failover", "Upstream selection strategy (failover, fastest, random, round-robin, race)")
	queryTimeout     = flag.Duration("timeout", 5*time.Second, "Query timeout for all protocols")
)

const EDNS0_OPTION_MAC = 65001

// --- Globals & Pools ---

// bufPool reduces GC pressure by reusing byte buffers for IO operations.
// Instead of creating garbage 4KB arrays for every packet, we recycle them.
var bufPool = sync.Pool{
	New: func() any {
		// 4KB is standard max for most DNS ops (EDNS0 usually caps around 1232 or 4096).
		return make([]byte, 4096)
	},
}

// Pre-compiled regex for ARP parsing.
// Optimization: Compiling regex is expensive. Doing it inside the loop is a performance killer.
// We compile these once at startup.
var (
	windowsARPRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})`)
	darwinARPRegex  = regexp.MustCompile(`\((.*?)\) at ([0-9a-fA-F:]+)`)
)

// --- Structs ---

type Upstream struct {
	URL         *url.URL
	Proto       string
	Host        string
	Port        string
	BootstrapIP string
	Path        string
	// rtt is accessed atomically because multiple goroutines (race strategy) update it.
	rtt        int64
	httpClient *http.Client
	h3Client   *http.Client
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
	// EWMA (Exponential Weighted Moving Average) filters out jitter.
	// We give 70% weight to history, 30% to the new sample.
	avg := int64(float64(old)*0.7 + float64(newVal)*0.3)
	atomic.StoreInt64(&u.rtt, avg)
}

func (u *Upstream) getRTT() int64 { return atomic.LoadInt64(&u.rtt) }

var upstreams []*Upstream
var rrCounter atomic.Uint64

// --- DoQ Connection Pool ---

// DoQ (DNS over QUIC) establishes heavy sessions. We don't want to handshake on every query.
// This pool keeps sessions alive and manages reuse.
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

// Get returns an existing active session or dials a new one.
func (p *DoQPool) Get(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	p.mu.RLock()
	sess, exists := p.sessions[addr]
	p.mu.RUnlock()

	if exists {
		sess.mu.Lock()
		// Check if connection is effectively dead before returning it.
		select {
		case <-sess.conn.Context().Done():
			// It's dead, Jim. Clean it up.
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

	// No session found, dial a new one.
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

// cleanup creates a background ticker to close idle connections.
// Prevents memory leaks from stale sessions.
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

// Singleflight prevents the "Thundering Herd" problem.
// If 100 clients ask for "google.com" at the exact same millisecond,
// we send only ONE request upstream and share the result with all 100 clients.
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
		// Request in progress, join the wait group.
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, true
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	// Execute the function (upstream call).
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

Usage: %s [options]

Description:
  A robust DNS proxy supporting modern encrypted DNS protocols (DoT, DoH, DoH3, DoQ)
  alongside legacy UDP/TCP. It features smart upstream selection strategies,
  in-memory caching, and connection pooling for optimal performance.

Options:
`
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()

		const detailedInfo = `
Strategies (-strategy):
  failover     Use the first valid upstream; switch only if it fails (Default).
  fastest      Measure latency (RTT) and prefer the fastest upstream. Includes 
               epsilon-greedy exploration (10% chance) to re-check slower servers.
  round-robin  Rotate through upstreams sequentially for load balancing.
  random       Pick a random upstream for every request.
  race         Send request to ALL upstreams simultaneously; return the first response.

Examples:
  1. Simple UDP/TCP Proxy (defaults to 127.0.0.1:5355 upstream):
     %[1]s

  2. Use Cloudflare DoH with "fastest" strategy:
     %[1]s -upstream doh://cloudflare-dns.com/dns-query -strategy fastest

  3. Mix Protocols (Google DoT + Quad9 DoQ) with specific listening ports:
     %[1]s -upstream tls://8.8.8.8 -upstream quic://dns.quad9.net -udp 5300 -tls 8530

  4. Load upstreams from a file (one URL per line) with caching disabled:
     %[1]s -upstream ./resolvers.txt -no-cache

  5. Secure DoH Server (requires certs) proxying to local BIND:
     %[1]s -cert fullchain.pem -key privkey.pem -upstream udp://127.0.0.1:53

  6. Bootstrap IP (skip system DNS for upstream resolution):
     %[1]s -upstream "doh://dns.google/dns-query#8.8.4.4"

Notes:
  - Default bind address is 0.0.0.0 (all interfaces).
  - Self-signed certificates are generated automatically if -cert/-key are missing 
    (clients may reject these).
`
		fmt.Fprintf(os.Stderr, detailedInfo, os.Args[0])
	}

	flag.Var(&upstreamFlags, "upstream", "Upstream server URL or file path")
	flag.Parse()

	if len(upstreamFlags) == 0 {
		upstreamFlags = []string{"udp://127.0.0.1:5355"}
	}

	rawUpstreams := loadUpstreamSources(upstreamFlags)
	if len(rawUpstreams) == 0 {
		log.Fatalf("No valid upstreams found")
	}

	for _, u := range rawUpstreams {
		parsed, err := parseUpstream(u)
		if err != nil {
			log.Fatalf("Invalid upstream %s: %v", u, err)
		}
		upstreams = append(upstreams, parsed)
		log.Printf("Loaded Upstream: %s", parsed.String())
	}

	// Start background maintenance routines
	go maintainARPCache()
	go doqPool.cleanup()

	if !*cacheDisabled {
		log.Println("Caching: Enabled")
		go maintainDNSCache()
	} else {
		log.Println("Caching: Disabled")
	}

	// Setup TLS for incoming connections (DoT/DoQ/DoH)
	tlsConfig, err := getTLSConfig(*certFile, *keyFile, *listenAddr)
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	var wg sync.WaitGroup
	startServers(&wg, tlsConfig)
	wg.Wait()
}

func loadUpstreamSources(sources []string) []string {
	var rawUpstreams []string
	for _, source := range sources {
		// check if arg is a file path
		info, err := os.Stat(source)
		if err == nil && !info.IsDir() {
			log.Printf("Reading upstreams from file: %s", source)
			file, err := os.Open(source)
			if err != nil {
				log.Printf("Warning: Failed to open file %s: %v", source, err)
				continue
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
					continue
				}
				rawUpstreams = append(rawUpstreams, line)
			}
			file.Close()
			if err := scanner.Err(); err != nil {
				log.Printf("Warning: Error scanning file %s: %v", source, err)
			}
		} else {
			// arg is a direct URL
			rawUpstreams = append(rawUpstreams, source)
		}
	}
	return rawUpstreams
}

func startServers(wg *sync.WaitGroup, tlsConfig *tls.Config) {
	// 1. Standard UDP DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", *listenAddr, *udpPort), Net: "udp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), *queryTimeout)
			defer cancel()
			processDNSRequest(ctx, w, r, "UDP", "")
		})
		log.Printf("Starting DNS UDP on %s:%d", *listenAddr, *udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	// 2. Standard TCP DNS (Reliability / Big packets)
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", *listenAddr, *udpPort), Net: "tcp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), *queryTimeout)
			defer cancel()
			processDNSRequest(ctx, w, r, "TCP", "")
		})
		log.Printf("Starting DNS TCP on %s:%d", *listenAddr, *udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	// 3. DNS over TLS (DoT)
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{
			Addr: fmt.Sprintf("%s:%d", *listenAddr, *tlsPort),
			Net:  "tcp-tls", TLSConfig: tlsConfig,
		}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), *queryTimeout)
			defer cancel()
			processDNSRequest(ctx, w, r, "DoT", "")
		})
		log.Printf("Starting DoT on %s:%d", *listenAddr, *tlsPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("DoT server error: %v", err)
		}
	}()

	// 4. DNS over QUIC (DoQ)
	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", *listenAddr, *tlsPort)
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

	// 5. DNS over HTTPS (DoH) & HTTP/3 (DoH3)
	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", *listenAddr, *httpsPort)
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", handleDoH)

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

// --- Upstream Parsing ---

func parseUpstream(raw string) (*Upstream, error) {
	// Support for bootstrap IPs (e.g., doh://example.com#1.2.3.4) to avoid circular dependency loops.
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
	// Normalization for easy config
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
	// Set default ports if user was lazy
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

	timeout := *queryTimeout

	// Configure HTTP clients for DoH/DoH3 upstreams with proper TLS settings
	if proto == "doh" {
		up.httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: *insecureUpstream, ServerName: host},
				ForceAttemptHTTP2: true, // Try H2, fallback to H1
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// Use bootstrap IP if provided
					target := addr
					if bootstrap != "" {
						target = net.JoinHostPort(bootstrap, port)
					}
					var d net.Dialer
					return d.DialContext(ctx, network, target)
				},
			},
		}
	}

	if proto == "doh3" {
		up.h3Client = &http.Client{
			Timeout: timeout,
			Transport: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureUpstream, ServerName: host},
				Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					target := addr
					if bootstrap != "" {
						target = net.JoinHostPort(bootstrap, port)
					}
					return quic.DialAddrEarly(ctx, target, tlsConf, cfg)
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
	if u.BootstrapIP != "" {
		targetHost = u.BootstrapIP
	}
	targetAddr := net.JoinHostPort(targetHost, u.Port)

	type result struct {
		resp *dns.Msg
		err  error
	}
	done := make(chan result, 1)

	// Execute exchange in a goroutine to handle context cancellation/timeout cleanly
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
			// Update stats only on success
			u.updateRTT(rtt)
		}
		return r.resp, rtt, r.err
	}
}

func (u *Upstream) doExchange(ctx context.Context, req *dns.Msg, targetAddr string) (*dns.Msg, error) {
	switch u.Proto {
	case "udp", "tcp":
		c := &dns.Client{Net: u.Proto, Timeout: *queryTimeout}
		resp, _, err := c.ExchangeContext(ctx, req, targetAddr)
		return resp, err

	case "dot":
		c := &dns.Client{
			Net:     "tcp-tls",
			Timeout: *queryTimeout,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: *insecureUpstream,
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
	tlsConf := &tls.Config{
		InsecureSkipVerify: *insecureUpstream,
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

	// Optimization: Coalesce length prefix and payload into one write.
	// This reduces syscalls and improves efficiency over QUIC streams.
	fullLen := 2 + len(buf)
	// Grab a buffer from the pool to avoid allocs
	sendBuf := bufPool.Get().([]byte)
	if cap(sendBuf) < fullLen {
		sendBuf = make([]byte, fullLen)
	} else {
		sendBuf = sendBuf[:fullLen]
	}
	defer bufPool.Put(sendBuf)

	// RFC 9250: DoQ messages are length-prefixed (2 bytes)
	binary.BigEndian.PutUint16(sendBuf[:2], uint16(len(buf)))
	copy(sendBuf[2:], buf)

	if _, err := stream.Write(sendBuf); err != nil {
		return nil, err
	}

	// Read response length
	lBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lBuf)

	// Use pool for reading response body
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
	// MIME type is critical for DoH servers
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

// --- Strategy Logic ---

func forwardToUpstreams(ctx context.Context, req *dns.Msg) (*dns.Msg, string, time.Duration, error) {
	// Fast-path for single upstream config
	if len(upstreams) == 1 {
		u := upstreams[0]
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err
	}

	strat := strings.ToLower(*strategy)

	switch strat {
	case "round-robin":
		// Atomic counter ensures thread-safe round-robin distribution
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
		// Try sequentially until one succeeds
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
		return fastestStrategy(ctx, req)

	case "race":
		return raceStrategy(ctx, req)

	default:
		// Fallback to failover
		for _, u := range upstreams {
			resp, rtt, err := u.executeExchange(ctx, req)
			if err == nil {
				return resp, u.String(), rtt, nil
			}
		}
		return nil, "", 0, errors.New("all upstreams failed")
	}
}

func fastestStrategy(ctx context.Context, req *dns.Msg) (*dns.Msg, string, time.Duration, error) {
	// Epsilon-greedy: 10% chance to pick a random upstream to explore potentially better routes
	if rand.Float64() < 0.1 {
		idx := rand.IntN(len(upstreams))
		u := upstreams[idx]
		log.Printf("[STRATEGY] Fastest: Exploration mode (10%% chance). Probing %s", u.String())
		resp, rtt, err := u.executeExchange(ctx, req)
		return resp, u.String(), rtt, err
	}

	// We calculate stats for logging.
	// Optimization Note: Sorting this slice is O(N log N). For small N (upstreams) this is negligible.
	// If you have thousands of upstreams, switch to a linear O(N) scan.
	type uStat struct {
		u   *Upstream
		rtt int64
	}
	stats := make([]uStat, len(upstreams))
	for i, u := range upstreams {
		stats[i] = uStat{u, u.getRTT()}
	}

	// Sort: unmeasured (0 RTT) first (to give them a chance), then by fastest RTT
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

	// Log the ranking to console
	log.Printf("[STRATEGY] Fastest: Ranking:")
	for i, s := range stats {
		rttVal := "Unmeasured"
		if s.rtt > 0 {
			rttVal = time.Duration(s.rtt).String()
		}
		log.Printf("  Rank #%d | Upstream: %s | RTT: %s", i+1, s.u.String(), rttVal)
	}

	best := stats[0].u
	log.Printf("[STRATEGY] Fastest: Selected #1 %s", best.String())

	resp, rtt, err := best.executeExchange(ctx, req)
	return resp, best.String(), rtt, err
}

func raceStrategy(ctx context.Context, req *dns.Msg) (*dns.Msg, string, time.Duration, error) {
	log.Printf("[STRATEGY] Race: Broadcasting to %d upstreams...", len(upstreams))

	type result struct {
		msg *dns.Msg
		str string
		rtt time.Duration
		err error
	}

	// Use a cancelable context so we can cancel pending requests once the winner returns
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan result, len(upstreams))

	// Launch ALL requests simultaneously
	for _, u := range upstreams {
		go func(upstream *Upstream) {
			resp, rtt, err := upstream.executeExchange(ctx, req)
			select {
			case resCh <- result{msg: resp, str: upstream.String(), rtt: rtt, err: err}:
			case <-ctx.Done():
			}
		}(u)
	}

	// Wait for the first success
	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				log.Printf("[STRATEGY] Race: Winner is %s (RTT: %v)", res.str, res.rtt)
				return res.msg, res.str, res.rtt, nil
			}
			log.Printf("[STRATEGY] Race: %s failed: %v", res.str, res.err)
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", 0, ctx.Err()
		}
	}

	log.Printf("[STRATEGY] Race: All upstreams failed.")
	if lastErr != nil {
		return nil, "", 0, lastErr
	}
	return nil, "", 0, errors.New("all upstreams failed in race")
}

// --- Core Request Processing ---

func processDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, proto, meta string) {
	start := time.Now()

	// 1. Identify Client
	remoteAddr := w.RemoteAddr()
	ip := getIPFromAddr(remoteAddr)
	mac := getMacFromCache(ip)

	// 2. Prepare Message (Add Metadata/EDNS0)
	msg := r.Copy()
	addEDNS0Options(msg, ip, mac)

	// 3. Extract info for logging & caching
	var qInfo, cacheKey, ecsSubnet string
	if len(r.Question) > 0 {
		q := r.Question[0]
		qInfo = fmt.Sprintf("%s (%s)", q.Name, dns.TypeToString[q.Qtype])
	}

	// Extract existing EDNS0 options for logs (like Client Subnet)
	if opt := msg.IsEdns0(); opt != nil {
		var extra []string
		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_SUBNET:
				ecs := fmt.Sprintf("ECS:%s/%d", v.Address.String(), v.SourceNetmask)
				extra = append(extra, ecs)
				ecsSubnet = fmt.Sprintf("%s/%d", v.Address.String(), v.SourceNetmask)
			case *dns.EDNS0_LOCAL:
				if v.Code == EDNS0_OPTION_MAC {
					extra = append(extra, fmt.Sprintf("MAC65001:%s", net.HardwareAddr(v.Data).String()))
				}
			}
		}
		if len(extra) > 0 {
			qInfo += fmt.Sprintf(" [%s]", strings.Join(extra, " "))
		}
	}

	// Generate cache key based on query + ECS (to prevent cache poisoning between subnets)
	if len(r.Question) > 0 {
		q := r.Question[0]
		cacheKey = fmt.Sprintf("%s|%d|%d|%s", q.Name, q.Qtype, q.Qclass, ecsSubnet)
	}

	// 4. Cache Check
	if !*cacheDisabled && cacheKey != "" {
		if cachedResp := getFromCache(cacheKey, r.Id); cachedResp != nil {
			logRequest(r.Id, ip, mac, proto, meta, qInfo, "CACHE_HIT", "CACHE", 0, time.Since(start), cachedResp)
			w.WriteMsg(cachedResp)
			return
		}
	}

	// 5. Forward to Upstream (using Singleflight)
	callResult, shared := requestGroup.Do(cacheKey, func() callResult {
		resp, upstreamStr, rtt, err := forwardToUpstreams(ctx, msg)
		return callResult{msg: resp, upstreamStr: upstreamStr, rtt: rtt, err: err}
	})

	if callResult.err != nil {
		log.Printf("Error forwarding %s from %s: %v", qInfo, ip, callResult.err)
		dns.HandleFailed(w, r)
		return
	}

	resp := callResult.msg
	if !*cacheDisabled && resp != nil {
		addToCache(cacheKey, resp)
	}

	status := dns.RcodeToString[resp.Rcode]
	if shared {
		status = fmt.Sprintf("%s (COALESCED)", status)
	}

	logRequest(r.Id, ip, mac, proto, meta, qInfo, status, callResult.upstreamStr, callResult.rtt, time.Since(start), resp)

	// Fix ID to match the original request before replying
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

	// Log Query
	log.Printf("[QRY] QID:%d | Client:%s | MAC:%s | Proto:%s | Query:%s", qid, ip, macStr, protoLog, qInfo)

	// Log Forwarding Details (if applicable)
	if upstream != "" && upstream != "CACHE" {
		log.Printf("[FWD] QID:%d | Upstream:%s | RTT:%v | Query:%s | Response:%s", qid, upstream, upstreamRTT, qInfo, status)
	}

	// Log Response Details
	var answers []string
	if resp != nil {
		addRRs := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				// Format simple string representation of RR
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
	dnsCache.RLock()
	entry, found := dnsCache.items[key]
	dnsCache.RUnlock()

	if !found {
		log.Printf("[CACHE] MISS: Key=%s", key)
		return nil
	}

	now := time.Now()
	if now.After(entry.Expiration) {
		log.Printf("[CACHE] EXPIRED: Key=%s", key)
		return nil
	}

	// Update access time for LRU logic
	dnsCache.Lock()
	if e, ok := dnsCache.items[key]; ok {
		e.LastAccess = now
	}
	dnsCache.Unlock()

	msg := entry.Msg.Copy()
	msg.Id = reqID

	// Adjust TTL in response based on time spent in cache
	ttlDiff := uint32(entry.Expiration.Sub(now).Seconds())
	if ttlDiff <= 0 {
		return nil
	}

	log.Printf("[CACHE] HIT: Key=%s | Adjusted TTL: %ds", key, ttlDiff)

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
	// Don't cache failures or truncated messages
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	if msg.Truncated {
		return
	}

	// Calculate MinTTL to respect the upstream's wishes
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
	// Default negative caching (NXDOMAIN) to 60s
	if !foundTTL && msg.Rcode == dns.RcodeNameError {
		minTTL = 60
	} else if !foundTTL {
		return
	}

	dnsCache.Lock()
	defer dnsCache.Unlock()

	// Optimization: Smart LRU Eviction
	// If the cache is full, we need to make space.
	if len(dnsCache.items) >= *cacheSize {
		// 1. First, quickly prune anything that's already expired.
		now := time.Now()
		for k, v := range dnsCache.items {
			if now.After(v.Expiration) {
				delete(dnsCache.items, k)
			}
		}

		// 2. If still full, we use Random Sample Eviction (Approximate LRU).
		// Why? Because sorting 10,000 items to find the "absolute" oldest is O(N log N).
		// Picking 50 random items and killing the oldest among them is O(K) and effectively nearly as good.
		if len(dnsCache.items) >= *cacheSize {
			evictSmartLRU()
		}
	}

	now := time.Now()
	dnsCache.items[key] = &CacheEntry{
		Msg:        msg,
		Expiration: now.Add(time.Duration(minTTL) * time.Second),
		LastAccess: now,
	}
	log.Printf("[CACHE] ADD: Key=%s | MinTTL: %ds", key, minTTL)
}

func evictSmartLRU() {
	// Target removing 5% of cache to prevent thrashing
	toRemove := *cacheSize / 20
	if toRemove < 10 {
		toRemove = 10
	}

	const sampleSize = 50 // Check 50 items to find a victim
	
	for i := 0; i < toRemove; i++ {
		if len(dnsCache.items) == 0 {
			break
		}

		var oldestKey string
		var oldestTime time.Time
		first := true
		count := 0

		// Map iteration in Go is random. We rely on this property!
		// Just iterating 'sampleSize' times gives us a random sample.
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
	
	log.Printf("[CACHE] EVICTION: Smart LRU removed ~%d items", toRemove)
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
		// Optimization: io.ReadAll allocates a new buffer. 
		// For max performance, could use a pooled buffer and io.Copy, but ReadAll is safer for standard HTTP handlers.
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
	dw := &dohResponseWriter{w: w, r: r, localAddr: localAddr}
	processDNSRequest(ctx, dw, msg, proto, r.Host)
}

func handleDoQSession(sess quic.Connection) {
	sni := sess.ConnectionState().TLS.ServerName
	for {
		// DoQ handles multiple streams per connection
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(str quic.Stream) {
			defer str.Close()

			ctx, cancel := context.WithTimeout(context.Background(), *queryTimeout)
			defer cancel()

			// Read 2-byte length
			lBuf := make([]byte, 2)
			if _, err := io.ReadFull(str, lBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lBuf)

			// Use buffer pool for reading the payload
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
			dw := &doqResponseWriter{stream: str, remoteAddr: sess.RemoteAddr()}
			processDNSRequest(ctx, dw, msg, "DoQ", sni)
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
		log.Printf("ARP refresh error: %v", err)
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
		log.Printf("ARP refresh error: %v", err)
		return
	}
	// Optimization: Use pre-compiled Regex variable (windowsARPRegex)
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
		log.Printf("ARP refresh error: %v", err)
		return
	}
	// Optimization: Use pre-compiled Regex variable (darwinARPRegex)
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
			continue // Skip to overwrite
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
	// Optimization: Type switch is faster than SplitHostPort string manipulation
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
	
	// Optimization: Use buffer pool + Coalesced write
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

