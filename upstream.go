/*
File: upstream.go
Description: Defines the Upstream struct and handles downstream connection logic, pooling, and protocol-specific exchanges.
             Includes Circuit Breaker logic to handle failing upstreams efficiently.
             UPDATED: Increased connection pool size and enabled TLS Session Resumption for high performance.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Circuit Breaker Constants
const (
	cbFailureThreshold = 3                // Number of failures before opening circuit
	cbProbeInterval    = 30 * time.Second // Time to wait before probing an open circuit
)

// Global TLS Session Cache to enable Session Resumption (Fast Handshakes)
var globalSessionCache = tls.NewLRUClientSessionCache(1024)

type Upstream struct {
	URL         *url.URL
	Proto       string
	Host        string // This is the template host (e.g. {client-id}.dns.com)
	Port        string
	BootstrapIP string
	Path        string // This is the template path
	ResolvedIPs []net.IP
	rtt         int64
	lastProbe   int64 // Unix timestamp in nanoseconds
	httpClient  *http.Client
	h3Client    *http.Client

	// Circuit Breaker State
	cbFailures  atomic.Uint32
	cbOpen      atomic.Bool  // true = Open (Unhealthy), false = Closed (Healthy)
	cbNextProbe atomic.Int64 // UnixNano timestamp when next probe is allowed
}

func (u *Upstream) String() string {
	s := fmt.Sprintf("%s://%s:%s%s", u.Proto, u.Host, u.Port, u.Path)
	if u.BootstrapIP != "" {
		s += fmt.Sprintf("#%s", u.BootstrapIP)
	}
	return s
}

// DynamicString returns the upstream URL with variables ({client-ip}, etc.) replaced
// based on the provided RequestContext. Used for logging actual request targets.
func (u *Upstream) DynamicString(rc *RequestContext) string {
	host, path := u.getDynamicConfig(rc)
	s := fmt.Sprintf("%s://%s:%s%s", u.Proto, host, u.Port, path)
	if u.BootstrapIP != "" {
		s += fmt.Sprintf("#%s", u.BootstrapIP)
	}
	return s
}

// --- Variable Replacement Helper ---

var sanitizeRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func sanitizeClientID(s string) string {
	return sanitizeRegex.ReplaceAllString(s, "-")
}

func (u *Upstream) getDynamicConfig(rc *RequestContext) (string, string) {
	// Fast path: no variables
	if !strings.Contains(u.Host, "{") && !strings.Contains(u.Path, "{") {
		return u.Host, u.Path
	}

	clientIP := "0-0-0-0"
	if rc != nil && rc.ClientIP != nil {
		clientIP = sanitizeClientID(rc.ClientIP.String())
	}

	clientMAC := "00-00-00-00-00-00"
	if rc != nil && rc.ClientMAC != nil {
		clientMAC = sanitizeClientID(rc.ClientMAC.String())
	}

	replacer := strings.NewReplacer(
		"{client-ip}", clientIP,
		"{client-mac}", clientMAC,
	)

	return replacer.Replace(u.Host), replacer.Replace(u.Path)
}

// --- Circuit Breaker Logic ---

// IsHealthy returns true if the upstream is healthy (Circuit Closed)
// or if it is time to probe (Circuit Open but interval passed).
func (u *Upstream) IsHealthy() bool {
	// If circuit is closed, it's healthy
	if !u.cbOpen.Load() {
		return true
	}

	// If circuit is open, check if we are allowed to probe (Half-Open state)
	if time.Now().UnixNano() >= u.cbNextProbe.Load() {
		LogDebug("[CIRCUIT] Upstream %s entering HALF-OPEN state (Probing)", u.String())
		return true
	}

	return false
}

func (u *Upstream) recordSuccess() {
	// Reset failures on success
	u.cbFailures.Store(0)

	// If circuit was open, close it
	if u.cbOpen.Load() {
		u.cbOpen.Store(false)
		LogInfo("[CIRCUIT] Upstream %s recovered (Circuit Closed)", u.String())
	}
}

func (u *Upstream) recordFailure() {
	newFailures := u.cbFailures.Add(1)

	// Check if we hit the threshold to open the circuit
	if newFailures >= cbFailureThreshold {
		// Only log if we are transitioning from Closed to Open
		if !u.cbOpen.Swap(true) {
			LogWarn("[CIRCUIT] Upstream %s failed %d times. Circuit OPEN. Backoff %v", u.String(), newFailures, cbProbeInterval)
		}
		// Reset/Extend the probe timer
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	} else if u.cbOpen.Load() {
		// If already open (probing failed), push back next probe
		LogDebug("[CIRCUIT] Upstream %s probe failed. Circuit remains OPEN. Backoff extended %v", u.String(), cbProbeInterval)
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	}
}

// --- Metrics ---

func (u *Upstream) updateRTT(d time.Duration, rcode int) {
	newVal := int64(d)
	old := atomic.LoadInt64(&u.rtt)

	// Update last probe time regardless of rcode
	atomic.StoreInt64(&u.lastProbe, time.Now().UnixNano())

	// Only update RTT for successful responses (NOERROR)
	// NXDOMAIN, SERVFAIL, etc. can have different latency characteristics
	if rcode != 0 { // dns.RcodeSuccess == 0
		return
	}

	if old == 0 {
		atomic.StoreInt64(&u.rtt, newVal)
		return
	}

	// Exponential moving average: 70% old, 30% new
	avg := int64(float64(old)*0.7 + float64(newVal)*0.3)
	atomic.StoreInt64(&u.rtt, avg)
}

func (u *Upstream) getRTT() int64 {
	return atomic.LoadInt64(&u.rtt)
}

func (u *Upstream) getLastProbeTime() time.Time {
	nanos := atomic.LoadInt64(&u.lastProbe)
	if nanos == 0 {
		return time.Time{} // Zero time if never probed
	}
	return time.Unix(0, nanos)
}

// --- TCP/DoT Connection Pool ---

type TCPConnPool struct {
	mu    sync.Mutex
	conns map[string][]*dns.Conn
}

var tcpPool = &TCPConnPool{
	conns: make(map[string][]*dns.Conn),
}

// Get retrieves a cached connection or returns nil
func (p *TCPConnPool) Get(key string) *dns.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.conns[key]
	if len(list) > 0 {
		// Pop the last one
		conn := list[len(list)-1]
		p.conns[key] = list[:len(list)-1]
		return conn
	}
	return nil
}

// Put returns a connection to the pool
func (p *TCPConnPool) Put(key string, conn *dns.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Limit pool size per upstream to prevent leaks
	// UPDATED: Increased from 5 to 128 to prevent connection churn under high load
	if len(p.conns[key]) >= 128 {
		conn.Close()
		return
	}
	p.conns[key] = append(p.conns[key], conn)
}

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
	// UPDATED: Include SNI in key to separate sessions for different client IDs
	poolKey := fmt.Sprintf("%s|%s", addr, tlsConf.ServerName)

	p.mu.RLock()
	sess, exists := p.sessions[poolKey]
	p.mu.RUnlock()

	if exists {
		sess.mu.Lock()
		select {
		case <-sess.conn.Context().Done():
			sess.mu.Unlock()
			p.mu.Lock()
			delete(p.sessions, poolKey)
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
	p.sessions[poolKey] = &doqSession{conn: conn, lastUsed: time.Now()}
	p.mu.Unlock()

	return conn, nil
}

func (p *DoQPool) cleanup(ctx context.Context) {
	LogInfo("[DOQ] Starting DoQ connection pool maintenance")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Close all connections on shutdown
			p.mu.Lock()
			count := 0
			for _, sess := range p.sessions {
				sess.conn.CloseWithError(0, "shutdown")
				count++
			}
			p.sessions = make(map[string]*doqSession)
			p.mu.Unlock()
			LogInfo("[DOQ] Closed %d connections on shutdown", count)
			return
		case <-ticker.C:
			p.mu.Lock()
			closedCount := 0
			for addr, sess := range p.sessions {
				sess.mu.Lock()
				// Idle time limit: 2 minutes
				if time.Since(sess.lastUsed) > 2*time.Minute {
					sess.conn.CloseWithError(0, "idle timeout")
					delete(p.sessions, addr)
					closedCount++
				}
				sess.mu.Unlock()
			}
			p.mu.Unlock()
			if closedCount > 0 {
				LogDebug("[DOQ] Cleaned up %d idle DoQ connections", closedCount)
			}
		}
	}
}

// --- Bootstrap DNS Cache ---

type bootstrapCacheEntry struct {
	ips       []net.IP
	timestamp time.Time
}

var (
	bootstrapCache    = make(map[string]*bootstrapCacheEntry)
	bootstrapCacheMu  sync.RWMutex
	bootstrapCacheTTL = 5 * time.Minute // Cache bootstrap results for 5 minutes
)

func getBootstrapCache(hostname string) ([]net.IP, bool) {
	bootstrapCacheMu.RLock()
	defer bootstrapCacheMu.RUnlock()

	entry, exists := bootstrapCache[hostname]
	if !exists {
		return nil, false
	}

	// Check if cache entry is still valid
	if time.Since(entry.timestamp) > bootstrapCacheTTL {
		return nil, false
	}

	return entry.ips, true
}

func setBootstrapCache(hostname string, ips []net.IP) {
	bootstrapCacheMu.Lock()
	defer bootstrapCacheMu.Unlock()

	bootstrapCache[hostname] = &bootstrapCacheEntry{
		ips:       ips,
		timestamp: time.Now(),
	}
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
		LogDebug("Upstream %s using bootstrap IP: %s", up.String(), bootstrap)
	} else if net.ParseIP(host) != nil {
		up.ResolvedIPs = []net.IP{net.ParseIP(host)}
		LogDebug("Upstream %s using direct IP: %s", up.String(), host)
	} else if !strings.Contains(host, "{") {
		LogDebug("Resolving hostname %s using bootstrap servers...", host)
		ips, err := resolveHostnameWithBootstrap(host, ipVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve upstream hostname %s: %w", host, err)
		}
		up.ResolvedIPs = ips
		LogDebug("Upstream %s resolved to %d IPs: %v", up.String(), len(ips), ips)
	} else {
		LogWarn("Upstream %s contains variables but no bootstrap IP. Resolution may fail at runtime if not provided.", up.String())
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
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
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
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
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

func resolveHostnameWithBootstrap(hostname string, preferredVersion string) ([]net.IP, error) {
	if cachedIPs, found := getBootstrapCache(hostname); found {
		LogDebug("[BOOTSTRAP] Using cached resolution for %s: %v (age: %v)",
			hostname, cachedIPs, time.Since(bootstrapCache[hostname].timestamp).Round(time.Second))
		return cachedIPs, nil
	}

	var allIPs []net.IP
	var lastErr error

	version := preferredVersion
	if version == "" {
		version = config.Bootstrap.IPVersion
	}

	var qTypes []uint16
	if version == "ipv4" || version == "both" {
		qTypes = append(qTypes, dns.TypeA)
	}
	if version == "ipv6" || version == "both" {
		qTypes = append(qTypes, dns.TypeAAAA)
	}

	LogDebug("[BOOTSTRAP] Resolving hostname: %s (IP version: %s)", hostname, version)

	for i, bootstrap := range bootstrapServers {
		LogDebug("[BOOTSTRAP] Attempting resolution via bootstrap server [%d/%d]: %s",
			i+1, len(bootstrapServers), bootstrap)

		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

		for _, qType := range qTypes {
			msg := getMsg()
			msg.SetQuestion(dns.Fqdn(hostname), qType)

			typeName := dns.TypeToString[qType]
			LogDebug("[BOOTSTRAP] Querying %s for %s (%s record)", bootstrap, hostname, typeName)

			resp, rtt, err := c.Exchange(msg, bootstrap)
			putMsg(msg)

			if err == nil && resp != nil {
				LogDebug("[BOOTSTRAP] Response from %s for %s (%s): %d answers (RTT: %v)",
					bootstrap, hostname, typeName, len(resp.Answer), rtt)

				for _, ans := range resp.Answer {
					switch r := ans.(type) {
					case *dns.A:
						allIPs = append(allIPs, r.A)
						LogDebug("[BOOTSTRAP]   Found A record: %s → %s", hostname, r.A.String())
					case *dns.AAAA:
						allIPs = append(allIPs, r.AAAA)
						LogDebug("[BOOTSTRAP]   Found AAAA record: %s → %s", hostname, r.AAAA.String())
					}
				}
			} else {
				lastErr = err
				LogDebug("[BOOTSTRAP] Failed to resolve %s (%s) via %s: %v", hostname, typeName, bootstrap, err)
			}
		}

		if len(allIPs) > 0 {
			LogDebug("[BOOTSTRAP] Successfully resolved %s to %d IP(s) using %s",
				hostname, len(allIPs), bootstrap)
			break
		}
	}

	if len(allIPs) == 0 {
		if lastErr != nil {
			LogError("[BOOTSTRAP] FAILED to resolve %s: %v", hostname, lastErr)
			return nil, fmt.Errorf("failed to resolve %s: %w", hostname, lastErr)
		}
		LogError("[BOOTSTRAP] FAILED to resolve %s: no IPs found", hostname)
		return nil, fmt.Errorf("no IPs found for %s", hostname)
	}

	setBootstrapCache(hostname, allIPs)
	LogDebug("[BOOTSTRAP] Resolution complete for %s: %v (cached for %v)",
		hostname, allIPs, bootstrapCacheTTL)

	return allIPs, nil
}

// --- Exchange ---

func (u *Upstream) executeExchange(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, time.Duration, error) {
	if !u.IsHealthy() {
		return nil, 0, fmt.Errorf("circuit open for %s", u.String())
	}

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
		resp, err := u.doExchange(ctx, req, targetAddr, reqCtx)
		done <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancellation (e.g. from Race strategy) will now cascade
		// down to connections via the fix in dialTCP/exchangeTCPPool/exchangeDoQ
		return nil, time.Since(start), ctx.Err()
	case r := <-done:
		rtt := time.Since(start)

		if r.err == nil && r.resp != nil {
			u.recordSuccess()
			u.updateRTT(rtt, r.resp.Rcode)
		} else {
			u.recordFailure()
		}

		return r.resp, rtt, r.err
	}
}

func (u *Upstream) doExchange(ctx context.Context, req *dns.Msg, targetAddr string, reqCtx *RequestContext) (*dns.Msg, error) {
	timeout := getTimeout()
	insecure := config.Server.InsecureUpstream

	switch u.Proto {
	case "udp":
		c := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := c.ExchangeContext(ctx, req, targetAddr)
		return resp, err

	case "tcp", "dot":
		return u.exchangeTCPPool(ctx, req, targetAddr, u.Proto == "dot", insecure, reqCtx)

	case "doq":
		return u.exchangeDoQ(ctx, req, targetAddr, reqCtx)

	case "doh", "doh3":
		return u.exchangeDoH(ctx, req, reqCtx)
	}

	return nil, errors.New("unsupported protocol")
}

func (u *Upstream) exchangeTCPPool(ctx context.Context, req *dns.Msg, addr string, useTLS bool, insecure bool, reqCtx *RequestContext) (*dns.Msg, error) {
	dynamicHost, _ := u.getDynamicConfig(reqCtx)

	poolKey := fmt.Sprintf("%s|%s", u.Proto, addr)
	if useTLS {
		poolKey = fmt.Sprintf("%s|%s|%s", u.Proto, addr, dynamicHost)
	}

	// Helper to attempt an exchange on a specific connection with a context watcher
	attempt := func(c *dns.Conn) (*dns.Msg, error) {
		doneCh := make(chan struct{})
		defer close(doneCh)

		// Watch for context cancellation to abort I/O for THIS connection
		go func() {
			select {
			case <-ctx.Done():
				c.Close()
			case <-doneCh:
			}
		}()

		c.SetDeadline(time.Now().Add(getTimeout()))
		if err := c.WriteMsg(req); err != nil {
			return nil, err
		}
		return c.ReadMsg()
	}

	// 1. Try pooled connection
	conn := tcpPool.Get(poolKey)
	if conn != nil {
		resp, err := attempt(conn)
		if err == nil {
			go tcpPool.Put(poolKey, conn)
			return resp, nil
		}
		// Failure on pooled connection
		conn.Close()
		// If cancelled, stop
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		LogDebug("[UPSTREAM] Cached conn failed (%v), retrying dial...", err)
	}

	// 2. Dial new connection
	// Use new context-aware dialer
	var err error
	conn, err = u.dialTCP(ctx, addr, useTLS, insecure, dynamicHost)
	if err != nil {
		return nil, err
	}

	// 3. Try new connection
	resp, err := attempt(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Success
	if ctx.Err() == nil {
		go tcpPool.Put(poolKey, conn)
	} else {
		conn.Close()
	}

	return resp, nil
}

func (u *Upstream) dialTCP(ctx context.Context, addr string, useTLS bool, insecure bool, sniHost string) (*dns.Conn, error) {
	timeout := getTimeout()
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Use DialContext so the handshake can be aborted if the context is cancelled
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		LogWarn("[UPSTREAM] TCP Dial failed to %s: %v", addr, err)
		return nil, err
	}

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         sniHost,
			// UPDATED: Use shared session cache for faster re-connections (Session Resumption)
			ClientSessionCache: globalSessionCache,
		}
		
		tlsConn := tls.Client(conn, tlsConfig)
		
		// Perform TLS handshake respecting context
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			LogWarn("[UPSTREAM] DoT Handshake failed to %s (SNI: %s): %v", addr, sniHost, err)
			return nil, err
		}
		
		conn = net.Conn(tlsConn)
	}

	return &dns.Conn{Conn: conn}, nil
}

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetAddr string, reqCtx *RequestContext) (*dns.Msg, error) {
	insecure := config.Server.InsecureUpstream
	dynamicHost, _ := u.getDynamicConfig(reqCtx)

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         dynamicHost,
		NextProtos:         []string{"doq"},
		// UPDATED: Use shared session cache
		ClientSessionCache: globalSessionCache,
	}

	sess, err := doqPool.Get(ctx, targetAddr, tlsConf)
	if err != nil {
		LogWarn("[UPSTREAM] DoQ Dial/GetSession failed to %s (SNI: %s): %v", targetAddr, dynamicHost, err)
		return nil, err
	}

	// OpenStreamSync respects context
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// Watch for cancellation to abort stream I/O
	doneCh := make(chan struct{})
	defer close(doneCh)
	
	go func() {
		select {
		case <-ctx.Done():
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.CancelWrite(quic.StreamErrorCode(0))
		case <-doneCh:
		}
	}()

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

	resp := getMsg()
	if err := resp.Unpack(respBuf); err != nil {
		putMsg(resp)
		return nil, err
	}
	return resp, nil
}

func (u *Upstream) exchangeDoH(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, error) {
	client := u.httpClient
	if u.Proto == "doh3" {
		client = u.h3Client
	}

	buf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	dynHost, dynPath := u.getDynamicConfig(reqCtx)
	urlStr := fmt.Sprintf("https://%s:%s%s", dynHost, u.Port, dynPath)

	// NewRequestWithContext ensures the HTTP request is cancelled when ctx is cancelled
	hReq, err := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")
	hReq.Header.Set("User-Agent", "dproxy/1.0")

	hResp, err := client.Do(hReq)
	if err != nil {
		LogWarn("[UPSTREAM] DoH/H3 Request failed to %s: %v", urlStr, err)
		return nil, err
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(hResp.Body)
		bodyPreview := string(bodyBytes)
		if len(bodyPreview) > 100 {
			bodyPreview = bodyPreview[:100] + "..."
		}

		err = fmt.Errorf("DoH error: %d (%s) - %s",
			hResp.StatusCode, http.StatusText(hResp.StatusCode), bodyPreview)

		LogWarn("[UPSTREAM] DoH/H3 HTTP error from %s: %v", urlStr, err)
		return nil, err
	}

	respBody, err := io.ReadAll(hResp.Body)
	if err != nil {
		return nil, err
	}

	resp := getMsg()
	if err := resp.Unpack(respBody); err != nil {
		putMsg(resp)
		return nil, err
	}
	return resp, nil
}

