/*
File: upstream.go
Description: Defines the Upstream struct and handles downstream connection logic, pooling, and protocol-specific exchanges.
             Includes Circuit Breaker logic to handle failing upstreams efficiently.
             OPTIMIZED: Implemented Background Bootstrap Resolution to remove DNS lookups from the hot path.
             OPTIMIZED: Circuit Breaker now trips on Timeouts to fail-over faster from slow upstreams.
             OPTIMIZED: TCP/DoT Pool connection handling improved with stricter deadlining.
             OPTIMIZED: HTTP/2 Transport tuned for higher concurrency.
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
	cbProbeInterval    = 10 * time.Second // Faster probe interval (was 30s)
	maxDoQSessions     = 8                // Allow up to 8 concurrent QUIC sessions per upstream
	tcpIdlePoolSize    = 512              // Max idle TCP connections to hold per upstream
	bootstrapRefresh   = 10 * time.Minute // Interval to refresh upstream IPs
)

// Global TLS Session Cache to enable Session Resumption (Fast Handshakes)
var globalSessionCache = tls.NewLRUClientSessionCache(2048)

// packBufPool is a buffer pool to minimize allocations during DoQ framing.
// It stores *[]byte to allow resizing the underlying slice.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

type Upstream struct {
	URL         *url.URL
	Proto       string
	Host        string // Template host
	Port        string
	BootstrapIP string
	Path        string // Template path
	
	// ResolvedIPs is now managed by the background refresher
	resolvedIPs        []net.IP
	resolvedIPsLock    sync.RWMutex
	lastResolution     time.Time
	bootstrapIPVersion string // Cached IP version preference to avoid global config race

	rtt       int64
	lastProbe int64 // Unix timestamp in nanoseconds

	httpClient *http.Client
	h3Client   *http.Client

	// Circuit Breaker State
	cbFailures  atomic.Uint32
	cbOpen      atomic.Bool
	cbNextProbe atomic.Int64
}

func (u *Upstream) String() string {
	s := fmt.Sprintf("%s://%s:%s%s", u.Proto, u.Host, u.Port, u.Path)
	if u.BootstrapIP != "" {
		s += fmt.Sprintf("#%s", u.BootstrapIP)
	}
	return s
}

// DynamicString returns the upstream URL with variables replaced.
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
		if !u.cbOpen.Swap(true) {
			LogWarn("[CIRCUIT] Upstream %s failed %d times. Circuit OPEN. Backoff %v", u.String(), newFailures, cbProbeInterval)
		}
		// Reset/Extend the probe timer
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	} else if u.cbOpen.Load() {
		// If already open (probing failed), push back next probe
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	}
}

// --- Metrics ---

func (u *Upstream) updateRTT(d time.Duration, rcode int) {
	newVal := int64(d)
	old := atomic.LoadInt64(&u.rtt)

	atomic.StoreInt64(&u.lastProbe, time.Now().UnixNano())

	// Don't update RTT on errors or servfail to avoid skewing stats with "fast failures"
	if rcode != dns.RcodeSuccess && rcode != dns.RcodeNameError {
		return
	}

	if old == 0 {
		atomic.StoreInt64(&u.rtt, newVal)
		return
	}

	// Exponential moving average
	avg := int64(float64(old)*0.7 + float64(newVal)*0.3)
	atomic.StoreInt64(&u.rtt, avg)
}

func (u *Upstream) getRTT() int64 {
	return atomic.LoadInt64(&u.rtt)
}

func (u *Upstream) getLastProbeTime() time.Time {
	nanos := atomic.LoadInt64(&u.lastProbe)
	if nanos == 0 {
		return time.Time{}
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

func (p *TCPConnPool) Get(key string) *dns.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.conns[key]
	if len(list) > 0 {
		// LIFO (Stack) to keep hot connections hot
		conn := list[len(list)-1]
		p.conns[key] = list[:len(list)-1]
		return conn
	}
	return nil
}

func (p *TCPConnPool) Put(key string, conn *dns.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns[key]) >= tcpIdlePoolSize {
		conn.Close()
		return
	}
	p.conns[key] = append(p.conns[key], conn)
}

// --- DoQ Connection Pool ---

type DoQPool struct {
	mu       sync.RWMutex
	sessions map[string][]*doqSession
	nextIdx  map[string]int
}

type doqSession struct {
	conn     quic.Connection
	lastUsed time.Time
	mu       sync.Mutex
}

var doqPool = &DoQPool{
	sessions: make(map[string][]*doqSession),
	nextIdx:  make(map[string]int),
}

func (p *DoQPool) Get(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	poolKey := fmt.Sprintf("%s|%s", addr, tlsConf.ServerName)

	p.mu.Lock()
	// Clean closed sessions
	sessions := p.sessions[poolKey]
	validSessions := make([]*doqSession, 0, len(sessions))
	for _, s := range sessions {
		select {
		case <-s.conn.Context().Done():
			// Closed
		default:
			validSessions = append(validSessions, s)
		}
	}
	p.sessions[poolKey] = validSessions

	// If fewer than max sessions, dial a new one
	if len(validSessions) < maxDoQSessions {
		p.mu.Unlock()

		conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
			KeepAlivePeriod:    30 * time.Second,
			MaxIdleTimeout:     60 * time.Second,
			MaxIncomingStreams: 1000,
		})

		if err != nil {
			p.mu.Lock()
			// Fallback to existing if dial fails
			if len(p.sessions[poolKey]) > 0 {
				idx := p.nextIdx[poolKey] % len(p.sessions[poolKey])
				p.nextIdx[poolKey]++
				s := p.sessions[poolKey][idx]
				s.lastUsed = time.Now()
				p.mu.Unlock()
				return s.conn, nil
			}
			p.mu.Unlock()
			return nil, err
		}

		p.mu.Lock()
		newSess := &doqSession{conn: conn, lastUsed: time.Now()}
		p.sessions[poolKey] = append(p.sessions[poolKey], newSess)
		p.mu.Unlock()
		return conn, nil
	}

	idx := p.nextIdx[poolKey] % len(validSessions)
	p.nextIdx[poolKey]++
	sess := validSessions[idx]
	sess.lastUsed = time.Now()
	p.mu.Unlock()

	return sess.conn, nil
}

func (p *DoQPool) cleanup(ctx context.Context) {
	LogInfo("[DOQ] Starting DoQ connection pool maintenance")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			count := 0
			for _, sessions := range p.sessions {
				for _, sess := range sessions {
					sess.conn.CloseWithError(0, "shutdown")
					count++
				}
			}
			p.sessions = make(map[string][]*doqSession)
			p.mu.Unlock()
			LogInfo("[DOQ] Closed %d connections on shutdown", count)
			return
		case <-ticker.C:
			p.mu.Lock()
			closedCount := 0
			for addr, sessions := range p.sessions {
				var active []*doqSession
				for _, sess := range sessions {
					sess.mu.Lock()
					if time.Since(sess.lastUsed) > 2*time.Minute {
						sess.conn.CloseWithError(0, "idle timeout")
						closedCount++
					} else {
						active = append(active, sess)
					}
					sess.mu.Unlock()
				}
				if len(active) == 0 {
					delete(p.sessions, addr)
					delete(p.nextIdx, addr)
				} else {
					p.sessions[addr] = active
				}
			}
			p.mu.Unlock()
			if closedCount > 0 {
				LogDebug("[DOQ] Cleaned up %d idle DoQ connections", closedCount)
			}
		}
	}
}

// --- Bootstrap DNS Logic ---

// resolveIPs returns the cached IPs or refreshes them if empty.
// This is non-blocking if IPs are available.
func (u *Upstream) resolveIPs() []net.IP {
	u.resolvedIPsLock.RLock()
	ips := u.resolvedIPs
	u.resolvedIPsLock.RUnlock()

	if len(ips) > 0 {
		return ips
	}

	// If empty, try immediate resolve (blocking)
	u.refreshIPs()
	
	u.resolvedIPsLock.RLock()
	defer u.resolvedIPsLock.RUnlock()
	return u.resolvedIPs
}

// refreshIPs performs the actual DNS lookup
func (u *Upstream) refreshIPs() {
	// Skip if using explicit BootstrapIP
	if u.BootstrapIP != "" {
		ip := net.ParseIP(u.BootstrapIP)
		if ip != nil {
			u.setIPs([]net.IP{ip})
		}
		return
	}

	// Skip if Host is already an IP
	if ip := net.ParseIP(u.Host); ip != nil {
		u.setIPs([]net.IP{ip})
		return
	}

	// Skip if Host contains variables
	if strings.Contains(u.Host, "{") {
		return
	}

	// Perform Lookup
	// Use a short timeout for bootstrap to avoid hanging
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// FIX: Use u.bootstrapIPVersion instead of global config.Bootstrap.IPVersion
	// The global config might not be fully initialized when this runs in a goroutine
	// during startup.
	ips, err := resolveHostnameWithBootstrap(ctx, u.Host, u.bootstrapIPVersion)
	if err != nil {
		LogWarn("[BOOTSTRAP] Failed to resolve %s: %v", u.Host, err)
		return
	}

	u.setIPs(ips)
	LogDebug("[BOOTSTRAP] Refreshed %s -> %v", u.Host, ips)
}

func (u *Upstream) setIPs(ips []net.IP) {
	u.resolvedIPsLock.Lock()
	u.resolvedIPs = ips
	u.lastResolution = time.Now()
	u.resolvedIPsLock.Unlock()
}

// startBootstrapRefresher starts the background loop
func (u *Upstream) startBootstrapRefresher() {
	// Initial resolution
	go u.refreshIPs()

	go func() {
		// Use a randomized ticker to prevent thundering herd
		jitter := time.Duration(rand.Int64N(60)) * time.Second
		time.Sleep(jitter)
		
		ticker := time.NewTicker(bootstrapRefresh)
		defer ticker.Stop()

		for range ticker.C {
			u.refreshIPs()
		}
	}()
}

// --- Upstream Parsing ---

func parseUpstream(raw string, ipVersion string, insecure bool, timeout string) (*Upstream, error) {
	parts := strings.Split(raw, "#")
	uString := parts[0]
	bootstrap := ""
	if len(parts) > 1 {
		bootstrap = parts[1]
	}

	uUrl, err := url.Parse(uString)
	if err != nil {
		return nil, err
	}

	proto := strings.ToLower(uUrl.Scheme)
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

	host := uUrl.Hostname()
	port := uUrl.Port()
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

	path := uUrl.Path
	if (proto == "doh" || proto == "doh3") && path == "" {
		path = "/dns-query"
	}

	// FIX: Initialize bootstrapIPVersion to avoid nil dereference in refreshIPs
	up := &Upstream{
		URL: uUrl, Proto: proto, Host: host,
		Port: port, BootstrapIP: bootstrap, Path: path,
		bootstrapIPVersion: ipVersion,
	}

	// Initialize HTTP clients
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
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 256, // Optimized: Allow high concurrency
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
			},
		}
	}

	if proto == "doh3" {
		up.h3Client = &http.Client{
			Timeout: timeoutDuration,
			Transport: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				QuicConfig: &quic.Config{
					KeepAlivePeriod: 30 * time.Second,
					MaxIdleTimeout:  60 * time.Second,
				},
			},
		}
	}

	// Start background IP resolution
	up.startBootstrapRefresher()

	return up, nil
}

func resolveHostnameWithBootstrap(ctx context.Context, hostname string, preferredVersion string) ([]net.IP, error) {
	// This function now just wraps the logic to query the bootstrap servers
	// It is called by the background refresher
	
	var allIPs []net.IP
	var lastErr error

	var qTypes []uint16
	if preferredVersion == "ipv4" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeA)
	}
	if preferredVersion == "ipv6" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeAAAA)
	}

	for _, bootstrap := range bootstrapServers {
		// Use a very short timeout for individual bootstrap queries
		// We don't want to stall the refresher for too long
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

		for _, qType := range qTypes {
			msg := getMsg()
			msg.SetQuestion(dns.Fqdn(hostname), qType)

			// Use the passed context to allow cancellation
			resp, _, err := c.ExchangeContext(ctx, msg, bootstrap)
			putMsg(msg)

			if err == nil && resp != nil {
				for _, ans := range resp.Answer {
					switch r := ans.(type) {
					case *dns.A:
						allIPs = append(allIPs, r.A)
					case *dns.AAAA:
						allIPs = append(allIPs, r.AAAA)
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
			return nil, lastErr
		}
		return nil, fmt.Errorf("no IPs found")
	}

	return allIPs, nil
}

// --- Exchange ---

func (u *Upstream) executeExchange(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, time.Duration, error) {
	if !u.IsHealthy() {
		return nil, 0, fmt.Errorf("circuit open for %s", u.String())
	}

	start := time.Now()

	// Use cached IPs - No DNS Lookup in Hot Path!
	ips := u.resolveIPs()
	targetHost := u.Host
	if len(ips) > 0 {
		targetHost = ips[rand.IntN(len(ips))].String()
	}
	targetAddr := net.JoinHostPort(targetHost, u.Port)

	resp, err := u.doExchange(ctx, req, targetAddr, reqCtx)
	rtt := time.Since(start)

	if err == nil && resp != nil {
		u.recordSuccess()
		u.updateRTT(rtt, resp.Rcode)
		return resp, rtt, nil
	}

	// OPTIMIZATION: Context Deadline Exceeded implies a slow upstream.
	// We MUST trip the circuit breaker to force failover/race strategies to pick
	// a healthier upstream.
	shouldRecordFailure := true

	// Special case: If the client cancelled, we shouldn't punish the upstream.
	if errors.Is(ctx.Err(), context.Canceled) {
		shouldRecordFailure = false
	} else if errors.Is(err, context.DeadlineExceeded) {
		// But if it was a DeadlineExceeded, it means the upstream was too slow.
		// Record it!
		shouldRecordFailure = true
	}

	if shouldRecordFailure {
		u.recordFailure()
	}

	return nil, rtt, err
}

func (u *Upstream) doExchange(ctx context.Context, req *dns.Msg, targetAddr string, reqCtx *RequestContext) (*dns.Msg, error) {
	timeout := getTimeout()
	insecure := config.Server.InsecureUpstream

	switch u.Proto {
	case "udp":
		c := &dns.Client{
			Net:     "udp",
			Timeout: timeout,
			UDPSize: 4096, // Avoid truncation
		}
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

	// Helper to perform the exchange
	attempt := func(c *dns.Conn) (*dns.Msg, error) {
		// Set aggressive deadines for the individual operations to fail fast
		// if the connection is dead, rather than waiting for the global context
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(getTimeout())
		}
		
		c.SetDeadline(deadline)
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
		// Connection likely dead/closed
		conn.Close()
		LogDebug("[UPSTREAM] Cached TCP conn failed, retrying dial: %v", err)
	}

	// 2. Dial new
	var err error
	conn, err = u.dialTCP(ctx, addr, useTLS, insecure, dynamicHost)
	if err != nil {
		return nil, err
	}

	resp, err := attempt(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Only pool if context is not yet expired
	if ctx.Err() == nil {
		go tcpPool.Put(poolKey, conn)
	} else {
		conn.Close()
	}

	return resp, nil
}

func (u *Upstream) dialTCP(ctx context.Context, addr string, useTLS bool, insecure bool, sniHost string) (*dns.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   getTimeout(),
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         sniHost,
			ClientSessionCache: globalSessionCache,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		// Explicit handshake to catch crypto errors early
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
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
		ClientSessionCache: globalSessionCache,
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

	// DoQ Framing
	fullLen := 2 + len(buf)
	sendBuf := packBufPool.Get().(*[]byte)
	// Ensure capacity
	if cap(*sendBuf) < fullLen {
		*sendBuf = make([]byte, fullLen)
	} else {
		*sendBuf = (*sendBuf)[:fullLen]
	}
	defer packBufPool.Put(sendBuf)

	binary.BigEndian.PutUint16(*sendBuf, uint16(len(buf)))
	copy((*sendBuf)[2:], buf)

	// Set deadline based on context
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(getTimeout())
	}
	stream.SetDeadline(deadline)

	if _, err := stream.Write(*sendBuf); err != nil {
		return nil, err
	}

	// Read Length
	lBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lBuf)

	// Read Body
	respBuf := packBufPool.Get().(*[]byte)
	if cap(*respBuf) < int(length) {
		*respBuf = make([]byte, length)
	} else {
		*respBuf = (*respBuf)[:length]
	}
	defer packBufPool.Put(respBuf)

	if _, err := io.ReadFull(stream, *respBuf); err != nil {
		return nil, err
	}

	resp := getMsg()
	if err := resp.Unpack(*respBuf); err != nil {
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

	hReq, err := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")
	hReq.Header.Set("User-Agent", "dproxy/3.0")

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

	resp := getMsg()
	if err := resp.Unpack(respBody); err != nil {
		putMsg(resp)
		return nil, err
	}
	return resp, nil
}

