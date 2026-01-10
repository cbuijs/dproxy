/*
FILENAME:    upstream.go
VERSION:     2.5.0
LAST UPDATE: 2026-01-10
SUMMARY:     Defines the Upstream struct and handles downstream protocol exchange.
CHANGES:     - REFACTORED: Strict RFC 9250 Compliance.
             - Added dedicated 'writeDoQMsg' and 'readDoQMsg' to avoid buffer abuse.
             - Explicitly handles 2-byte length prefixing in separate I/O calls.
             - Correctly closes stream (FIN) after writing query.
             - Re-added readDoQMsg/writeDoQMsg definitions to fix "undefined" errors.
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/time/rate"
)

// Circuit Breaker Constants
const (
	cbFailureThreshold = 3                // Number of failures before opening circuit
	cbProbeInterval    = 10 * time.Second // Faster probe interval
	bootstrapRefresh   = 10 * time.Minute // Interval to refresh upstream IPs

	// Generic User-Agent to mimic a standard browser.
	GenericUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Global TLS Session Cache to enable Session Resumption (Fast Handshakes)
var globalSessionCache = tls.NewLRUClientSessionCache(2048)

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

	// Rate Limiter
	limiter *rate.Limiter

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

// Allow checks if the upstream has capacity for a request (QPS limit).
func (u *Upstream) Allow() bool {
	if u.limiter == nil {
		return true
	}
	return u.limiter.Allow()
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

// --- Bootstrap DNS Logic ---

// resolveIPs returns the cached IPs or refreshes them if empty.
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

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

	// Extract QPS from query params if present
	qpsLimit := 0
	if qpsStr := uUrl.Query().Get("qps"); qpsStr != "" {
		if v, err := strconv.Atoi(qpsStr); err == nil && v > 0 {
			qpsLimit = v
		}
	}

	// Clean up query params from stored URL to avoid clutter
	if len(uUrl.RawQuery) > 0 {
		q := uUrl.Query()
		q.Del("qps")
		uUrl.RawQuery = q.Encode()
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

	up := &Upstream{
		URL: uUrl, Proto: proto, Host: host,
		Port: port, BootstrapIP: bootstrap, Path: path,
		bootstrapIPVersion: ipVersion,
	}

	// Init Rate Limiter if QPS configured
	if qpsLimit > 0 {
		// Burst size 2x QPS or min 10
		burst := qpsLimit * 2
		if burst < 10 {
			burst = 10
		}
		up.limiter = rate.NewLimiter(rate.Limit(qpsLimit), burst)
		LogInfo("[UPSTREAM] Configured QPS limit for %s: %d (Burst: %d)", up.String(), qpsLimit, burst)
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
	if len(bootstrapServers) == 0 {
		return nil, errors.New("no bootstrap servers configured")
	}

	// Determine query types based on preference
	var qTypes []uint16
	if preferredVersion == "ipv4" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeA)
	}
	if preferredVersion == "ipv6" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeAAAA)
	}

	// Result container
	type result struct {
		ips []net.IP
		err error
	}

	// We use a buffered channel to avoid leaking goroutines
	resultCh := make(chan result, len(bootstrapServers))

	// Create a child context to cancel other requests once one succeeds
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Launch a goroutine for each bootstrap server
	for _, server := range bootstrapServers {
		go func(bootstrapServer string) {
			// Check context before starting (fail fast)
			if ctx.Err() != nil {
				return
			}

			var ips []net.IP
			var err error

			// Try all required query types against this server
			c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

			for _, qType := range qTypes {
				// Check context again between queries
				if ctx.Err() != nil {
					return
				}

				msg := getMsg()
				msg.SetQuestion(dns.Fqdn(hostname), qType)

				r, _, e := c.ExchangeContext(ctx, msg, bootstrapServer)
				putMsg(msg)

				if e != nil {
					err = e
					// If one type fails, we might still want the other?
					// Usually if a server is down, both fail.
					// But let's continue to try to get partial results if possible?
					continue
				}

				if r != nil {
					for _, ans := range r.Answer {
						switch rec := ans.(type) {
						case *dns.A:
							ips = append(ips, rec.A)
						case *dns.AAAA:
							ips = append(ips, rec.AAAA)
						}
					}
				}
			}

			// If we found IPs, it's a success
			if len(ips) > 0 {
				select {
				case resultCh <- result{ips: ips, err: nil}:
					cancel() // Cancel others immediately
				case <-ctx.Done():
				}
			} else {
				// If no IPs, report error (or nil if it was just empty response)
				if err == nil {
					err = fmt.Errorf("no IPs found on %s", bootstrapServer)
				}
				select {
				case resultCh <- result{ips: nil, err: err}:
				case <-ctx.Done():
				}
			}
		}(server)
	}

	// Wait for results
	var lastErr error
	failureCount := 0

	for i := 0; i < len(bootstrapServers); i++ {
		select {
		case res := <-resultCh:
			if res.ips != nil {
				return res.ips, nil
			}
			if res.err != nil {
				lastErr = res.err
			}
			failureCount++
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all bootstrap servers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no IPs found from any bootstrap server")
}

// --- Exchange ---

func (u *Upstream) executeExchange(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	// Check QPS Limit
	if !u.Allow() {
		return nil, "", 0, fmt.Errorf("QPS limit exceeded for %s", u.String())
	}

	if !u.IsHealthy() {
		return nil, "", 0, fmt.Errorf("circuit open for %s", u.String())
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
		return resp, targetAddr, rtt, nil
	}

	shouldRecordFailure := true
	if errors.Is(ctx.Err(), context.Canceled) {
		shouldRecordFailure = false
	} else if errors.Is(err, context.DeadlineExceeded) {
		shouldRecordFailure = true
	}

	if shouldRecordFailure {
		u.recordFailure()
	}

	return nil, targetAddr, rtt, err
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

	attempt := func(c *dns.Conn) (*dns.Msg, error) {
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

	conn := tcpPool.Get(poolKey)
	if conn != nil {
		resp, err := attempt(conn)
		if err == nil {
			go tcpPool.Put(poolKey, conn)
			return resp, nil
		}
		conn.Close()
		LogDebug("[UPSTREAM] Cached TCP conn failed, retrying dial: %v", err)
	}

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

	// Open a bidirectional stream
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	
	// Ensure we handle stream closure if anything goes wrong during write/read
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(getTimeout())
	}
	stream.SetDeadline(deadline)

	// WRITE REQUEST
	if err := writeDoQMsg(stream, req); err != nil {
		return nil, fmt.Errorf("failed to write DoQ request: %w", err)
	}
	
	// CRITICAL RFC 9250: "The client MUST close the stream after sending the query."
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stream write side: %w", err)
	}

	// READ RESPONSE
	resp, err := readDoQMsg(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoQ response: %w", err)
	}

	return resp, nil
}

func (u *Upstream) exchangeDoH(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, error) {
	client := u.httpClient
	if u.Proto == "doh3" {
		client = u.h3Client
	}

	// OPTIMIZATION: Use bufPool for packing
	buf := bufPool.Get().([]byte)

	// Fix: Reset buffer length to 0 so PackBuffer uses it as scratch and doesn't append after garbage
	packed, err := req.PackBuffer(buf[:0])
	if err != nil {
		bufPool.Put(buf)
		return nil, err
	}

	// Note: We cannot defer Put(buf) here because 'packed' might alias 'buf' or be a new slice.
	defer bufPool.Put(packed)

	dynHost, dynPath := u.getDynamicConfig(reqCtx)
	urlStr := fmt.Sprintf("https://%s:%s%s", dynHost, u.Port, dynPath)

	hReq, err := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}

	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")
	// UPDATED: Use generic Chrome agent to avoid blocking
	hReq.Header.Set("User-Agent", GenericUserAgent)

	hResp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH error: %d", hResp.StatusCode)
	}

	// SECURITY: Limit response reading to 64KB
	limitReader := io.LimitReader(hResp.Body, 65535)

	// OPTIMIZATION: Use bufPool for reading response
	respBuf := bufPool.Get().([]byte)
	defer bufPool.Put(respBuf)

	// Ensure we have capacity and reset slice length
	if cap(respBuf) < 4096 {
		respBuf = make([]byte, 4096)
	}

	readTarget := respBuf[:cap(respBuf)]
	bytesRead := 0

	for {
		if bytesRead == len(readTarget) {
			// Grow
			if len(readTarget) >= 65535 {
				return nil, fmt.Errorf("response too large")
			}
			newCap := len(readTarget) * 2
			if newCap > 65535 {
				newCap = 65535
			}
			newBuf := make([]byte, newCap)
			copy(newBuf, readTarget)
			readTarget = newBuf
		}

		n, err := limitReader.Read(readTarget[bytesRead:])
		bytesRead += n
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	resp := getMsg()
	if err := resp.Unpack(readTarget[:bytesRead]); err != nil {
		putMsg(resp)
		return nil, err
	}
	return resp, nil
}

// RFC 9250 Strictly Compliant Helper: writeDoQMsg
func writeDoQMsg(w io.Writer, msg *dns.Msg) error {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	// Pack DNS message (buffer offset 0)
	packed, err := msg.PackBuffer(buf[:0])
	if err != nil {
		return err
	}

	// Prepare Header [Length: 2 bytes]
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))

	// Write Header
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	// Write Body
	if _, err := w.Write(packed); err != nil {
		return err
	}

	return nil
}

// RFC 9250 Strictly Compliant Helper: readDoQMsg
func readDoQMsg(r io.Reader) (*dns.Msg, error) {
	// 1. Read Length (2 bytes, network byte order)
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	if length == 0 {
		return nil, fmt.Errorf("empty DoQ message")
	}
	if int(length) > 65535 {
		return nil, fmt.Errorf("DoQ message too large: %d", length)
	}

	// 2. Read Payload
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	
	if cap(buf) < int(length) {
		buf = make([]byte, length)
	}
	buf = buf[:length]

	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	msg := getMsg()
	if err := msg.Unpack(buf); err != nil {
		putMsg(msg)
		return nil, err
	}
	return msg, nil
}

