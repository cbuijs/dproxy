/*
File: upstream.go
Version: 2.20.0 (RDNS Integration)
Description: Defines the Upstream struct and handles downstream protocol exchange.
             UPDATED: resolveClientName now utilizes globalRDNS for caching reverse lookups.
*/

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
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
	defaultCBFailureThreshold = 3                // Default number of failures before opening circuit
	cbProbeInterval           = 5 * time.Second  // Faster probe interval for recovery
	bootstrapRefresh          = 10 * time.Minute // Interval to refresh upstream IPs
	defaultMaxConcurrency     = 50               // Default max in-flight requests per upstream
)

// Global TLS Session Cache to enable Session Resumption (Fast Handshakes)
var globalSessionCache = tls.NewLRUClientSessionCache(2048)

// Upstream Actions
const (
	UpstreamActionForward = iota
	UpstreamActionBlock
	UpstreamActionDrop
)

type Upstream struct {
	Action int

	URL         *url.URL
	Proto       string
	Host        string // Template host (may contain {client-ip})
	Port        string
	BootstrapIP string // Raw bootstrap string
	Path        string // Template path

	// Optimized Flags
	IsDynamic bool // True if Host or Path contains '{'

	DOHMethod   string
	Retries     int
	CBThreshold uint32

	resolvedIPs        []net.IP
	resolvedIPsLock    sync.RWMutex
	lastResolution     time.Time
	bootstrapIPVersion string

	rtt       int64
	lastProbe int64

	httpClient *http.Client
	h3Client   *http.Client

	limiter *rate.Limiter

	semaphore chan struct{}
	maxConns  int

	cbFailures  atomic.Uint32
	cbOpen      atomic.Bool
	cbNextProbe atomic.Int64

	probing atomic.Bool
}

func (u *Upstream) String() string {
	if u.Action == UpstreamActionBlock {
		return "BLOCK"
	}
	if u.Action == UpstreamActionDrop {
		return "DROP"
	}
	s := u.Proto + "://" + u.Host + ":" + u.Port + u.Path
	if u.BootstrapIP != "" {
		s += "#" + u.BootstrapIP
	}
	return s
}

func (u *Upstream) DynamicString(rc *RequestContext) string {
	if u.Action != UpstreamActionForward {
		return u.String()
	}
	host, path := u.getDynamicConfig(rc)
	s := u.Proto + "://" + host + ":" + u.Port + path
	if u.BootstrapIP != "" {
		s += "#" + u.BootstrapIP
	}
	return s
}

func (u *Upstream) Allow() bool {
	if u.Action != UpstreamActionForward {
		return true
	}
	if u.limiter == nil {
		return true
	}
	return u.limiter.Allow()
}

// Optimized sanitization (No Regex)
func sanitizeClientID(s string) string {
	// Fast path check
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	// Allocation only if needed
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// sanitizeClientName allows dots, dashes, underscores for hostnames
func sanitizeClientName(s string) string {
	// Fast path check
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	// Allocation only if needed
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// resolveClientName attempts to resolve the client IP to a hostname.
// Uses local hosts cache first, then falls back to the global RDNS cache.
// UPDATED: Now uses globalRDNS for system lookups to enable caching.
func resolveClientName(clientIP net.IP) string {
	if clientIP == nil {
		return ""
	}

	var fqdn string

	// 1. Check local hosts first (fast/memory)
	if config != nil && config.Routing.DefaultRule.parsedHosts != nil {
		names := config.Routing.DefaultRule.parsedHosts.GetHostnames(clientIP)
		if len(names) > 0 {
			fqdn = names[0]
		}
	}

	// 2. Fallback to global RDNS cache (System Resolver + Caching)
	if fqdn == "" {
		fqdn = globalRDNS.GetHostname(clientIP)
	}

	if fqdn == "" {
		return ""
	}

	// Clean up FQDN
	fqdn = strings.TrimSuffix(fqdn, ".")
	
	// Extract Hostname (everything before the first dot)
	if idx := strings.Index(fqdn, "."); idx != -1 {
		return fqdn[:idx]
	}
	return fqdn
}

// isValidHostname checks RFC 1035 constraints: total length <= 253, label length <= 63
func isValidHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

func (u *Upstream) getDynamicConfig(rc *RequestContext) (string, string) {
	if !u.IsDynamic {
		return u.Host, u.Path
	}

	clientIP := "0-0-0-0"
	if rc != nil && rc.ClientIP != nil {
		clientIP = sanitizeClientID(rc.ClientIP.String())
	}

	clientMAC := "00-00-00-00-00-00"
	if rc != nil {
		if rc.ClientMAC != nil {
			clientMAC = sanitizeClientID(rc.ClientMAC.String())
		} else if rc.ClientEDNSMAC != nil {
			clientMAC = sanitizeClientID(rc.ClientEDNSMAC.String())
		}
	}

	clientID := clientMAC
	if clientID == "00-00-00-00-00-00" {
		clientID = clientIP
	}

	clientName := ""
	if rc != nil && rc.ClientIP != nil {
		name := resolveClientName(rc.ClientIP)
		if name != "" {
			clientName = sanitizeClientName(name)
		}
	}

	// Fallback to client-ip if client-name is not available (empty)
	if clientName == "" {
		clientName = clientIP
	}

	// Replacement logic with validation flag
	apply := func(s string, isHostname bool) string {
		if !strings.Contains(s, "{") {
			return s
		}
		
		// Create result by replacing tags
		res := s
		res = strings.ReplaceAll(res, "{client-ip}", clientIP)
		res = strings.ReplaceAll(res, "{client-mac}", clientMAC)
		res = strings.ReplaceAll(res, "{client-id}", clientID)
		res = strings.ReplaceAll(res, "{client-name}", clientName)

		// If this is a hostname, enforce length limits
		if isHostname && !isValidHostname(res) {
			if IsDebugEnabled() {
				LogDebug("[UPSTREAM] Dynamic hostname length exceeded limit: %s", res)
			}
			return "invalid-dynamic-hostname"
		}
		return res
	}

	return apply(u.Host, true), apply(u.Path, false)
}

// --- Circuit Breaker ---

func (u *Upstream) IsHealthy() bool {
	if u.Action != UpstreamActionForward {
		return true
	}
	if !u.cbOpen.Load() {
		return true
	}
	if time.Now().UnixNano() >= u.cbNextProbe.Load() {
		return true
	}
	return false
}

func (u *Upstream) recordSuccess() {
	u.cbFailures.Store(0)
	if u.cbOpen.Load() {
		u.cbOpen.Store(false)
		LogInfo("[CIRCUIT] Upstream %s recovered (Circuit Closed)", u.String())
	}
}

func (u *Upstream) recordFailure() {
	newFailures := u.cbFailures.Add(1)
	threshold := u.CBThreshold
	if threshold == 0 {
		threshold = defaultCBFailureThreshold
	}
	if newFailures >= threshold {
		if !u.cbOpen.Swap(true) {
			LogWarn("[CIRCUIT] Upstream %s failed %d times. Circuit OPEN. Backoff %v", u.String(), newFailures, cbProbeInterval)
		}
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	} else if u.cbOpen.Load() {
		u.cbNextProbe.Store(time.Now().Add(cbProbeInterval).UnixNano())
	}
}

func (u *Upstream) TryLockProbe() bool { return u.probing.CompareAndSwap(false, true) }
func (u *Upstream) UnlockProbe()       { u.probing.Store(false) }

// --- Metrics ---

func (u *Upstream) updateRTT(d time.Duration, rcode int) {
	newVal := int64(d)
	old := atomic.LoadInt64(&u.rtt)
	atomic.StoreInt64(&u.lastProbe, time.Now().UnixNano())
	if rcode != dns.RcodeSuccess && rcode != dns.RcodeNameError {
		return
	}
	if old == 0 {
		atomic.StoreInt64(&u.rtt, newVal)
		return
	}
	avg := int64(float64(old)*0.7 + float64(newVal)*0.3)
	atomic.StoreInt64(&u.rtt, avg)
}

func (u *Upstream) getRTT() int64 { return atomic.LoadInt64(&u.rtt) }
func (u *Upstream) getLastProbeTime() time.Time {
	nanos := atomic.LoadInt64(&u.lastProbe)
	if nanos == 0 { return time.Time{} }
	return time.Unix(0, nanos)
}

// --- Bootstrap DNS Logic ---

func (u *Upstream) resolveIPs() []net.IP {
	if u.Action != UpstreamActionForward {
		return nil
	}
	u.resolvedIPsLock.RLock()
	ips := u.resolvedIPs
	u.resolvedIPsLock.RUnlock()
	if len(ips) > 0 { return ips }
	u.refreshIPs()
	u.resolvedIPsLock.RLock()
	defer u.resolvedIPsLock.RUnlock()
	return u.resolvedIPs
}

func (u *Upstream) refreshIPs() {
	if u.Action != UpstreamActionForward {
		return
	}

	if u.BootstrapIP != "" {
		var parsedIPs []net.IP
		parts := strings.Split(u.BootstrapIP, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if ip := net.ParseIP(part); ip != nil {
				parsedIPs = append(parsedIPs, ip)
			}
		}
		if len(parsedIPs) > 0 {
			u.setIPs(parsedIPs)
			return
		}
	}

	if ip := net.ParseIP(u.Host); ip != nil {
		u.setIPs([]net.IP{ip})
		return
	}

	// Do not attempt to resolve dynamic hosts globally
	if u.IsDynamic {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := resolveHostnameWithBootstrap(ctx, u.Host, u.bootstrapIPVersion)
	if err != nil {
		LogWarn("[BOOTSTRAP] Failed to resolve %s: %v", u.Host, err)
		return
	}

	u.setIPs(ips)
	if IsDebugEnabled() {
		LogDebug("[BOOTSTRAP] Refreshed %s -> %v", u.Host, ips)
	}
}

func (u *Upstream) setIPs(ips []net.IP) {
	u.resolvedIPsLock.Lock()
	u.resolvedIPs = ips
	u.lastResolution = time.Now()
	u.resolvedIPsLock.Unlock()
}

func (u *Upstream) startBootstrapRefresher() {
	if u.Action != UpstreamActionForward {
		return
	}
	go u.refreshIPs()
	go func() {
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
	if raw == "BLOCK" {
		return &Upstream{Action: UpstreamActionBlock, Host: "BLOCK", Proto: "internal"}, nil
	}
	if raw == "DROP" {
		return &Upstream{Action: UpstreamActionDrop, Host: "DROP", Proto: "internal"}, nil
	}

	// Template Substitution for URL Parsing placeholders
	templateMap := map[string]string{
		"{client-ip}":   "var-client-ip",
		"{client-mac}":  "var-client-mac",
		"{client-id}":   "var-client-id",
		"{client-name}": "var-client-name",
	}

	parts := strings.Split(raw, "#")
	uString := parts[0]
	bootstrap := ""
	if len(parts) > 1 {
		bootstrap = parts[1]
	}

	tempString := uString
	for k, v := range templateMap {
		tempString = strings.ReplaceAll(tempString, k, v)
	}

	uUrl, err := url.Parse(tempString)
	if err != nil {
		return nil, err
	}

	query := uUrl.Query()
	qpsLimit := 0
	if qpsStr := query.Get("qps"); qpsStr != "" {
		if v, err := strconv.Atoi(qpsStr); err == nil && v > 0 {
			qpsLimit = v
		}
		query.Del("qps")
	}

	maxConns := defaultMaxConcurrency
	if mcStr := query.Get("max_conns"); mcStr != "" {
		if v, err := strconv.Atoi(mcStr); err == nil && v > 0 {
			maxConns = v
		}
		query.Del("max_conns")
	}

	dohMethod := "POST"
	if m := query.Get("method"); m != "" {
		upper := strings.ToUpper(m)
		if upper == "GET" || upper == "POST" {
			dohMethod = upper
		}
		query.Del("method")
	}

	uUrl.RawQuery = query.Encode()

	host := uUrl.Hostname()
	path := uUrl.Path
	
	for k, v := range templateMap {
		host = strings.ReplaceAll(host, v, k)
		path = strings.ReplaceAll(path, v, k)
	}

	isDynamic := strings.Contains(host, "{") || strings.Contains(path, "{")

	up := &Upstream{
		Action:             UpstreamActionForward,
		URL:                uUrl,
		Host:               host,
		BootstrapIP:        bootstrap,
		Path:               path,
		IsDynamic:          isDynamic,
		bootstrapIPVersion: ipVersion,
		DOHMethod:          dohMethod,
		semaphore:          make(chan struct{}, maxConns),
		maxConns:           maxConns,
	}

	if v := query.Get("retries"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i >= 0 {
			up.Retries = i
		}
		query.Del("retries")
	}

	if v := query.Get("cb_min"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			up.CBThreshold = uint32(i)
		}
		query.Del("cb_min")
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
	up.Proto = proto

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
	up.Port = port

	if (proto == "doh" || proto == "doh3") && up.Path == "" {
		up.Path = "/dns-query"
	}

	if qpsLimit > 0 {
		burst := qpsLimit * 2
		if burst < 10 { burst = 10 }
		up.limiter = rate.NewLimiter(rate.Limit(qpsLimit), burst)
	}

	timeoutDuration := 5 * time.Second
	if timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
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
				MaxIdleConnsPerHost: maxConns + 10,
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

	up.startBootstrapRefresher()
	return up, nil
}

func resolveHostnameWithBootstrap(ctx context.Context, hostname string, preferredVersion string) ([]net.IP, error) {
	if len(bootstrapServers) == 0 {
		return nil, errors.New("no bootstrap servers configured")
	}

	var qTypes []uint16
	if preferredVersion == "ipv4" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeA)
	}
	if preferredVersion == "ipv6" || preferredVersion == "both" {
		qTypes = append(qTypes, dns.TypeAAAA)
	}

	type result struct {
		ips []net.IP
		err error
	}
	resultCh := make(chan result, len(bootstrapServers))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, server := range bootstrapServers {
		go func(bootstrapServer string) {
			if ctx.Err() != nil { return }
			var ips []net.IP
			var err error
			c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

			for _, qType := range qTypes {
				if ctx.Err() != nil { return }
				msg := getMsg()
				msg.SetQuestion(dns.Fqdn(hostname), qType)
				r, _, e := c.ExchangeContext(ctx, msg, bootstrapServer)
				putMsg(msg)

				if e != nil {
					err = e
					continue
				}
				if r != nil {
					for _, ans := range r.Answer {
						switch rec := ans.(type) {
						case *dns.A: ips = append(ips, rec.A)
						case *dns.AAAA: ips = append(ips, rec.AAAA)
						}
					}
				}
			}

			if len(ips) > 0 {
				select {
				case resultCh <- result{ips: ips, err: nil}:
					cancel()
				case <-ctx.Done():
				}
			} else {
				if err == nil { err = fmt.Errorf("no IPs found on %s", bootstrapServer) }
				select {
				case resultCh <- result{ips: nil, err: err}:
				case <-ctx.Done():
				}
			}
		}(server)
	}

	var lastErr error
	for i := 0; i < len(bootstrapServers); i++ {
		select {
		case res := <-resultCh:
			if res.ips != nil { return res.ips, nil }
			if res.err != nil { lastErr = res.err }
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("all bootstrap servers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no IPs found from any bootstrap server")
}

// --- Exchange Execution ---

func (u *Upstream) executeExchange(ctx context.Context, req *dns.Msg, reqCtx *RequestContext) (*dns.Msg, string, time.Duration, error) {
	if !u.Allow() {
		return nil, "", 0, fmt.Errorf("QPS limit exceeded for %s", u.String())
	}

	if !u.IsHealthy() {
		return nil, "", 0, fmt.Errorf("circuit open for %s", u.String())
	}

	select {
	case u.semaphore <- struct{}{}:
		defer func() { <-u.semaphore }()
	default:
		LogWarn("[UPSTREAM] Concurrency Limit Reached! Upstream: %s | Limit: %d connections", u.String(), u.maxConns)
		return nil, "", 0, fmt.Errorf("upstream busy (concurrency limit reached for %s)", u.String())
	}

	start := time.Now()
	ips := u.resolveIPs()
	attempts := 1 + u.Retries
	
	var resp *dns.Msg
	var err error
	var targetAddr string
	var successfulRTT time.Duration

	// Calculate Dynamic Hostname ONCE here.
	dynHost, dynPath := u.getDynamicConfig(reqCtx)

	for i := 0; i < attempts; i++ {
		if len(ips) > 0 {
			randomIP := ips[rand.IntN(len(ips))].String()
			targetAddr = net.JoinHostPort(randomIP, u.Port)
		} else {
			targetAddr = net.JoinHostPort(dynHost, u.Port)
		}

		// Pass the pre-calculated dynamic host/path
		resp, err = u.doExchange(ctx, req, targetAddr, reqCtx, dynHost, dynPath)
		if err == nil {
			successfulRTT = time.Since(start)
			break
		}
		
		if i < attempts-1 {
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				break
			}
			if IsDebugEnabled() {
				LogDebug("[UPSTREAM] Retry %d/%d for %s (%s) failed: %v", i+1, u.Retries, u.String(), targetAddr, err)
			}
			if isTimeoutError(err) {
				time.Sleep(50 * time.Millisecond)
			}
			continue
		}
	}

	if err == nil && resp != nil {
		u.recordSuccess()
		u.updateRTT(successfulRTT, resp.Rcode)
		return resp, targetAddr, successfulRTT, nil
	}

	rtt := time.Since(start)
	shouldRecordFailure := true
	if errors.Is(ctx.Err(), context.Canceled) {
		shouldRecordFailure = false
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		shouldRecordFailure = true
	} else if isTimeoutError(err) {
		shouldRecordFailure = true
	}

	if shouldRecordFailure {
		u.recordFailure()
	}

	return nil, targetAddr, rtt, err
}

func isTimeoutError(err error) bool {
    if err == nil { return false }
    if errors.Is(err, context.DeadlineExceeded) { return true }
    if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() { return true }
    return false
}

