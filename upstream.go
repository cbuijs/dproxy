/*
File: upstream.go
Description: Defines the Upstream struct and handles downstream connection logic, pooling, and protocol-specific exchanges.
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
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Upstream struct {
	URL         *url.URL
	Proto       string
	Host        string
	Port        string
	BootstrapIP string
	Path        string
	ResolvedIPs []net.IP
	rtt         int64
	lastProbe   int64 // Unix timestamp in nanoseconds
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

func (p *DoQPool) cleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			// Close all connections on shutdown
			p.mu.Lock()
			for _, sess := range p.sessions {
				sess.conn.CloseWithError(0, "shutdown")
			}
			p.sessions = make(map[string]*doqSession)
			p.mu.Unlock()
			return
		case <-ticker.C:
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
}

// --- Bootstrap DNS Cache ---

type bootstrapCacheEntry struct {
	ips       []net.IP
	timestamp time.Time
}

var (
	bootstrapCache   = make(map[string]*bootstrapCacheEntry)
	bootstrapCacheMu sync.RWMutex
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
		log.Printf("Upstream %s using bootstrap IP: %s", up.String(), bootstrap)
	} else if net.ParseIP(host) != nil {
		up.ResolvedIPs = []net.IP{net.ParseIP(host)}
		log.Printf("Upstream %s using direct IP: %s", up.String(), host)
	} else {
		log.Printf("Resolving hostname %s using bootstrap servers...", host)
		ips, err := resolveHostnameWithBootstrap(host, ipVersion)
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

func resolveHostnameWithBootstrap(hostname string, preferredVersion string) ([]net.IP, error) {
	// Check cache first
	if cachedIPs, found := getBootstrapCache(hostname); found {
		log.Printf("[BOOTSTRAP] Using cached resolution for %s: %v (age: %v)", 
			hostname, cachedIPs, time.Since(bootstrapCache[hostname].timestamp).Round(time.Second))
		return cachedIPs, nil
	}

	var allIPs []net.IP
	var lastErr error

	version := preferredVersion
	if version == "" {
		version = config.Bootstrap.IPVersion
	}

	useIPv4 := version == "ipv4" || version == "both"
	useIPv6 := version == "ipv6" || version == "both"

	log.Printf("[BOOTSTRAP] Resolving hostname: %s (IP version: %s)", hostname, version)

	for i, bootstrap := range bootstrapServers {
		log.Printf("[BOOTSTRAP] Attempting resolution via bootstrap server [%d/%d]: %s", 
			i+1, len(bootstrapServers), bootstrap)

		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

		if useIPv4 {
			// OPTIMIZATION: Use message pool
			msg := getMsg()
			msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
			
			log.Printf("[BOOTSTRAP] Querying %s for %s (A record)", bootstrap, hostname)
			resp, rtt, err := c.Exchange(msg, bootstrap)
			putMsg(msg) // Release request message
			
			if err == nil && resp != nil {
				log.Printf("[BOOTSTRAP] Response from %s for %s: %d answers (RTT: %v)", 
					bootstrap, hostname, len(resp.Answer), rtt)
				
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						allIPs = append(allIPs, a.A)
						log.Printf("[BOOTSTRAP]   Found A record: %s → %s", hostname, a.A.String())
					}
				}
			} else {
				lastErr = err
				log.Printf("[BOOTSTRAP] Failed to resolve %s (A) via %s: %v", hostname, bootstrap, err)
			}
		}

		if useIPv6 {
			// OPTIMIZATION: Use message pool
			msg := getMsg()
			msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
			
			log.Printf("[BOOTSTRAP] Querying %s for %s (AAAA record)", bootstrap, hostname)
			resp, rtt, err := c.Exchange(msg, bootstrap)
			putMsg(msg) // Release request message
			
			if err == nil && resp != nil {
				log.Printf("[BOOTSTRAP] Response from %s for %s: %d answers (RTT: %v)", 
					bootstrap, hostname, len(resp.Answer), rtt)
				
				for _, ans := range resp.Answer {
					if aaaa, ok := ans.(*dns.AAAA); ok {
						allIPs = append(allIPs, aaaa.AAAA)
						log.Printf("[BOOTSTRAP]   Found AAAA record: %s → %s", hostname, aaaa.AAAA.String())
					}
				}
			} else {
				lastErr = err
				log.Printf("[BOOTSTRAP] Failed to resolve %s (AAAA) via %s: %v", hostname, bootstrap, err)
			}
		}

		if len(allIPs) > 0 {
			log.Printf("[BOOTSTRAP] Successfully resolved %s to %d IP(s) using %s", 
				hostname, len(allIPs), bootstrap)
			break
		}
	}

	if len(allIPs) == 0 {
		if lastErr != nil {
			log.Printf("[BOOTSTRAP] FAILED to resolve %s: %v", hostname, lastErr)
			return nil, fmt.Errorf("failed to resolve %s: %w", hostname, lastErr)
		}
		log.Printf("[BOOTSTRAP] FAILED to resolve %s: no IPs found", hostname)
		return nil, fmt.Errorf("no IPs found for %s", hostname)
	}

	// Cache the successful resolution
	setBootstrapCache(hostname, allIPs)
	log.Printf("[BOOTSTRAP] Resolution complete for %s: %v (cached for %v)", 
		hostname, allIPs, bootstrapCacheTTL)
	
	return allIPs, nil
}

// --- Exchange ---

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
		if r.err == nil && r.resp != nil {
			u.updateRTT(rtt, r.resp.Rcode)
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

	// OPTIMIZATION: Use message pool for the response
	// The caller (doExchange -> executeExchange) passes this back up.
	// We CANNOT putMsg() here. It will be collected eventually by GC 
	// or we'd need a complex lifecycle management since it flows up to process.go
	// However, we save the allocation of new(dns.Msg) which is still a win.
	resp := getMsg()
	
	if err := resp.Unpack(respBuf); err != nil {
		putMsg(resp) // Error case: can return immediately
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
	
	// Set required headers for DoH
	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")
	hReq.Header.Set("User-Agent", "dproxy/1.0")  // Add User-Agent to prevent 403

	hResp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		// Read response body for better error context
		bodyBytes, _ := io.ReadAll(hResp.Body)
		bodyPreview := string(bodyBytes)
		if len(bodyPreview) > 100 {
			bodyPreview = bodyPreview[:100] + "..."
		}
		
		return nil, fmt.Errorf("DoH error: %d (%s) - %s", 
			hResp.StatusCode, http.StatusText(hResp.StatusCode), bodyPreview)
	}

	respBody, err := io.ReadAll(hResp.Body)
	if err != nil {
		return nil, err
	}

	// OPTIMIZATION: Use message pool for the response
	resp := getMsg()
	if err := resp.Unpack(respBody); err != nil {
		putMsg(resp)
		return nil, err
	}
	return resp, nil
}

