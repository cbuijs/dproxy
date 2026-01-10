/*
File: server.go
Version: 1.6.0
Last Update: 2026-01-10
Description: Implements the protocol listeners.
             FIXED: DoQ (RFC 9250) compliance and robustness.
             - Added detection for 2-byte length prefix (Draft compatibility) to handle clients like 'q' that might send it.
             - Improved buffer handling.
             UPDATED: Enhanced logging.
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Constants
const (
	MaxDNSBodySize       = 65535 // Max size for a DNS message (64KB)
	MaxDoTPipelines      = 128   // Max concurrent requests per DoT connection
	DefaultServerTimeout = 5 * time.Second
)

// ServerShutdowner interface for graceful shutdown
type ServerShutdowner interface {
	Shutdown(ctx context.Context) error
	String() string
}

// DNSServerWrapper wraps dns.Server to implement ServerShutdowner
type DNSServerWrapper struct {
	*dns.Server
}

func (w *DNSServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.ShutdownContext(ctx)
}

func (w *DNSServerWrapper) String() string {
	return fmt.Sprintf("Protocol: DNS/%s | Addr: %s", strings.ToUpper(w.Net), w.Addr)
}

// HTTPServerWrapper wraps http.Server to implement ServerShutdowner
type HTTPServerWrapper struct {
	*http.Server
}

func (w *HTTPServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.Shutdown(ctx)
}

func (w *HTTPServerWrapper) String() string {
	return fmt.Sprintf("Protocol: DoH (HTTP/1.1&2) | Addr: %s | Path: /", w.Addr)
}

// HTTP3ServerWrapper wraps http3.Server to implement ServerShutdowner
type HTTP3ServerWrapper struct {
	*http3.Server
}

func (w *HTTP3ServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.Close()
}

func (w *HTTP3ServerWrapper) String() string {
	return fmt.Sprintf("Protocol: DoH3 (QUIC) | Addr: %s | Path: /", w.Addr)
}

// DoQServerWrapper wraps QUIC listener for DoQ
type DoQServerWrapper struct {
	listener *quic.Listener
	cancel   context.CancelFunc
	done     chan struct{}
	Addr     string
}

func (w *DoQServerWrapper) Shutdown(ctx context.Context) error {
	w.cancel()
	if w.listener != nil {
		w.listener.Close()
	}
	
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *DoQServerWrapper) String() string {
	return fmt.Sprintf("Protocol: DoQ | Addr: %s", w.Addr)
}

// DoTServerWrapper for custom SNI handling
type DoTServerWrapper struct {
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
	Addr     string
}

func (w *DoTServerWrapper) Shutdown(ctx context.Context) error {
	close(w.quit) // Signal accept loop to stop
	if w.listener != nil {
		w.listener.Close()
	}

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *DoTServerWrapper) String() string {
	return fmt.Sprintf("Protocol: DoT | Addr: %s", w.Addr)
}

func (w *DoTServerWrapper) acceptLoop() {
	for {
		conn, err := w.listener.Accept()
		if err != nil {
			select {
			case <-w.quit:
				return // Normal shutdown
			default:
				// Log real errors as Warn to ensure visibility of listener issues
				LogWarn("DoT Accept error: %v", err)
				continue
			}
		}

		w.wg.Add(1)
		go func(c net.Conn) {
			defer w.wg.Done()
			handleDoTConnection(c)
		}(conn)
	}
}

// idleConn wraps net.Conn to extend deadlines on activity
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

func startServers(wg *sync.WaitGroup, tlsConfig *tls.Config) []ServerShutdowner {
	var servers []ServerShutdowner

	// Shared HTTP Mux for all DoH listeners
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDoH)

	for _, l := range config.Server.Listeners {
		// Iterate over address list and port list
		for _, address := range l.Address {
			for _, port := range l.Port {
				// FIX: Use net.JoinHostPort to correctly handle IPv6 literals (e.g. [::1]:53)
				addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
				protocol := strings.ToLower(l.Protocol)

				// Start servers based on protocol
				switch protocol {
				case "dns", "udp":
					// UDP Listener
					wg.Add(1)
					udpServer := &dns.Server{Addr: addr, Net: "udp"}
					udpWrapper := &DNSServerWrapper{udpServer}
					
					udpServer.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
						ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
						defer cancel()
						reqCtx := &RequestContext{
							ServerIP:   getLocalIP(w.LocalAddr()),
							ServerPort: getLocalPort(w.LocalAddr()),
							Protocol:   "UDP",
						}
						processDNSRequest(ctx, w, r, reqCtx)
					})
					
					go func() {
						defer wg.Done()
						LogInfo("Starting Server [%s]", udpWrapper.String())
						if err := udpServer.ListenAndServe(); err != nil {
							LogError("Server [%s] stopped: %v", udpWrapper.String(), err)
						}
					}()
					servers = append(servers, udpWrapper)
				}

				switch protocol {
				case "dns", "tcp":
					// TCP Listener
					wg.Add(1)
					tcpServer := &dns.Server{Addr: addr, Net: "tcp"}
					tcpWrapper := &DNSServerWrapper{tcpServer}

					tcpServer.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
						ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
						defer cancel()
						reqCtx := &RequestContext{
							ServerIP:   getLocalIP(w.LocalAddr()),
							ServerPort: getLocalPort(w.LocalAddr()),
							Protocol:   "TCP",
						}
						processDNSRequest(ctx, w, r, reqCtx)
					})
					
					go func() {
						defer wg.Done()
						LogInfo("Starting Server [%s]", tcpWrapper.String())
						if err := tcpServer.ListenAndServe(); err != nil {
							LogError("Server [%s] stopped: %v", tcpWrapper.String(), err)
						}
					}()
					servers = append(servers, tcpWrapper)
				}

				if protocol == "dot" || protocol == "tls" {
					// DoT (DNS over TLS) Listener
					wg.Add(1)
					dotListener, err := tls.Listen("tcp", addr, tlsConfig)
					if err != nil {
						LogWarn("Failed to bind DoT listener on %s: %v", addr, err)
						wg.Done()
					} else {
						dotServer := &DoTServerWrapper{
							listener: dotListener,
							quit:     make(chan struct{}),
							Addr:     addr,
						}

						go func() {
							defer wg.Done()
							LogInfo("Starting Server [%s]", dotServer.String())
							dotServer.acceptLoop()
						}()
						servers = append(servers, dotServer)
					}
				}

				if protocol == "doq" || protocol == "quic" {
					// DoQ (DNS over QUIC) Listener
					wg.Add(1)
					doqCtx, doqCancel := context.WithCancel(context.Background())
					doqDone := make(chan struct{})
					doqWrapper := &DoQServerWrapper{cancel: doqCancel, done: doqDone, Addr: addr}
					
					go func() {
						defer wg.Done()
						defer close(doqDone)
						
						LogInfo("Starting Server [%s]", doqWrapper.String())
						listener, err := quic.ListenAddr(addr, tlsConfig, nil)
						if err != nil {
							LogError("Server [%s] listen error: %v", doqWrapper.String(), err)
							return
						}
						doqWrapper.listener = listener
						
						for {
							select {
							case <-doqCtx.Done():
								LogInfo("Server [%s] stopped", doqWrapper.String())
								return
							default:
								sess, err := listener.Accept(doqCtx)
								if err != nil {
									select {
									case <-doqCtx.Done():
										return
									default:
										LogWarn("DoQ accept error: %v", err)
										continue
									}
								}
								go handleDoQSession(sess)
							}
						}
					}()
					servers = append(servers, doqWrapper)
				}

				// HTTPS Listeners
				// "https" -> Enables both DoH (TCP) and DoH3 (UDP/QUIC)
				// "doh"   -> DoH (TCP) only
				// "doh3"  -> DoH3 (UDP/QUIC) only
				
				if protocol == "https" || protocol == "doh" {
					wg.Add(1)
					h1Server := &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}
					h1Wrapper := &HTTPServerWrapper{h1Server}

					go func() {
						defer wg.Done()
						LogInfo("Starting Server [%s]", h1Wrapper.String())
						if err := h1Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
							LogError("Server [%s] stopped: %v", h1Wrapper.String(), err)
						}
					}()
					servers = append(servers, h1Wrapper)
				}

				if protocol == "https" || protocol == "doh3" || protocol == "h3" {
					wg.Add(1)
					h3Server := &http3.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}
					h3Wrapper := &HTTP3ServerWrapper{h3Server}

					go func() {
						defer wg.Done()
						LogInfo("Starting Server [%s]", h3Wrapper.String())
						if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
							LogError("Server [%s] stopped: %v", h3Wrapper.String(), err)
						}
					}()
					servers = append(servers, h3Wrapper)
				}
			}
		}
	}

	return servers
}

func getTimeout() time.Duration {
	if config.Server.Timeout == "" {
		return DefaultServerTimeout
	}
	d, err := time.ParseDuration(config.Server.Timeout)
	if err != nil {
		return DefaultServerTimeout
	}
	return d
}

// --- Handlers ---

func handleDoTConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()

	// TLS Handshake to get SNI
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Handshake timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		LogWarn("DoT Handshake failed from %v: %v", remoteAddr, err)
		return
	}

	sni := tlsConn.ConnectionState().ServerName

	// Wrap for idle timeouts (10s default idle)
	iconn := &idleConn{
		Conn:    conn,
		timeout: 10 * time.Second,
	}
	// Clear handshake deadline
	conn.SetDeadline(time.Time{})

	// Manually handle the DNS messages on this connection
	dconn := new(dns.Conn)
	dconn.Conn = iconn

	// Mutex to serialize writes to the socket while allowing concurrent processing
	var writeMu sync.Mutex
	
	// SECURITY: Limit concurrent pipelined requests per connection
	sem := make(chan struct{}, MaxDoTPipelines)

	for {
		req, err := dconn.ReadMsg()
		if err != nil {
			if err != io.EOF {
				LogWarn("DoT Read error from %v: %v", remoteAddr, err)
			}
			return
		}

		// Acquire semaphore (blocking if limit reached)
		sem <- struct{}{}

		// OPTIMIZATION: Launch request in goroutine to allow pipelining
		go func(reqMsg *dns.Msg) {
			defer func() { <-sem }() // Release semaphore

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			
			reqCtx := &RequestContext{
				ServerIP:       getLocalIP(conn.LocalAddr()),
				ServerPort:     getLocalPort(conn.LocalAddr()),
				ServerHostname: sni, // SNI captured here
				Protocol:       "DoT",
			}

			// Pass the write mutex to the writer
			w := &dotResponseWriter{Conn: dconn, writeMu: &writeMu}
			processDNSRequest(ctx, w, reqMsg, reqCtx)
		}(req)
	}
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), getTimeout())
	defer cancel()
	remoteAddr := r.RemoteAddr

	// --- PATH VALIDATION LOGIC ---
	if config.Server.DOH.StrictPath {
		allowed := false
		for _, path := range config.Server.DOH.AllowedPaths {
			if r.URL.Path == path {
				allowed = true
				break
			}
		}
		if !allowed {
			LogWarn("DoH Path mismatch from %s: %s", remoteAddr, r.URL.Path)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}

	// OPTIMIZATION: Use message pool
	msg := getMsg()
	defer putMsg(msg)

	var err error

	proto := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	// SECURITY: Enforce max body size to prevent DoS via OOM
	r.Body = http.MaxBytesReader(w, r.Body, MaxDNSBodySize)

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			LogWarn("DoH Invalid Content-Type from %s: %s", remoteAddr, r.Header.Get("Content-Type"))
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		
		data, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			LogWarn("DoH Body Read failed from %s: %v", remoteAddr, readErr)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		err = msg.Unpack(data)
	case http.MethodGet:
		b64str := r.URL.Query().Get("dns")
		if b64str == "" {
			LogWarn("DoH Missing 'dns' param from %s", remoteAddr)
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		data, e := base64.RawURLEncoding.DecodeString(b64str)
		if e != nil {
			LogWarn("DoH Invalid Base64 from %s: %v", remoteAddr, e)
			http.Error(w, "Invalid base64", http.StatusBadRequest)
			return
		}
		err = msg.Unpack(data)
	default:
		LogWarn("DoH Invalid Method from %s: %s", remoteAddr, r.Method)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		LogWarn("DoH Unpack failed from %s: %v", remoteAddr, err)
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
	remoteAddr := sess.RemoteAddr()

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(str quic.Stream) {
			defer str.Close() // Ensures FIN is sent after we are done writing

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()

			buf := bufPool.Get().([]byte)
			defer bufPool.Put(buf)
			
			// Reset buffer length to cap to allow reading into it
			buf = buf[:cap(buf)]
			
			// Read loop to handle fragmented frames or large packets
			totalBytes := 0
			for {
				if totalBytes >= MaxDNSBodySize {
					LogWarn("DoQ message too large from %v", remoteAddr)
					return
				}
				
				n, err := str.Read(buf[totalBytes:])
				totalBytes += n
				
				if err != nil {
					if err == io.EOF {
						break // Normal end of message
					}
					LogWarn("DoQ Read error from %v: %v", remoteAddr, err)
					return
				}
				
				// If buffer is full and we haven't hit EOF, we might need to grow
				if totalBytes == cap(buf) {
					if len(buf)*2 > MaxDNSBodySize {
						LogWarn("DoQ message too large from %v", remoteAddr)
						return
					}
					newBuf := make([]byte, len(buf)*2)
					copy(newBuf, buf)
					bufPool.Put(buf) // Return old buffer
					buf = newBuf     // Reassign to new buffer
				}
			}

			if totalBytes == 0 {
				return
			}
			
			// ROBUSTNESS: Check for draft compatibility (2-byte length prefix)
			// Some tools/drafts send [Length(2)][Message...].
			// RFC 9250 sends [Message...].
			// Detection: If 1st 2 bytes = (TotalLen - 2), assume prefix and strip.
			unpackBuf := buf[:totalBytes]
			if totalBytes > 2 {
				possibleLen := binary.BigEndian.Uint16(buf[:2])
				if int(possibleLen) == totalBytes-2 {
					// Likely a length prefix (Draft DoQ or client quirk)
					unpackBuf = buf[2:totalBytes]
					LogDebug("DoQ: Detected and stripped length prefix from %v", remoteAddr)
				}
			}

			// OPTIMIZATION: Use message pool
			msg := getMsg()
			defer putMsg(msg)
			
			if err := msg.Unpack(unpackBuf); err != nil {
				LogWarn("DoQ Unpack failed from %v: %v", remoteAddr, err)
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

// --- Response Writers ---

// dotResponseWriter adapts dns.Conn to dns.ResponseWriter
// UPDATED: Includes a mutex to prevent concurrent writes on the shared connection
type dotResponseWriter struct {
	*dns.Conn
	writeMu *sync.Mutex
}

func (w *dotResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	buf := bufPool.Get().([]byte)
	out, err := msg.PackBuffer(buf[:0])
	if err != nil {
		bufPool.Put(buf)
		return err
	}
	
	_, err = w.Conn.Write(out)
	bufPool.Put(out)
	return err
}

func (w *dotResponseWriter) Hijack() {
	// No-op for DoT
}

func (w *dotResponseWriter) TsigStatus() error { return nil }
func (w *dotResponseWriter) TsigTimersOnly(bool) {}

type doqResponseWriter struct {
	stream     quic.Stream
	remoteAddr net.Addr
}

func (w *doqResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *doqResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	buf := bufPool.Get().([]byte)
	
	// RFC 9250: No length prefix for DoQ
	// Pack directly into buffer
	packed, err := msg.PackBuffer(buf[:0])
	if err != nil {
		bufPool.Put(buf)
		return err
	}

	_, err = w.stream.Write(packed)
	bufPool.Put(packed)
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
	buf := bufPool.Get().([]byte)
	out, err := msg.PackBuffer(buf[:0])
	if err != nil {
		bufPool.Put(buf)
		return err
	}
	
	w.w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.w.Write(out)
	bufPool.Put(out)
	return err
}
func (w *dohResponseWriter) Write(b []byte) (int, error) { return w.w.Write(b) }
func (w *dohResponseWriter) Close() error                { return nil }
func (w *dohResponseWriter) TsigStatus() error           { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)         {}
func (w *dohResponseWriter) Hijack()                     {}

