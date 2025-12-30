/*
File: server.go
Description: Implements the protocol listeners (UDP, TCP, DoT, DoQ, DoH/DoH3) and request handlers.
             UPDATED: Enhanced logging for failed connection attempts and protocol errors.
             UPDATED: Added String() method to ServerShutdowner for verbose shutdown logging.
             UPDATED: Consistent verbose logging for server startup.
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
	listenAddr := config.Server.ListenAddr
	udpPort := config.Server.Ports.UDP
	tlsPort := config.Server.Ports.TLS
	httpsPort := config.Server.Ports.HTTPS

	var servers []ServerShutdowner

	// UDP Listener
	wg.Add(1)
	udpServer := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "udp"}
	udpWrapper := &DNSServerWrapper{udpServer} // Create wrapper early for logging
	
	// Set the Handler *before* wrapping if possible, or just use udpServer inside closure
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

	// TCP Listener
	wg.Add(1)
	tcpServer := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "tcp"}
	tcpWrapper := &DNSServerWrapper{tcpServer} // Create wrapper early for logging

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

	// DoT (DNS over TLS) Listener - Custom Implementation for SNI
	wg.Add(1)
	dotAddr := fmt.Sprintf("%s:%d", listenAddr, tlsPort)
	dotListener, err := tls.Listen("tcp", dotAddr, tlsConfig)
	if err != nil {
		LogWarn("Failed to bind DoT listener: %v", err)
		wg.Done()
	} else {
		dotServer := &DoTServerWrapper{
			listener: dotListener,
			quit:     make(chan struct{}),
			Addr:     dotAddr,
		}

		go func() {
			defer wg.Done()
			LogInfo("Starting Server [%s]", dotServer.String())
			dotServer.acceptLoop()
		}()
		servers = append(servers, dotServer)
	}

	// DoQ (DNS over QUIC) Listener
	wg.Add(1)
	doqCtx, doqCancel := context.WithCancel(context.Background())
	doqDone := make(chan struct{})
	doqAddr := fmt.Sprintf("%s:%d", listenAddr, tlsPort)
	doqWrapper := &DoQServerWrapper{cancel: doqCancel, done: doqDone, Addr: doqAddr}
	
	go func() {
		defer wg.Done()
		defer close(doqDone)
		
		LogInfo("Starting Server [%s]", doqWrapper.String())
		listener, err := quic.ListenAddr(doqAddr, tlsConfig, nil)
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
						// Log as Warn to track connection issues
						LogWarn("DoQ accept error: %v", err)
						continue
					}
				}
				go handleDoQSession(sess)
			}
		}
	}()
	servers = append(servers, doqWrapper)

	// DoH / DoH3 (HTTP/HTTPS) Listener
	wg.Add(1)
	addr := fmt.Sprintf("%s:%d", listenAddr, httpsPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDoH)

	h3Server := &http3.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}
	h1Server := &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig}
	
	h1Wrapper := &HTTPServerWrapper{h1Server}
	h3Wrapper := &HTTP3ServerWrapper{h3Server}

	go func() {
		defer wg.Done()
		LogInfo("Starting Server [%s]", h1Wrapper.String())
		LogInfo("Starting Server [%s]", h3Wrapper.String())
		
		// Start HTTP/3 in a goroutine
		go func() {
			if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				LogError("Server [%s] stopped: %v", h3Wrapper.String(), err)
			}
		}()
		
		// Start HTTP/1.1 & HTTP/2
		if err := h1Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			LogError("Server [%s] stopped: %v", h1Wrapper.String(), err)
		}
	}()
	servers = append(servers, h1Wrapper)
	servers = append(servers, h3Wrapper)

	return servers
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
		// UPDATED: LogWarn for visibility
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

	for {
		req, err := dconn.ReadMsg()
		if err != nil {
			if err != io.EOF {
				// UPDATED: LogWarn for read errors (protocol violations, early closes)
				LogWarn("DoT Read error from %v: %v", remoteAddr, err)
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
		reqCtx := &RequestContext{
			ServerIP:       getLocalIP(conn.LocalAddr()),
			ServerPort:     getLocalPort(conn.LocalAddr()),
			ServerHostname: sni, // SNI captured here
			Protocol:       "DoT",
		}

		w := &dotResponseWriter{Conn: dconn}
		processDNSRequest(ctx, w, req, reqCtx)
		cancel()
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

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			LogWarn("DoH Invalid Content-Type from %s: %s", remoteAddr, r.Header.Get("Content-Type"))
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		data, _ := io.ReadAll(r.Body)
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
			// UPDATED: Log stream accept failures (could be connection teardown or protocol error)
			LogWarn("DoQ AcceptStream error from %v: %v", remoteAddr, err)
			return
		}
		go func(str quic.Stream) {
			defer str.Close()

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()

			lBuf := make([]byte, 2)
			if _, err := io.ReadFull(str, lBuf); err != nil {
				// UPDATED: Log read failures
				LogWarn("DoQ Read length failed from %v: %v", remoteAddr, err)
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
				LogWarn("DoQ Read body failed from %v: %v", remoteAddr, err)
				return
			}
			
			// OPTIMIZATION: Use message pool
			msg := getMsg()
			defer putMsg(msg)
			
			if err := msg.Unpack(buf); err != nil {
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
type dotResponseWriter struct {
	*dns.Conn
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

