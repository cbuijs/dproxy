/*
File: server.go
Description: Implements the protocol listeners (UDP, TCP, DoT, DoQ, DoH/DoH3) and request handlers.
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
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ServerShutdowner interface for graceful shutdown
type ServerShutdowner interface {
	Shutdown(ctx context.Context) error
}

// DNSServerWrapper wraps dns.Server to implement ServerShutdowner
type DNSServerWrapper struct {
	*dns.Server
}

func (w *DNSServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.ShutdownContext(ctx)
}

// HTTPServerWrapper wraps http.Server to implement ServerShutdowner
type HTTPServerWrapper struct {
	*http.Server
}

func (w *HTTPServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.Shutdown(ctx)
}

// HTTP3ServerWrapper wraps http3.Server to implement ServerShutdowner
type HTTP3ServerWrapper struct {
	*http3.Server
}

func (w *HTTP3ServerWrapper) Shutdown(ctx context.Context) error {
	return w.Server.Close()
}

// DoQServerWrapper wraps QUIC listener for DoQ
type DoQServerWrapper struct {
	listener *quic.Listener
	cancel   context.CancelFunc
	done     chan struct{}
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

// DoTServerWrapper for custom SNI handling
type DoTServerWrapper struct {
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
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

func (w *DoTServerWrapper) acceptLoop() {
	for {
		conn, err := w.listener.Accept()
		if err != nil {
			select {
			case <-w.quit:
				return // Normal shutdown
			default:
				// Only log real errors, not closed listener errors during shutdown
				LogDebug("DoT Accept error: %v", err)
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
		LogInfo("Starting DNS UDP on %s:%d", listenAddr, udpPort)
		if err := udpServer.ListenAndServe(); err != nil {
			LogError("UDP server stopped: %v", err)
		}
	}()
	servers = append(servers, &DNSServerWrapper{udpServer})

	// TCP Listener
	wg.Add(1)
	tcpServer := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "tcp"}
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
		LogInfo("Starting DNS TCP on %s:%d", listenAddr, udpPort)
		if err := tcpServer.ListenAndServe(); err != nil {
			LogError("TCP server stopped: %v", err)
		}
	}()
	servers = append(servers, &DNSServerWrapper{tcpServer})

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
		}

		go func() {
			defer wg.Done()
			LogInfo("Starting DoT on %s", dotAddr)
			dotServer.acceptLoop()
		}()
		servers = append(servers, dotServer)
	}

	// DoQ (DNS over QUIC) Listener
	wg.Add(1)
	doqCtx, doqCancel := context.WithCancel(context.Background())
	doqDone := make(chan struct{})
	doqWrapper := &DoQServerWrapper{cancel: doqCancel, done: doqDone}
	
	go func() {
		defer wg.Done()
		defer close(doqDone)
		
		addr := fmt.Sprintf("%s:%d", listenAddr, tlsPort)
		LogInfo("Starting DoQ on %s", addr)
		listener, err := quic.ListenAddr(addr, tlsConfig, nil)
		if err != nil {
			LogError("DoQ listen error: %v", err)
			return
		}
		doqWrapper.listener = listener
		
		for {
			select {
			case <-doqCtx.Done():
				LogInfo("DoQ server stopped")
				return
			default:
				sess, err := listener.Accept(doqCtx)
				if err != nil {
					select {
					case <-doqCtx.Done():
						return
					default:
						LogError("DoQ accept error: %v", err)
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

	go func() {
		defer wg.Done()
		LogInfo("Starting DoH/DoH3 on %s", addr)
		
		// Start HTTP/3 in a goroutine
		go func() {
			if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				LogError("DoH3 server stopped: %v", err)
			}
		}()
		
		// Start HTTP/1.1 & HTTP/2
		if err := h1Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			LogError("DoH server stopped: %v", err)
		}
	}()
	servers = append(servers, &HTTPServerWrapper{h1Server})
	servers = append(servers, &HTTP3ServerWrapper{h3Server})

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

	// TLS Handshake to get SNI
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Handshake timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		LogDebug("DoT Handshake failed: %v", err)
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
				LogDebug("DoT Read error: %v", err)
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
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		data, _ := io.ReadAll(r.Body)
		err = msg.Unpack(data)
	case http.MethodGet:
		b64str := r.URL.Query().Get("dns")
		if b64str == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		data, e := base64.RawURLEncoding.DecodeString(b64str)
		if e != nil {
			http.Error(w, "Invalid base64", http.StatusBadRequest)
			return
		}
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

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
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
			
			// OPTIMIZATION: Use message pool
			msg := getMsg()
			defer putMsg(msg)
			
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

