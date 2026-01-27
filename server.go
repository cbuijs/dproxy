/*
File: server.go
Version: 3.2.0
Last Update: 2026-01-26
Description: Implements server orchestration, UDP workers, and protocol listeners.
             Specific protocol handlers (DoH, DoT, DoQ) have been moved to server_doh.go and server_secure.go.
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
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
	return fmt.Sprintf("Protocol: DoH3 (QUIC/0-RTT) | Addr: %s | Path: /", w.Addr)
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
	return fmt.Sprintf("Protocol: DoQ (0-RTT) | Addr: %s", w.Addr)
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

// --- UDP Worker Pool ---

type udpJob struct {
	w   dns.ResponseWriter
	msg *dns.Msg
}

var (
	udpWorkCh   chan udpJob
	udpPoolOnce sync.Once
)

func startUDPWorkers() {
	udpPoolOnce.Do(func() {
		// Reasonable default: 128 workers per CPU core
		numWorkers := runtime.NumCPU() * 128
		udpWorkCh = make(chan udpJob, numWorkers*2) // Buffer 2x workers

		LogInfo("[SERVER] Starting UDP Worker Pool with %d workers", numWorkers)

		for i := 0; i < numWorkers; i++ {
			go func(id int) {
				for job := range udpWorkCh {
					ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
					
					// Re-construct basic context from the writer (LocalAddr)
					// Use POOL to avoid heap allocation
					reqCtx := reqCtxPool.Get().(*RequestContext)
					reqCtx.Reset()
					reqCtx.ServerIP = getLocalIP(job.w.LocalAddr())
					reqCtx.ServerPort = getLocalPort(job.w.LocalAddr())
					reqCtx.Protocol = "UDP"
					
					processDNSRequest(ctx, job.w, job.msg, reqCtx)
					reqCtxPool.Put(reqCtx)
					
					cancel()
				}
			}(i)
		}
	})
}

func startServers(wg *sync.WaitGroup, tlsConfig *tls.Config) []ServerShutdowner {
	var servers []ServerShutdowner

	// Initialize UDP Worker Pool if not already started
	startUDPWorkers()

	// Shared HTTP Mux for all DoH listeners
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDoH)

	// Configurable /robots.txt handler
	if config.Server.DOH.RobotsTxt {
		mux.HandleFunc("/robots.txt", handleRobotsTxt)
	}

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
					
					// Handler pushes to Worker Pool
					udpServer.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
						select {
						case udpWorkCh <- udpJob{w: w, msg: r}:
							// Job enqueued successfully
						default:
							// Load Shedding: Pool is full
							LogWarn("[SERVER] UDP Worker Pool Full - Dropping request from %s", w.RemoteAddr())
						}
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
						
						reqCtx := reqCtxPool.Get().(*RequestContext)
						reqCtx.Reset()
						reqCtx.ServerIP = getLocalIP(w.LocalAddr())
						reqCtx.ServerPort = getLocalPort(w.LocalAddr())
						reqCtx.Protocol = "TCP"
						
						processDNSRequest(ctx, w, r, reqCtx)
						reqCtxPool.Put(reqCtx)
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
						// Enable RFC 9250 ALPN "doq"
						if len(tlsConfig.NextProtos) == 0 {
							tlsConfig.NextProtos = []string{"doq"}
						}
						
						// Enable 0-RTT support for DoQ
						quicConfig := &quic.Config{
							Allow0RTT: true,
						}

						listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
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
					h3Server := &http3.Server{
						Addr:      addr,
						Handler:   mux,
						TLSConfig: tlsConfig,
						QuicConfig: &quic.Config{
							Allow0RTT: true, // Enable 0-RTT for HTTP/3
						},
					}
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

