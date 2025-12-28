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
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func startServers(wg *sync.WaitGroup, tlsConfig *tls.Config) {
	listenAddr := config.Server.ListenAddr
	udpPort := config.Server.Ports.UDP
	tlsPort := config.Server.Ports.TLS
	httpsPort := config.Server.Ports.HTTPS

	// UDP Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "udp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "UDP",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DNS UDP on %s:%d", listenAddr, udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	// TCP Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", listenAddr, udpPort), Net: "tcp"}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "TCP",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DNS TCP on %s:%d", listenAddr, udpPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	// DoT (DNS over TLS) Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := &dns.Server{
			Addr: fmt.Sprintf("%s:%d", listenAddr, tlsPort),
			Net:  "tcp-tls", TLSConfig: tlsConfig,
		}
		srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			reqCtx := &RequestContext{
				ServerIP:   getLocalIP(w.LocalAddr()),
				ServerPort: getLocalPort(w.LocalAddr()),
				Protocol:   "DoT",
			}
			processDNSRequest(ctx, w, r, reqCtx)
		})
		log.Printf("Starting DoT on %s:%d", listenAddr, tlsPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("DoT server error: %v", err)
		}
	}()

	// DoQ (DNS over QUIC) Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", listenAddr, tlsPort)
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

	// DoH / DoH3 (HTTP/HTTPS) Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := fmt.Sprintf("%s:%d", listenAddr, httpsPort)

		mux := http.NewServeMux()
		mux.HandleFunc("/", handleDoH)

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

func handleDoH(w http.ResponseWriter, r *http.Request) {
	// Use getTimeout() which reads from config
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
		data, _ := io.ReadAll(r.Body)
		msg = new(dns.Msg)
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

			// Use getTimeout() which reads from config
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
			msg := new(dns.Msg)
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

