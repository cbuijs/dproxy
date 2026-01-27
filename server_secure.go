/*
File: server_secure.go
Version: 1.0.0
Last Update: 2026-01-26
Description: Contains handlers and ResponseWriters for encrypted DNS protocols:
             DNS-over-TLS (DoT) and DNS-over-QUIC (DoQ).
             Separated from server.go.
*/

package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

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

	dconn := new(dns.Conn)
	dconn.Conn = iconn

	var writeMu sync.Mutex
	sem := make(chan struct{}, MaxDoTPipelines)

	for {
		req, err := dconn.ReadMsg()
		if err != nil {
			if err != io.EOF {
				LogWarn("DoT Read error from %v: %v", remoteAddr, err)
			}
			return
		}

		sem <- struct{}{}

		go func(reqMsg *dns.Msg) {
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()
			
			reqCtx := reqCtxPool.Get().(*RequestContext)
			reqCtx.Reset()
			reqCtx.ServerIP = getLocalIP(conn.LocalAddr())
			reqCtx.ServerPort = getLocalPort(conn.LocalAddr())
			reqCtx.ServerHostname = sni
			reqCtx.Protocol = "DoT"

			w := &dotResponseWriter{Conn: dconn, writeMu: &writeMu}
			processDNSRequest(ctx, w, reqMsg, reqCtx)
			reqCtxPool.Put(reqCtx)
		}(req)
	}
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
			// RFC 9250: "The stream MUST be closed by the server after sending the response."
			defer str.Close()

			ctx, cancel := context.WithTimeout(context.Background(), getTimeout())
			defer cancel()

			// Use Strict helper from client_transport.go (shared package)
			msg, err := readDoQMsg(str)
			if err != nil {
				// Only log real errors, not EOF if connection closed cleanly
				if err != io.EOF {
					LogWarn("DoQ Read error from %v: %v", remoteAddr, err)
				}
				return
			}

			reqCtx := reqCtxPool.Get().(*RequestContext)
			reqCtx.Reset()
			reqCtx.ServerIP = getLocalIP(localAddr)
			reqCtx.ServerPort = getLocalPort(localAddr)
			reqCtx.ServerHostname = sni
			reqCtx.Protocol = "DoQ"

			dw := &doqResponseWriter{stream: str, remoteAddr: sess.RemoteAddr()}
			processDNSRequest(ctx, dw, msg, reqCtx)
			reqCtxPool.Put(reqCtx)
		}(stream)
	}
}

// --- Response Writers ---

type dotResponseWriter struct {
	*dns.Conn
	writeMu *sync.Mutex
}

func (w *dotResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.Conn.WriteMsg(msg)
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
	// DoQ (QUIC) requires strict RFC 9250 framing (2-byte length).
	return writeDoQMsg(w.stream, msg)
}
func (w *doqResponseWriter) Write(b []byte) (int, error) { return w.stream.Write(b) }
func (w *doqResponseWriter) Close() error                { return w.stream.Close() }
func (w *doqResponseWriter) TsigStatus() error           { return nil }
func (w *doqResponseWriter) TsigTimersOnly(bool)         {}
func (w *doqResponseWriter) Hijack()                     {}

