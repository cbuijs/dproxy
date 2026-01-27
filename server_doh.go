/*
File: server_doh.go
Version: 1.0.0
Last Update: 2026-01-26
Description: Contains HTTP handlers and ResponseWriters for DNS-over-HTTPS (DoH).
             Separated from server.go.
*/

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

func handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), getTimeout())
	defer cancel()
	remoteAddr := r.RemoteAddr

	// Helper to handle mismatches
	rejectMismatch := func(reason string) {
		LogWarn(reason)

		// 1. Backoff (Tarpit)
		if delay := config.Server.DOH.parsedMismatchBackoff; delay > 0 {
			time.Sleep(delay)
		}

		behavior := config.Server.DOH.MismatchBehavior
		if behavior == "drop" {
			// 2. Try to Hijack (TCP Drop) - Works mostly for HTTP/1.x
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					conn.Close()
					return
				}
			}
			
			// 3. Fallback for H2/H3 or failed Hijack: Abort Handler
			panic(http.ErrAbortHandler)
		}

		code := http.StatusNotFound
		switch behavior {
		case "400":
			code = http.StatusBadRequest
		case "403":
			code = http.StatusForbidden
		case "405":
			code = http.StatusMethodNotAllowed
		// default case is 404/NotFound
		}

		msg := config.Server.DOH.MismatchText
		if msg == "" {
			msg = http.StatusText(code)
		}
		
		http.Error(w, msg, code)
	}

	// --- PATH VALIDATION LOGIC ---
	if r.URL.Path == "" {
		rejectMismatch(fmt.Sprintf("DoH Empty Path from %s", remoteAddr))
		return
	}

	if config.Server.DOH.StrictPath {
		allowed := false
		for _, path := range config.Server.DOH.AllowedPaths {
			if r.URL.Path == path {
				allowed = true
				break
			}
		}
		if !allowed {
			rejectMismatch(fmt.Sprintf("DoH Path mismatch from %s: %s", remoteAddr, r.URL.Path))
			return
		}
	}

	msg := getMsg()
	defer putMsg(msg)

	var err error

	proto := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxDNSBodySize)

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			LogWarn("DoH Invalid Content-Type from %s: %s", remoteAddr, r.Header.Get("Content-Type"))
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		
		// OPTIMIZATION: Zero-allocation read using global pool
		buf := bufPool.Get().([]byte)
		// Reset buffer to max capacity (slice is len=cap)
		buf = buf[:cap(buf)]
		
		n, readErr := io.ReadFull(r.Body, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			// ErrUnexpectedEOF is actually fine here if the body was shorter than buf
			LogWarn("DoH Body Read failed from %s: %v", remoteAddr, readErr)
			bufPool.Put(buf)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		
		// Unpack using the slice of data we read
		err = msg.Unpack(buf[:n])
		bufPool.Put(buf) // Return buffer immediately after unpacking

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
	
	reqCtx := reqCtxPool.Get().(*RequestContext)
	reqCtx.Reset()
	reqCtx.ServerIP = getLocalIP(localAddr)
	reqCtx.ServerPort = getLocalPort(localAddr)
	reqCtx.ServerHostname = r.Host
	reqCtx.ServerPath = r.URL.Path
	reqCtx.Protocol = proto

	dw := &dohResponseWriter{w: w, r: r, localAddr: localAddr}
	processDNSRequest(ctx, dw, msg, reqCtx)
	reqCtxPool.Put(reqCtx)
}

// --- Response Writers ---

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

