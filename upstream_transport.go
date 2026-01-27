/*
File: upstream_transport.go
Version: 1.1.2 (Sync Fix)
Last Update: 2026-01-27
Description: Handles the low-level network exchanges for upstream DNS resolution.
             FIXED: Ensure globalSessionCache reference is valid (dependent on upstream.go compilation).
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// doExchange routes the request to the specific protocol implementation
func (u *Upstream) doExchange(ctx context.Context, req *dns.Msg, targetAddr string, reqCtx *RequestContext, dynHost, dynPath string) (*dns.Msg, error) {
	timeout := getTimeout()
	insecure := config.Server.InsecureUpstream

	switch u.Proto {
	case "udp":
		c := &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 4096}
		resp, _, err := c.ExchangeContext(ctx, req, targetAddr)
		return resp, err
	case "tcp", "dot":
		return u.exchangeTCPPool(ctx, req, targetAddr, u.Proto == "dot", insecure, reqCtx, dynHost)
	case "doq":
		return u.exchangeDoQ(ctx, req, targetAddr, reqCtx, dynHost)
	case "doh", "doh3":
		return u.exchangeDoH(ctx, req, reqCtx, dynHost, dynPath)
	}
	return nil, errors.New("unsupported protocol")
}

func (u *Upstream) exchangeTCPPool(ctx context.Context, req *dns.Msg, addr string, useTLS bool, insecure bool, reqCtx *RequestContext, dynHost string) (*dns.Msg, error) {
	poolKey := u.Proto + "|" + addr
	if useTLS {
		poolKey = poolKey + "|" + dynHost
	}

	attempt := func(c *dns.Conn, deadline time.Time) (*dns.Msg, error) {
		c.SetDeadline(deadline)
		if err := c.WriteMsg(req); err != nil {
			return nil, err
		}
		return c.ReadMsg()
	}

	// 1. Try Cached Connection
	conn := tcpPool.Get(poolKey)
	if conn != nil {
		fastDeadline := time.Now().Add(1 * time.Second)
		if globalDeadline, ok := ctx.Deadline(); ok && globalDeadline.Before(fastDeadline) {
			fastDeadline = globalDeadline
		}
		resp, err := attempt(conn, fastDeadline)
		if err == nil {
			go tcpPool.Put(poolKey, conn)
			return resp, nil
		}
		conn.Close()
		if IsDebugEnabled() {
			LogDebug("[UPSTREAM] Cached TCP conn failed (fast-fail), retrying dial: %v", err)
		}
	}

	// 2. Dial Fresh
	var err error
	conn, err = u.dialTCP(ctx, addr, useTLS, insecure, dynHost)
	if err != nil {
		return nil, err
	}

	dialDeadline, ok := ctx.Deadline()
	if !ok {
		dialDeadline = time.Now().Add(getTimeout())
	}

	resp, err := attempt(conn, dialDeadline)
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
	dialer := &net.Dialer{Timeout: getTimeout(), KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         sniHost,
			ClientSessionCache: globalSessionCache,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"dot"},
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

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetAddr string, reqCtx *RequestContext, dynHost string) (*dns.Msg, error) {
	insecure := config.Server.InsecureUpstream
	
	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         dynHost,
		NextProtos:         []string{"doq"},
		ClientSessionCache: globalSessionCache,
	}

	sess, err := doqPool.Get(ctx, targetAddr, tlsConf)
	if err != nil {
		return nil, err
	}

	reportFailure := func() {
		if !errors.Is(ctx.Err(), context.Canceled) {
			doqPool.Report0RTTFailure(targetAddr, tlsConf)
		}
	}

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		reportFailure()
		return nil, err
	}
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(getTimeout())
	}
	stream.SetDeadline(deadline)

	if err := writeDoQMsg(stream, req); err != nil {
		reportFailure()
		return nil, fmt.Errorf("failed to write DoQ request: %w", err)
	}
	if err := stream.Close(); err != nil {
		reportFailure()
		return nil, fmt.Errorf("failed to close stream write side: %w", err)
	}
	resp, err := readDoQMsg(stream)
	if err != nil {
		reportFailure()
		return nil, fmt.Errorf("failed to read DoQ response: %w", err)
	}
	return resp, nil
}

func (u *Upstream) exchangeDoH(ctx context.Context, req *dns.Msg, reqCtx *RequestContext, dynHost, dynPath string) (*dns.Msg, error) {
	client := u.httpClient
	if u.Proto == "doh3" {
		client = u.h3Client
	}

	buf := bufPool.Get().([]byte)
	packed, err := req.PackBuffer(buf[:0])
	if err != nil {
		bufPool.Put(buf)
		return nil, err
	}
	defer bufPool.Put(packed)

	// Simple concatenation for speed
	fullUrl := "https://" + dynHost + ":" + u.Port + dynPath

	var hReq *http.Request
	if u.DOHMethod == "GET" {
		payload := base64.RawURLEncoding.EncodeToString(packed)
		prefix := "?"
		if strings.Contains(fullUrl, "?") {
			prefix = "&"
		}
		targetUrl := fullUrl + prefix + "dns=" + payload
		hReq, err = http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	} else {
		hReq, err = http.NewRequestWithContext(ctx, "POST", fullUrl, bytes.NewReader(packed))
		if err == nil {
			hReq.Header.Set("Content-Type", "application/dns-message")
		}
	}

	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Accept", "application/dns-message")

	hResp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH error: %d", hResp.StatusCode)
	}

	limitReader := io.LimitReader(hResp.Body, 65535)
	respBuf := bufPool.Get().([]byte)
	defer bufPool.Put(respBuf)

	if cap(respBuf) < 4096 {
		respBuf = make([]byte, 4096)
	}
	readTarget := respBuf[:cap(respBuf)]
	bytesRead := 0

	for {
		if bytesRead == len(readTarget) {
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

func writeDoQMsg(w io.Writer, msg *dns.Msg) error {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	packed, err := msg.PackBuffer(buf[:0])
	if err != nil {
		return err
	}
	msgLen := len(packed)
	if msgLen > 65535 {
		return fmt.Errorf("message too large: %d", msgLen)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(msgLen))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(packed); err != nil {
		return err
	}
	return nil
}

func readDoQMsg(r io.Reader) (*dns.Msg, error) {
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

