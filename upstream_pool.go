/*
File: upstream_pool.go
Version: 1.7.0
Description: Manages TCP and DoQ connection pools for upstream exchanges.
             OPTIMIZED: Cleaned up race-condition logic and added safety checks.
             UPDATED: Added Report0RTTFailure to allow consumers to feedback protocol errors.
*/

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"strings"
	"sync"
	"time"
	"crypto/tls"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	maxDoQSessions  = 8   
	tcpIdlePoolSize = 512 
	poolShardCount  = 256 
)

var poolHasherSeed = maphash.MakeSeed()

// --- Sharded TCP/DoT Connection Pool ---

type tcpPoolShard struct {
	sync.Mutex
	conns map[string][]*dns.Conn
}

type TCPConnPool struct {
	shards [poolShardCount]*tcpPoolShard
}

var tcpPool = newTCPConnPool()

func newTCPConnPool() *TCPConnPool {
	p := &TCPConnPool{}
	for i := 0; i < poolShardCount; i++ {
		p.shards[i] = &tcpPoolShard{
			conns: make(map[string][]*dns.Conn),
		}
	}
	return p
}

func (p *TCPConnPool) getShard(key string) *tcpPoolShard {
	var h maphash.Hash
	h.SetSeed(poolHasherSeed)
	h.WriteString(key)
	return p.shards[h.Sum64()&(poolShardCount-1)]
}

func (p *TCPConnPool) Get(key string) *dns.Conn {
	shard := p.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	list := shard.conns[key]
	if len(list) > 0 {
		conn := list[len(list)-1]
		shard.conns[key] = list[:len(list)-1]
		return conn
	}
	return nil
}

func (p *TCPConnPool) Put(key string, conn *dns.Conn) {
	shard := p.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if len(shard.conns[key]) >= tcpIdlePoolSize {
		conn.Close()
		return
	}
	shard.conns[key] = append(shard.conns[key], conn)
}

// --- Sharded DoQ Connection Pool ---

type doqPoolShard struct {
	sync.RWMutex
	sessions   map[string][]*doqSession
	dialing    map[string]int
	nextIdx    map[string]int
	failed0RTT map[string]bool // Tracks if 0-RTT failed for a specific upstream
}

type DoQPool struct {
	shards [poolShardCount]*doqPoolShard
}

type doqSession struct {
	conn     quic.Connection // Uses quic.Connection interface (satisfied by EarlyConnection too)
	lastUsed time.Time
	mu       sync.Mutex
}

var doqPool = newDoQPool()

func newDoQPool() *DoQPool {
	p := &DoQPool{}
	for i := 0; i < poolShardCount; i++ {
		p.shards[i] = &doqPoolShard{
			sessions:   make(map[string][]*doqSession),
			dialing:    make(map[string]int),
			nextIdx:    make(map[string]int),
			failed0RTT: make(map[string]bool),
		}
	}
	return p
}

func (p *DoQPool) getShard(key string) *doqPoolShard {
	var h maphash.Hash
	h.SetSeed(poolHasherSeed)
	h.WriteString(key)
	return p.shards[h.Sum64()&(poolShardCount-1)]
}

// Report0RTTFailure marks the upstream as incompatible with 0-RTT.
// This should be called by the consumer (upstream.go) if a read/write error occurs
// that indicates 0-RTT rejection after the connection was established.
func (p *DoQPool) Report0RTTFailure(addr string, tlsConf *tls.Config) {
	poolKey := fmt.Sprintf("%s|%s", addr, tlsConf.ServerName)
	shard := p.getShard(poolKey)
	shard.Lock()
	if !shard.failed0RTT[poolKey] {
		shard.failed0RTT[poolKey] = true
		// Clear existing sessions for this key as they might be tainted or closed
		delete(shard.sessions, poolKey)
		delete(shard.nextIdx, poolKey)
		// We don't touch dialing count here as that's transient
	}
	shard.Unlock()
}

func (p *DoQPool) Get(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	poolKey := fmt.Sprintf("%s|%s", addr, tlsConf.ServerName)
	shard := p.getShard(poolKey)

	shard.Lock()
	// Clean up closed sessions first
	sessions := shard.sessions[poolKey]
	validSessions := make([]*doqSession, 0, len(sessions))
	for _, s := range sessions {
		select {
		case <-s.conn.Context().Done():
		default:
			validSessions = append(validSessions, s)
		}
	}
	shard.sessions[poolKey] = validSessions
	
	currentCount := len(validSessions)
	pendingDials := shard.dialing[poolKey]
	
	// Check if 0-RTT is known to fail for this upstream
	skip0RTT := shard.failed0RTT[poolKey]

	// RACE FIX: Check count AND pending dials. If under limit, reserve a slot.
	// This prevents multiple goroutines from seeing "0 sessions" and all dialing at once.
	if currentCount+pendingDials < maxDoQSessions {
		shard.dialing[poolKey]++
		shard.Unlock()

		var conn quic.Connection
		var err error

		quicConf := &quic.Config{
			KeepAlivePeriod:    30 * time.Second,
			MaxIdleTimeout:     60 * time.Second,
			MaxIncomingStreams: 1000,
		}

		if !skip0RTT {
			// Try 0-RTT
			conn, err = quic.DialAddrEarly(ctx, addr, tlsConf, quicConf)
			
			// Check for 0-RTT specific rejection or failure at dial time
			if err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, "0-RTT rejected") || strings.Contains(errMsg, "0-RTT") {
					LogWarn("[DoQ] 0-RTT dial rejected for %s, switching to standard handshake. Error: %v", poolKey, err)
					
					// Mark as failed for future attempts
					shard.Lock()
					shard.failed0RTT[poolKey] = true
					shard.Unlock()

					// Fallback to standard DialAddr immediately
					conn, err = quic.DialAddr(ctx, addr, tlsConf, quicConf)
				}
			}
		} else {
			// Skip 0-RTT explicitly because it failed before
			conn, err = quic.DialAddr(ctx, addr, tlsConf, quicConf)
		}

		shard.Lock()
		shard.dialing[poolKey]-- // Release reservation

		if err != nil {
			// If dial failed, check if we have any existing sessions to fallback to
			if len(shard.sessions[poolKey]) > 0 {
				idx := shard.nextIdx[poolKey] % len(shard.sessions[poolKey])
				shard.nextIdx[poolKey]++
				s := shard.sessions[poolKey][idx]
				s.lastUsed = time.Now()
				shard.Unlock()
				return s.conn, nil
			}
			shard.Unlock()
			return nil, err
		}

		newSess := &doqSession{conn: conn, lastUsed: time.Now()}
		shard.sessions[poolKey] = append(shard.sessions[poolKey], newSess)
		shard.Unlock()
		return conn, nil
	}

	if len(validSessions) == 0 {
		shard.Unlock()
		return nil, fmt.Errorf("no DoQ sessions available and max limit %d reached (pending: %d)", maxDoQSessions, pendingDials)
	}

	idx := shard.nextIdx[poolKey] % len(validSessions)
	shard.nextIdx[poolKey]++
	sess := validSessions[idx]
	sess.lastUsed = time.Now()
	shard.Unlock()

	return sess.conn, nil
}

func (p *DoQPool) cleanup(ctx context.Context) {
	LogInfo("[DOQ] Starting DoQ connection pool maintenance")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			count := 0
			for _, shard := range p.shards {
				shard.Lock()
				for _, sessions := range shard.sessions {
					for _, sess := range sessions {
						sess.conn.CloseWithError(0, "shutdown")
						count++
					}
				}
				shard.sessions = make(map[string][]*doqSession)
				shard.failed0RTT = make(map[string]bool)
				shard.Unlock()
			}
			LogInfo("[DOQ] Closed %d connections on shutdown", count)
			return
		case <-ticker.C:
			closedCount := 0
			for _, shard := range p.shards {
				shard.Lock()
				for addr, sessions := range shard.sessions {
					var active []*doqSession
					for _, sess := range sessions {
						sess.mu.Lock()
						if time.Since(sess.lastUsed) > 2*time.Minute {
							sess.conn.CloseWithError(0, "idle timeout")
							closedCount++
						} else {
							active = append(active, sess)
						}
						sess.mu.Unlock()
					}
					if len(active) == 0 {
						delete(shard.sessions, addr)
						delete(shard.nextIdx, addr)
						delete(shard.dialing, addr) 
						// Keep failed0RTT state
					} else {
						shard.sessions[addr] = active
					}
				}
				shard.Unlock()
			}
			if closedCount > 0 {
				LogDebug("[DOQ] Cleaned up %d idle DoQ connections", closedCount)
			}
		}
	}
}

