/*
File: limiter.go
Version: 1.1.0
Description: Implements smart dynamic rate limiting logic using Token Buckets for client QPS
             and Proportional Delay / Load Shedding for system health.
             Includes thread-safe sharded map for managing client state.
             UPDATED: Added detailed decision logging.
*/

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Actions returned by the limiter
type LimitAction int

const (
	ActionAllow LimitAction = iota
	ActionDelay
	ActionDrop
)

func (a LimitAction) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionDelay:
		return "DELAY"
	case ActionDrop:
		return "DROP"
	default:
		return "UNKNOWN"
	}
}

const (
	limitShardCount = 256
)

// Global Limiter Instance
var GlobalLimiter *LimiterManager

// ClientState holds the rate limiter for a specific client
type ClientState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type limiterShard struct {
	sync.RWMutex
	clients map[string]*ClientState
}

type LimiterManager struct {
	shards    [limitShardCount]*limiterShard
	config    *RateLimitConfig
	enabled   bool
	hasher    maphash.Hash
	hasherMu  sync.Mutex
}

func InitLimiter(cfg RateLimitConfig) {
	GlobalLimiter = &LimiterManager{
		config:  &cfg,
		enabled: cfg.Enabled,
	}

	// Initialize shards
	for i := 0; i < limitShardCount; i++ {
		GlobalLimiter.shards[i] = &limiterShard{
			clients: make(map[string]*ClientState),
		}
	}
}

// StartCleanupRoutine starts the background worker to remove old client limiters
func (lm *LimiterManager) StartCleanupRoutine(ctx context.Context) {
	if !lm.enabled {
		return
	}

	interval := lm.config.parsedCleanupInterval
	if interval == 0 {
		interval = 1 * time.Minute
	}
	
	LogInfo("[LIMITER] Starting cleanup routine (Interval: %v)", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			LogInfo("[LIMITER] Stopping cleanup routine")
			return
		case <-ticker.C:
			lm.cleanup()
		}
	}
}

func (lm *LimiterManager) cleanup() {
	expiration := lm.config.parsedClientExpiration
	if expiration == 0 {
		expiration = 5 * time.Minute
	}
	now := time.Now()
	removedCount := 0

	for _, shard := range lm.shards {
		shard.Lock()
		for ip, state := range shard.clients {
			if now.Sub(state.lastSeen) > expiration {
				delete(shard.clients, ip)
				removedCount++
			}
		}
		shard.Unlock()
	}

	if removedCount > 0 {
		LogDebug("[LIMITER] Cleaned up %d idle client limiters", removedCount)
	}
}

func (lm *LimiterManager) getShard(key string) *limiterShard {
	lm.hasherMu.Lock()
	lm.hasher.Reset()
	lm.hasher.WriteString(key)
	hash := lm.hasher.Sum64()
	lm.hasherMu.Unlock()
	return lm.shards[hash&(limitShardCount-1)]
}

// Check evaluates the request against system load and client limits.
// Returns action (Allow/Delay/Drop), delay duration, and reason string.
func (lm *LimiterManager) Check(clientIP net.IP) (LimitAction, time.Duration, string) {
	if !lm.enabled {
		return ActionAllow, 0, ""
	}

	// 1. SYSTEM HEALTH CHECK (Global)
	// Check number of goroutines to determine system load
	numGoroutines := runtime.NumGoroutine()
	
	// Hard Limit: Immediate Drop (Load Shedding) to prevent crash
	if numGoroutines >= lm.config.HardMaxGoroutines {
		reason := fmt.Sprintf("System Overload (Hard Limit: %d/%d Goroutines)", numGoroutines, lm.config.HardMaxGoroutines)
		return ActionDrop, 0, reason
	}

	// Soft Limit: Proportional Delay
	if numGoroutines > lm.config.MaxGoroutines {
		// Calculate overage ratio (0.0 to 1.0 between soft and hard limit)
		spread := float64(lm.config.HardMaxGoroutines - lm.config.MaxGoroutines)
		overage := float64(numGoroutines - lm.config.MaxGoroutines)
		ratio := overage / spread
		if ratio > 1.0 {
			ratio = 1.0
		}

		// Calculate delay: BaseDelay + (MaxDelay - BaseDelay) * ratio
		base := float64(lm.config.parsedBaseDelay.Nanoseconds())
		max := float64(lm.config.parsedMaxDelay.Nanoseconds())
		delayNs := base + (max-base)*ratio
		delay := time.Duration(delayNs)
		
		reason := fmt.Sprintf("System Load (Soft Limit: %d/%d Goroutines, Ratio: %.2f)", numGoroutines, lm.config.MaxGoroutines, ratio)
		return ActionDelay, delay, reason
	}

	// 2. CLIENT QPS CHECK (Per-IP)
	if clientIP == nil {
		return ActionAllow, 0, ""
	}

	ipStr := clientIP.String()
	shard := lm.getShard(ipStr)
	
	shard.Lock()
	state, exists := shard.clients[ipStr]
	if !exists {
		state = &ClientState{
			limiter: rate.NewLimiter(rate.Limit(lm.config.ClientQPS), lm.config.ClientBurst),
		}
		shard.clients[ipStr] = state
	}
	state.lastSeen = time.Now()
	// Allow evaluates tokens.
	allowed := state.limiter.Allow()
	
	// Get stats for logging before unlocking if rejected
	var tokens float64
	if !allowed && IsDebugEnabled() {
		tokens = state.limiter.Tokens()
	}
	shard.Unlock()

	if !allowed {
		// QPS exceeded. We default to drop for QPS limits as clients should back off.
		reason := fmt.Sprintf("Client QPS Exceeded (IP: %s, Limit: %d, Burst: %d, Tokens: %.2f)", 
			ipStr, lm.config.ClientQPS, lm.config.ClientBurst, tokens)
		return ActionDrop, 0, reason
	}

	return ActionAllow, 0, ""
}

