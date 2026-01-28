/*
File: limiter.go
Version: 1.12.0
Description: Implements smart dynamic rate limiting logic using Token Buckets for client QPS
             and Proportional Delay / Load Shedding for system health.
             Includes thread-safe sharded map for managing client state.
             UPDATED: Implemented Traffic Shaping (Pacing) for Client QPS instead of immediate Drop.
             UPDATED: Added IsUnderLoad() to signal load shedding state to other modules.
             UPDATED: Added dynamic QPS scaling based on system load (Adaptive Throttling).
             UPDATED: Added comprehensive DEBUG logging for limiter decisions, including Goroutine stats.
             FIXED: Ensure logging happens immediately during load changes to avoid perceived lag.
             DEBUG: Added verbose logging for system load state to diagnose threshold issues.
             ADJUSTED: Made adaptive scaling more aggressive (bigger steps) by increasing reduction factor to 0.95.
             UPDATED: Round up calculated QPS and Burst values to nearest integer using math.Ceil.
*/

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"math"
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
	// maxPacingDelay defines the maximum time we are willing to delay a request
	// to smooth out traffic. If the required delay exceeds this, we drop.
	maxPacingDelay = 1 * time.Second
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

// IsUnderLoad returns true if the system is under significant stress.
// Used by the Cache to decide whether to serve stale data.
func (lm *LimiterManager) IsUnderLoad() bool {
	if !lm.enabled {
		return false
	}
	// Trigger load mode at 80% of the Soft Limit (MaxGoroutines).
	// This allows us to start shedding load (serving stale) BEFORE we start
	// imposing artificial delays or drops.
	threshold := int(float64(lm.config.MaxGoroutines) * 0.8)
	if threshold < 10 {
		threshold = 10
	}
	return runtime.NumGoroutine() > threshold
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
		if IsDebugEnabled() {
			LogDebug("[LIMITER] Hard limit hit! Dropping request. Goroutines: %d (Limit: %d)", numGoroutines, lm.config.HardMaxGoroutines)
		}
		return ActionDrop, 0, reason
	}

	// Adaptive Logic Vars
	var loadRatio float64
	systemDelay := time.Duration(0)
	systemReason := ""

	// Calculate ratio regardless of threshold for visibility (clamped at 0)
	if lm.config.HardMaxGoroutines > lm.config.MaxGoroutines {
		overage := float64(numGoroutines - lm.config.MaxGoroutines)
		spread := float64(lm.config.HardMaxGoroutines - lm.config.MaxGoroutines)
		loadRatio = overage / spread
	}
	
	if loadRatio < 0 {
		loadRatio = 0
	} else if loadRatio > 1.0 {
		loadRatio = 1.0
	}

	// Soft Limit Logic: Apply Delay
	if numGoroutines > lm.config.MaxGoroutines {
		// Calculate delay: BaseDelay + (MaxDelay - BaseDelay) * ratio
		base := float64(lm.config.parsedBaseDelay.Nanoseconds())
		max := float64(lm.config.parsedMaxDelay.Nanoseconds())
		delayNs := base + (max-base)*loadRatio
		systemDelay = time.Duration(delayNs)
		
		systemReason = fmt.Sprintf("System Load (Soft Limit: %d/%d Goroutines, Ratio: %.2f)", numGoroutines, lm.config.MaxGoroutines, loadRatio)
		
		if IsDebugEnabled() {
			// LOG IMMEDIATELY when system load is detected
			LogDebug("[LIMITER] System under load. Goroutines: %d (Soft: %d, Hard: %d), LoadRatio: %.2f, SystemDelay: %v", 
				numGoroutines, lm.config.MaxGoroutines, lm.config.HardMaxGoroutines, loadRatio, systemDelay)
		}
	} else if IsDebugEnabled() {
		// DEBUG: Periodic log or verbose log to prove we are checking
		// We use a simple check to avoid spamming 1000s of lines. 
		// Only log if we are somewhat close (e.g. > 50% of soft limit)
		if numGoroutines > lm.config.MaxGoroutines/2 {
			// LogDebug("[LIMITER] System normal. Goroutines: %d (Soft: %d)", numGoroutines, lm.config.MaxGoroutines)
		}
	}

	// 2. CLIENT QPS CHECK (Per-IP) with ADAPTIVE LIMITS
	if clientIP == nil {
		// If no client IP, we can only enforce system limits
		if systemDelay > 0 {
			return ActionDelay, systemDelay, systemReason
		}
		return ActionAllow, 0, ""
	}

	// Calculate Effective Client Limit
	// If under load, scale down the limit.
	targetLimit := rate.Limit(lm.config.ClientQPS)
	targetBurst := lm.config.ClientBurst

	if loadRatio > 0 {
		// Increased aggression: Scale down to 5% at max load (0.95 factor)
		scaleFactor := 1.0 - (loadRatio * 0.95) 
		scaledQPS := float64(lm.config.ClientQPS) * scaleFactor
		
		minQPS := float64(lm.config.ClientQPS) * 0.05 // Floor at 5%
		if minQPS < 5.0 { minQPS = 5.0 } // Absolute floor 5 QPS
		
		if scaledQPS < minQPS { scaledQPS = minQPS }
		
		// ROUND UP to nearest whole number
		targetLimit = rate.Limit(math.Ceil(scaledQPS))
		
		// Scale burst similarly
		scaledBurst := float64(lm.config.ClientBurst) * scaleFactor
		if scaledBurst < 1 { scaledBurst = 1 }
		// ROUND UP burst
		targetBurst = int(math.Ceil(scaledBurst))

		if IsDebugEnabled() {
			// LOG IMMEDIATELY when adaptive scaling is active
			LogDebug("[LIMITER] Adaptive Scaling Active: LoadRatio=%.2f -> Limit: %.2f QPS, Burst: %d (Factor: %.2f)", 
				loadRatio, float64(targetLimit), targetBurst, scaleFactor)
		}
	}

	ipStr := clientIP.String()
	shard := lm.getShard(ipStr)
	
	shard.Lock()
	state, exists := shard.clients[ipStr]
	if !exists {
		state = &ClientState{
			limiter: rate.NewLimiter(targetLimit, targetBurst),
		}
		shard.clients[ipStr] = state
	}
	state.lastSeen = time.Now()

	// Dynamic Adjustment: If the limit has changed significantly, update the limiter.
	currentLimit := state.limiter.Limit()
	if currentLimit != targetLimit {
		if IsDebugEnabled() {
			LogDebug("[LIMITER] Adjusting limiter for %s -> Old: %.2f, New: %.2f, Burst: %d (Active QPS)", ipStr, float64(currentLimit), float64(targetLimit), targetBurst)
		}
		state.limiter.SetLimit(targetLimit)
		state.limiter.SetBurst(targetBurst)
	}
	
	// Use Reserve() to determine traffic shaping requirements
	reservation := state.limiter.Reserve()
	shard.Unlock()

	if !reservation.OK() {
		return ActionDrop, 0, "Client Rate Limit Exceeded (Internal Error)"
	}

	clientDelay := reservation.Delay()
	
	// Combine Delays: Take the maximum of System Delay or Client Pacing Delay
	finalDelay := clientDelay
	finalReason := ""

	if systemDelay > clientDelay {
		finalDelay = systemDelay
		finalReason = systemReason
	} else if clientDelay > 0 {
		// Smart Pacing Check
		if clientDelay <= maxPacingDelay {
			finalReason = fmt.Sprintf("Client QPS Pacing (IP: %s, Delay: %v, Limit: %.2f)", ipStr, clientDelay, float64(targetLimit))
			if IsDebugEnabled() {
				// LOG IMMEDIATELY when pacing is applied
				LogDebug("[LIMITER] Pacing client %s. Delay: %v (Active QPS: %.2f)", ipStr, clientDelay, float64(targetLimit))
			}
		} else {
			reservation.Cancel()
			reason := fmt.Sprintf("Client QPS Exceeded (IP: %s, Required Delay: %v > Limit: %v, TargetRate: %.2f)", 
				ipStr, clientDelay, maxPacingDelay, float64(targetLimit))
			if IsDebugEnabled() {
				// LOG IMMEDIATELY when dropping due to excessive rate
				LogDebug("[LIMITER] Dropping client %s. Excessive delay required: %v (Active QPS: %.2f)", ipStr, clientDelay, float64(targetLimit))
			}
			return ActionDrop, 0, reason
		}
	}

	if finalDelay > 0 {
		if finalReason == "" { finalReason = "Rate Limiting" } // Fallback
		return ActionDelay, finalDelay, finalReason
	}

	return ActionAllow, 0, ""
}

