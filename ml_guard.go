/*
File: ml_guard.go
Version: 4.1.0
Description: Initialization and state loading logic for the ML Guard engine.
             UPDATED: Initializing ShardedGroup for concurrent analysis coalescing.
*/

package main

import (
	"encoding/json"
	"os"
	"strings"
)

func InitMLGuard(cfg MLGuardConfig) {
	GlobalMLGuard.Lock()
	defer GlobalMLGuard.Unlock()
	GlobalMLGuard.config = &cfg
	GlobalMLGuard.badProbs = make(map[string]float64)
	GlobalMLGuard.goodProbs = make(map[string]float64)
	GlobalMLGuard.tldCounts = make(map[string]int)
	GlobalMLGuard.cache = NewMLAnalysisCache(mlCacheSize)
	
	// Initialize sharded flight group if not present
	if GlobalMLGuard.flightGroup == nil {
		GlobalMLGuard.flightGroup = NewShardedGroup()
	}

	// Attempt to load state if configured
	if cfg.StateFile != "" {
		if err := GlobalMLGuard.loadStateLocked(cfg.StateFile); err != nil {
			LogWarn("[ML-GUARD] Failed to load state from %s: %v", cfg.StateFile, err)
		} else {
			LogInfo("[ML-GUARD] Loaded persistent state (Threshold: %.2f)", GlobalMLGuard.config.Threshold)
		}
	}

	if strings.ToLower(cfg.AutoThreshold) == "on" {
		GlobalMLGuard.scoreCh = make(chan scoreRecord, 2048)
	}

	LogInfo("[ML-GUARD] Initialized (Threshold: %.2f, Auto: %s, MinLength: %d)",
		cfg.Threshold, cfg.AutoThreshold, cfg.MinLength)
}

// loadStateLocked loads state. Must be called while holding lock.
func (ml *MLGuard) loadStateLocked(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state MLGuardState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	if state.Threshold >= minSafeThreshold && state.Threshold <= maxSafeThreshold {
		ml.config.Threshold = state.Threshold
	}

	if len(state.ScoreBuffer) > 0 {
		ml.scoreBuffer = state.ScoreBuffer
	}

	// Warm up cache from snapshot
	if len(state.CacheSnapshot) > 0 {
		count := 0
		for k, v := range state.CacheSnapshot {
			ml.cache.Add(k, v)
			count++
		}
		LogInfo("[ML-GUARD] Warmed up cache with %d entries from state file", count)
	}

	return nil
}

