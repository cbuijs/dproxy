/*
File: ml_guard_types.go
Version: 1.1.1
Description: Shared types, constants, and global state for the ML Guard engine.
             UPDATED: Removed unused singleflight import.
*/

package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// --- Constants ---

const (
	mlCacheShards      = 64
	mlCacheSize        = 65536
	tuningWindowSize   = 5000
	tuningInterval     = 5 * time.Minute
	maxThresholdChange = 0.05
	minSafeThreshold   = 0.50
	maxSafeThreshold   = 0.99

	maxPersistedCacheItems = 2000
)

// --- Structs ---

// AnalysisResult holds the outcome of a domain check
type AnalysisResult struct {
	Suspicious bool    `json:"suspicious"`
	Prob       float64 `json:"prob"`
	Reason     string  `json:"reason"`
}

// scoreRecord is used for dynamic tuning history
type scoreRecord struct {
	Prob       float64 `json:"prob"`
	WasBlocked bool    `json:"was_blocked"`
}

// MLGuardState represents the persisted state on disk
type MLGuardState struct {
	Threshold     float64                   `json:"threshold"`
	ScoreBuffer   []scoreRecord             `json:"score_buffer"`
	CacheSnapshot map[string]AnalysisResult `json:"cache_snapshot"`
	SavedAt       time.Time                 `json:"saved_at"`
}

// tokenStats is used for debugging training data quality
type tokenStats struct {
	Total      int
	Kept       int
	Short      int
	Common     int
	Safe       int
	Neutral    int
	LowEntropy int
}

// MLGuard is the main engine struct
type MLGuard struct {
	sync.RWMutex
	config    *MLGuardConfig
	badProbs  map[string]float64
	goodProbs map[string]float64
	tldCounts map[string]int
	probBad   float64
	probGood  float64
	cache     *MLAnalysisCache
	ready     atomic.Bool

	scoreCh     chan scoreRecord
	scoreBuffer []scoreRecord
	tunerOnce   sync.Once

	// Use pointer to ShardedGroup to avoid copying locks and enable sharing
	flightGroup *ShardedGroup
}

// --- Global Instance ---

var GlobalMLGuard = &MLGuard{
	ready: atomic.Bool{},
}

