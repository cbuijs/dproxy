/*
File: ml_guard_train.go
Version: 1.0.0
Description: Logic for training the ML model from cache, files, and lists.
*/

package main

import (
	"bufio"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

func (ml *MLGuard) TrainFromCache(cache SourceCache) {
	if ml.config == nil || !ml.config.Enabled {
		return
	}

	go func() {
		blockSet := make(map[string]struct{})
		allowSet := make(map[string]struct{})

		for _, data := range cache {
			for domain := range data.Forward {
				blockSet[domain] = struct{}{}
			}
			for domain := range data.Allowed {
				allowSet[domain] = struct{}{}
			}
		}

		// Load Tranco List if configured
		if ml.config.TrancoFile != "" {
			ml.loadTrancoData(ml.config.TrancoFile, ml.config.TrancoTopN, allowSet)
		}

		ml.train(blockSet, allowSet)
	}()
}

// loadTrancoData reads a CSV (rank,domain) and adds domains to the allowSet for training.
func (ml *MLGuard) loadTrancoData(path string, topN int, allowSet map[string]struct{}) {
	file, err := os.Open(path)
	if err != nil {
		LogWarn("[ML-GUARD] Failed to open Tranco file %s: %v", path, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	LogInfo("[ML-GUARD] Loading Tranco/Top-1M data from %s (Limit: %d)...", path, topN)

	for scanner.Scan() {
		line := scanner.Text()

		// Handle Tranco format: Rank,Domain (e.g. "1,google.com")
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		domain := strings.TrimSpace(parts[1])
		domain = strings.Trim(domain, "\"")
		domain = strings.Trim(domain, "'")

		if domain == "" {
			continue
		}

		allowSet[domain] = struct{}{}
		count++

		if topN > 0 && count >= topN {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		LogWarn("[ML-GUARD] Error scanning Tranco file: %v", err)
	}

	LogInfo("[ML-GUARD] Loaded %d domains from Tranco list for training.", count)
}

// getTrainingTokens tokenizes domains for training and analysis
func getTrainingTokens(domain string, stats *tokenStats) []string {
	d := strings.ToLower(strings.Trim(domain, "."))
	suffix, _ := publicsuffix.PublicSuffix(d)
	keepSuffix := false
	if len(suffix) > 0 {
		if _, isHighRisk := highRiskTLDs[suffix]; isHighRisk {
			keepSuffix = true
		}
	}
	payload := d
	if len(suffix) > 0 && len(d) > len(suffix) {
		if !keepSuffix {
			payload = d[:len(d)-len(suffix)]
			payload = strings.TrimSuffix(payload, ".")
		}
	} else if len(suffix) > 0 && len(d) == len(suffix) {
		if !keepSuffix {
			return nil
		}
	}
	rawParts := strings.Split(payload, ".")
	var tokens []string

	for _, p := range rawParts {
		if stats != nil {
			stats.Total++
		}

		if len(p) < 3 {
			if stats != nil {
				stats.Short++
			}
			continue
		}

		// 1. Check Explicit Lists
		if _, isCommon := commonLabels[p]; isCommon {
			if stats != nil {
				stats.Common++
			}
			continue
		}
		if _, isSafe := safeTLDs[p]; isSafe {
			if stats != nil {
				stats.Safe++
			}
			continue
		}
		if _, isNeutral := neutralWords[p]; isNeutral {
			if stats != nil {
				stats.Neutral++
			}
			continue
		}

		// 2. Check Entropy (Heuristic Filter)
		ent := calculateEntropy(p)
		if ent < 2.5 {
			if stats != nil {
				stats.LowEntropy++
			}
			continue
		}

		if stats != nil {
			stats.Kept++
		}
		tokens = append(tokens, p)
	}
	return tokens
}

func (ml *MLGuard) train(blocklist map[string]struct{}, allowlist map[string]struct{}) {
	start := time.Now()
	LogInfo("[ML-GUARD] Starting training on %d blocked and %d allowed domains...", len(blocklist), len(allowlist))

	badTokens := make(map[string]int)
	goodTokens := make(map[string]int)
	tldFreq := make(map[string]int)

	// Track stats for debugging
	tStats := &tokenStats{}

	totalBad := 0
	totalGood := 0

	processDomain := func(domain string, target map[string]int, isBlocklist bool) int {
		if isBlocklist {
			suffix, _ := publicsuffix.PublicSuffix(strings.ToLower(domain))
			if suffix != "" {
				checkSuffix := suffix
				if idx := strings.LastIndex(suffix, "."); idx != -1 {
					checkSuffix = suffix[idx+1:]
				}
				if _, safe := safeTLDs[checkSuffix]; !safe {
					tldFreq[suffix]++
				}
			}
		}
		// Pass tracking stats
		parts := getTrainingTokens(domain, tStats)

		cnt := 0
		for _, p := range parts {
			target[p]++
			if len(p) > 15 {
				target["LEN>15"]++
			}
			digitCount := 0
			for _, r := range p {
				if r >= '0' && r <= '9' {
					digitCount++
				}
			}
			if len(p) > 0 && digitCount == len(p) {
				target["HIGH_DIGITS"]++
			}
			cnt++
		}
		return cnt
	}

	for d := range blocklist {
		totalBad += processDomain(d, badTokens, true)
	}
	for d := range allowlist {
		totalGood += processDomain(d, goodTokens, false)
	}

	if totalGood < 2000 {
		commonDomains := getTop500Domains()
		for _, d := range commonDomains {
			for i := 0; i < 200; i++ {
				totalGood += processDomain(d, goodTokens, false)
			}
		}
	}

	vocab := make(map[string]bool)
	for k := range badTokens {
		vocab[k] = true
	}
	for k := range goodTokens {
		vocab[k] = true
	}
	vocabSize := float64(len(vocab))

	newBadProbs := make(map[string]float64)
	newGoodProbs := make(map[string]float64)

	for w := range vocab {
		countBad := badTokens[w]
		newBadProbs[w] = math.Log(float64(countBad+1) / (float64(totalBad) + vocabSize))
		countGood := goodTokens[w]
		newGoodProbs[w] = math.Log(float64(countGood+1) / (float64(totalGood) + vocabSize))
	}

	autoMode := strings.ToLower(ml.config.AutoThreshold)
	var advisedThreshold float64

	if autoMode == "startup" || autoMode == "on" {
		scoreDomain := func(domain string) float64 {
			// No stats needed for this check phase
			parts := getTrainingTokens(domain, nil)
			sBad := math.Log(0.5)
			sGood := math.Log(0.5)
			for _, token := range parts {
				pBad, ok := newBadProbs[token]
				if !ok {
					pBad = -15.0
				}
				pGood, ok := newGoodProbs[token]
				if !ok {
					pGood = -15.0
				}
				weight := 1.0
				sBad += pBad * weight
				sGood += pGood * weight
			}
			logOdds := sBad - sGood
			return 1.0 / (1.0 + math.Exp(-logOdds))
		}

		var goodScores []float64
		sampleSize := 1000
		i := 0
		for d := range allowlist {
			if i >= sampleSize {
				break
			}
			goodScores = append(goodScores, scoreDomain(d))
			i++
		}
		sort.Float64s(goodScores)
		advisedThreshold = 0.90
		if len(goodScores) > 0 {
			idx := int(float64(len(goodScores)) * 0.99)
			if idx >= len(goodScores) {
				idx = len(goodScores) - 1
			}
			p99Good := goodScores[idx]
			advisedThreshold = p99Good + 0.05
			if advisedThreshold > 0.99 {
				advisedThreshold = 0.99
			}
		}
	}

	ml.Lock()
	ml.badProbs = newBadProbs
	ml.goodProbs = newGoodProbs
	ml.tldCounts = tldFreq
	ml.probBad = math.Log(0.5)
	ml.probGood = math.Log(0.5)

	if (autoMode == "startup" || autoMode == "on") && advisedThreshold > minSafeThreshold {
		if advisedThreshold > minSafeThreshold {
			if ml.config.StateFile == "" {
				LogInfo("[ML-GUARD] Auto-Threshold: Updating threshold from %.2f to %.2f", ml.config.Threshold, advisedThreshold)
				ml.config.Threshold = advisedThreshold
			} else {
				LogInfo("[ML-GUARD] Trained Threshold: %.2f (Keeping loaded state: %.2f)", advisedThreshold, ml.config.Threshold)
			}
		}
	}

	if ml.cache != nil {
		ml.cache.Flush()
	}

	ml.ready.Store(true)
	ml.Unlock()

	LogInfo("[ML-GUARD] Training complete in %v. Vocab=%d", time.Since(start), int(vocabSize))
	// Log Token Stats
	LogInfo("[ML-GUARD] Token Analysis Stats: Total=%d | Kept=%d | Discarded [Short=%d, Common=%d, Safe=%d, Neutral=%d, LowEntropy=%d]",
		tStats.Total, tStats.Kept, tStats.Short, tStats.Common, tStats.Safe, tStats.Neutral, tStats.LowEntropy)
}

