/*
File: ml_guard_process.go
Version: 1.2.0 (Singleflight Logging)
Description: Runtime analysis, dynamic tuning, and scoring logic.
             UPDATED: Added logs for ML analysis singleflight status.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// StartDynamicTuner starts the background tuner. MUST be called after context initialization.
func (ml *MLGuard) StartDynamicTuner(ctx context.Context) {
	if strings.ToLower(ml.config.AutoThreshold) != "on" {
		return
	}

	ml.tunerOnce.Do(func() {
		go func() {
			saveInterval := 30 * time.Minute
			if ml.config.SaveInterval != "" {
				if parsed, err := time.ParseDuration(ml.config.SaveInterval); err == nil {
					saveInterval = parsed
				} else {
					LogWarn("[ML-GUARD] Invalid save_interval '%s', defaulting to 30m", ml.config.SaveInterval)
				}
			}

			LogInfo("[ML-GUARD] Continuous Dynamic Tuning Started (Tune: %v, Save: %v)", tuningInterval, saveInterval)
			if ml.scoreBuffer == nil {
				ml.scoreBuffer = make([]scoreRecord, 0, tuningWindowSize)
			}

			ticker := time.NewTicker(tuningInterval)
			defer ticker.Stop()

			saveTicker := time.NewTicker(saveInterval)
			defer saveTicker.Stop()

			for {
				select {
				case rec := <-ml.scoreCh:
					if len(ml.scoreBuffer) >= tuningWindowSize {
						copy(ml.scoreBuffer, ml.scoreBuffer[tuningWindowSize/2:])
						ml.scoreBuffer = ml.scoreBuffer[:tuningWindowSize/2]
					}
					ml.scoreBuffer = append(ml.scoreBuffer, rec)

				case <-ticker.C:
					ml.tuneThreshold()

				case <-saveTicker.C:
					ml.persistState()

				case <-ctx.Done():
					LogInfo("[ML-GUARD] Saving state on shutdown...")
					ml.persistState()
					return
				}
			}
		}()
	})
}

// persistState saves the current state to disk.
func (ml *MLGuard) persistState() {
	if ml.config.StateFile == "" {
		return
	}

	ml.RLock()
	currentThreshold := ml.config.Threshold
	ml.RUnlock()

	// Create snapshot of cache
	cacheSnapshot := ml.cache.Snapshot(maxPersistedCacheItems)

	state := MLGuardState{
		Threshold:     currentThreshold,
		ScoreBuffer:   ml.scoreBuffer,
		CacheSnapshot: cacheSnapshot,
		SavedAt:       time.Now(),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		LogWarn("[ML-GUARD] Failed to marshal state: %v", err)
		return
	}

	if err := os.WriteFile(ml.config.StateFile, data, 0644); err != nil {
		LogWarn("[ML-GUARD] Failed to save state to %s: %v", ml.config.StateFile, err)
	} else {
		LogDebug("[ML-GUARD] State saved to %s (Snapshot: %d items)", ml.config.StateFile, len(cacheSnapshot))
	}
}

// RecordScore is non-blocking
func (ml *MLGuard) RecordScore(prob float64, wasBlocked bool) {
	if ml.scoreCh == nil {
		return
	}
	select {
	case ml.scoreCh <- scoreRecord{Prob: prob, WasBlocked: wasBlocked}:
	default:
		// Channel full, drop metric
	}
}

// tuneThreshold logic
func (ml *MLGuard) tuneThreshold() {
	count := len(ml.scoreBuffer)

	if IsDebugEnabled() {
		LogDebug("[ML-TUNER] Evaluating threshold... (Samples in window: %d)", count)
	}

	if count < 100 {
		if IsDebugEnabled() {
			LogDebug("[ML-TUNER] Not enough samples (<100) to tune.")
		}
		return
	}

	var allowedScores []float64
	for _, rec := range ml.scoreBuffer {
		if !rec.WasBlocked {
			allowedScores = append(allowedScores, rec.Prob)
		}
	}

	allowedCount := len(allowedScores)
	if allowedCount < 50 {
		if IsDebugEnabled() {
			LogDebug("[ML-TUNER] Not enough ALLOWED samples (%d < 50) to tune.", allowedCount)
		}
		return
	}

	sort.Float64s(allowedScores)

	idx := int(float64(allowedCount) * 0.99)
	if idx >= allowedCount {
		idx = allowedCount - 1
	}
	p99Allowed := allowedScores[idx]

	proposed := p99Allowed + 0.03

	ml.Lock() // Still need lock to update global Config
	current := ml.config.Threshold

	if IsDebugEnabled() {
		p50 := allowedScores[int(float64(allowedCount)*0.50)]
		p90 := allowedScores[int(float64(allowedCount)*0.90)]
		LogDebug("[ML-TUNER] Analysis Stats: Samples=%d | p50=%.4f p90=%.4f p99=%.4f | Target=%.4f vs Current=%.4f",
			count, p50, p90, p99Allowed, proposed, current)
	}

	diff := proposed - current
	originalProposed := proposed

	if diff > maxThresholdChange {
		proposed = current + maxThresholdChange
	} else if diff < -maxThresholdChange {
		proposed = current - maxThresholdChange
	}

	if proposed < minSafeThreshold {
		proposed = minSafeThreshold
	}
	if proposed > maxSafeThreshold {
		proposed = maxSafeThreshold
	}

	if math.Abs(proposed-current) > 0.01 {
		LogInfo("[ML-GUARD] Dynamic Tuning: Shifted threshold %.2f -> %.2f (p99 Allowed=%.2f, Dampened from %.2f)",
			current, proposed, p99Allowed, originalProposed)
		ml.config.Threshold = proposed
		if ml.cache != nil {
			ml.cache.Flush()
		}
		go ml.persistState()
	}
	ml.Unlock()
}

// Check evaluates a domain
func (ml *MLGuard) Check(domain string, recordType string, mode string, isResponse bool) (bool, float64, string) {
	if !ml.ready.Load() || !ml.config.Enabled || mode == "disable" || mode == "" {
		return false, 0, ""
	}

	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}

	if len(domain) < ml.config.MinLength {
		return false, 0, "too_short"
	}

	domainClean := strings.ToLower(domain)

	if res, ok := ml.cache.Get(domainClean); ok {
		if IsDebugEnabled() {
			LogDebug("[ML-GUARD] Cache Hit: %s -> Prob: %.4f", domainClean, res.Prob)
		}
		return res.Suspicious, res.Prob, res.Reason
	}

	if IsDebugEnabled() {
		LogDebug("[ML-SF] Joining analysis flight for %s", domainClean)
	}

	// Singleflight: Coalesce concurrent analysis
	v, _, shared := ml.flightGroup.Do(domainClean, func() (interface{}, error) {
		// Double-check cache inside lock
		if res, ok := ml.cache.Get(domainClean); ok {
			return res, nil
		}

		if IsDebugEnabled() {
			LogDebug("[ML-SF] Executing analysis (Leader) for %s", domainClean)
		}

		ml.RLock()
		scoreBad := ml.probBad
		scoreGood := ml.probGood
		badMap := ml.badProbs
		goodMap := ml.goodProbs
		tldMap := ml.tldCounts
		ml.RUnlock()

		debug := IsDebugEnabled()

		if debug {
			LogDebug("[ML-DETAIL] Analysis for '%s'", domainClean)
		}

		suffix, icann := publicsuffix.PublicSuffix(domainClean)
		var suspiciousFeatures []string

		if !icann && !strings.Contains(suffix, ".") {
			penalty := 10.0
			scoreBad += penalty
			suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("UNKNOWN_TLD(%s)", suffix))
			if debug {
				LogDebug("[ML-DETAIL] %s | Feature: Unknown TLD '%s' (+%.2f Bad)", domainClean, suffix, penalty)
			}
		}

		keepSuffix := false
		if _, isHighRisk := highRiskTLDs[suffix]; isHighRisk {
			penalty := 5.0
			scoreBad += penalty
			suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("RISKY_TLD(%s)", suffix))
			keepSuffix = true
			if debug {
				LogDebug("[ML-DETAIL] %s | Feature: Risky TLD '%s' (+%.2f Bad)", domainClean, suffix, penalty)
			}
		}

		if count, ok := tldMap[suffix]; ok {
			if count > 100 {
				penalty := math.Log(float64(count) / 100.0)
				if penalty > 5.0 {
					penalty = 5.0
				}
				scoreBad += penalty
				suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("FREQ_TLD(%s:%d)", suffix, count))
				if debug {
					LogDebug("[ML-DETAIL] %s | Feature: Frequent TLD '%s' (Count %d) (+%.2f Bad)", domainClean, suffix, count, penalty)
				}
			}
		}

		payload := domainClean
		if len(suffix) > 0 && len(domainClean) > len(suffix) {
			if !keepSuffix {
				payload = domainClean[:len(domainClean)-len(suffix)]
				payload = strings.TrimSuffix(payload, ".")
			}
		} else if len(suffix) > 0 && len(domainClean) == len(suffix) {
			if !keepSuffix {
				return AnalysisResult{Suspicious: false, Prob: 0, Reason: "tld_only"}, nil
			}
		}

		parts := strings.Split(payload, ".")
		limit := len(parts)
		var maxTokenScore float64
		var maxToken string

		for i := 0; i < limit; i++ {
			token := parts[i]

			if len(token) < 2 {
				continue
			}
			if _, isCommon := commonLabels[token]; isCommon {
				continue
			}
			if _, isSafe := safeTLDs[token]; isSafe {
				continue
			}

			if _, isHighRisk := highRiskLabels[token]; isHighRisk {
				penalty := 8.0
				scoreBad += penalty
				suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("RISKY_LABEL(%s)", token))
				if debug {
					LogDebug("[ML-DETAIL] %s | Feature: Risky Label '%s' (+%.2f Bad)", domainClean, token, penalty)
				}
			}

			distance := float64(limit - i)
			posMultiplier := 0.4
			if isResponse {
				posMultiplier = 0.2
			}

			weight := 1.0 + (distance * posMultiplier)

			pBad, okB := badMap[token]
			if !okB {
				pBad = -15.0
			}

			pGood, okG := goodMap[token]
			if !okG {
				pGood = -15.0
			}

			badContrib := pBad * weight
			goodContrib := pGood * weight

			scoreBad += badContrib
			scoreGood += goodContrib

			tokenScore := badContrib - goodContrib
			if tokenScore > maxTokenScore {
				maxTokenScore = tokenScore
				maxToken = token
			}

			if debug {
				LogDebug("[ML-DETAIL] %s | Token '%s' (W=%.2f): Bad=%.2f, Good=%.2f", domainClean, token, weight, badContrib, goodContrib)
			}

			if len(token) > 15 {
				lenBad := badMap["LEN>15"] * weight
				lenGood := goodMap["LEN>15"] * weight
				scoreBad += lenBad
				scoreGood += lenGood
			}

			allDigits := true
			for _, r := range token {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				digBad := badMap["HIGH_DIGITS"] * weight
				digGood := goodMap["HIGH_DIGITS"] * weight
				scoreBad += digBad
				scoreGood += digGood
				suspiciousFeatures = append(suspiciousFeatures, "ALL_DIGITS")
			}

			entropy := calculateEntropy(token)
			if entropy > 3.8 {
				entPenalty := (entropy - 3.8) * 5.0 * weight
				scoreBad += entPenalty
				suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("HIGH_ENTROPY(%.2f)", entropy))
				if debug {
					LogDebug("[ML-DETAIL] %s | Token '%s' High Entropy (%.2f): Bad+=%.2f", domainClean, token, entropy, entPenalty)
				}
			}
		}

		logOdds := scoreBad - scoreGood
		prob := 1.0 / (1.0 + math.Exp(-logOdds))

		if debug {
			LogDebug("[ML-DETAIL] %s | Final: LogOdds=%.2f, Prob=%.4f", domainClean, logOdds, prob)
		}

		isSuspicious := prob >= ml.config.Threshold

		var reason string
		if isSuspicious {
			if len(suspiciousFeatures) == 0 && maxToken != "" {
				suspiciousFeatures = append(suspiciousFeatures, fmt.Sprintf("TOKEN_WEIGHT(%s)", maxToken))
			} else if len(suspiciousFeatures) == 0 {
				suspiciousFeatures = append(suspiciousFeatures, "CUMULATIVE_WEIGHT")
			}

			featureSummary := strings.Join(suspiciousFeatures, ",")
			if len(featureSummary) > 50 {
				featureSummary = featureSummary[:47] + "..."
			}
			reason = fmt.Sprintf("High Probability (%.1f%%) patterns: [%s]", prob*100, featureSummary)
		}

		result := AnalysisResult{
			Suspicious: isSuspicious,
			Prob:       prob,
			Reason:     reason,
		}

		ml.cache.Add(domainClean, result)
		return result, nil
	})

	if IsDebugEnabled() {
		LogDebug("[ML-SF] Analysis flight done for %s (Shared: %v)", domainClean, shared)
	}

	res := v.(AnalysisResult)
	return res.Suspicious, res.Prob, res.Reason
}

// DecideAction determines whether to Log or Block
func (ml *MLGuard) DecideAction(mode string, isResponse bool, isSuspicious bool) (shouldBlock bool, shouldLog bool) {
	if !isSuspicious || mode == "" || mode == "disable" {
		return false, false
	}

	mode = strings.ToLower(mode)

	if mode == "block" {
		return true, true
	}
	if mode == "log" {
		return false, true
	}

	if isResponse {
		if mode == "block-response" {
			return true, true
		}
		if mode == "log-response" {
			return false, true
		}
	} else {
		if mode == "block-query" {
			return true, true
		}
		if mode == "log-query" {
			return false, true
		}
	}

	return false, false
}

// calculateEntropy optimized to use zero-alloc stack array
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}

	var entropy float64
	total := float64(len(s))

	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

