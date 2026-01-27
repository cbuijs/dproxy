/*
File: ml_guard_cache.go
Version: 1.0.0
Description: Thread-safe sharded LRU cache for ML analysis results.
*/

package main

import (
	"container/list"
	"hash/maphash"
	"sync"
)

type mlCacheEntry struct {
	key    string
	result AnalysisResult
}

type mlCacheShard struct {
	sync.RWMutex
	items    map[string]*list.Element
	lruList  *list.List
	capacity int
}

type MLAnalysisCache struct {
	shards [mlCacheShards]*mlCacheShard
	seed   maphash.Seed
}

func NewMLAnalysisCache(capacity int) *MLAnalysisCache {
	c := &MLAnalysisCache{
		seed: maphash.MakeSeed(),
	}
	shardCap := capacity / mlCacheShards
	if shardCap < 1 {
		shardCap = 1
	}

	for i := 0; i < mlCacheShards; i++ {
		c.shards[i] = &mlCacheShard{
			items:    make(map[string]*list.Element),
			lruList:  list.New(),
			capacity: shardCap,
		}
	}
	return c
}

func (c *MLAnalysisCache) getShard(key string) *mlCacheShard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	h.WriteString(key)
	return c.shards[h.Sum64()&(mlCacheShards-1)]
}

func (c *MLAnalysisCache) Get(key string) (AnalysisResult, bool) {
	shard := c.getShard(key)
	shard.RLock()
	_, found := shard.items[key]
	shard.RUnlock()

	if found {
		shard.Lock()
		if el, ok := shard.items[key]; ok {
			shard.lruList.MoveToFront(el)
			shard.Unlock()
			return el.Value.(*mlCacheEntry).result, true
		}
		shard.Unlock()
	}
	return AnalysisResult{}, false
}

func (c *MLAnalysisCache) Add(key string, result AnalysisResult) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if elem, found := shard.items[key]; found {
		shard.lruList.MoveToFront(elem)
		elem.Value.(*mlCacheEntry).result = result
		return
	}

	if shard.lruList.Len() >= shard.capacity {
		if oldest := shard.lruList.Back(); oldest != nil {
			shard.lruList.Remove(oldest)
			delete(shard.items, oldest.Value.(*mlCacheEntry).key)
		}
	}

	entry := &mlCacheEntry{key: key, result: result}
	elem := shard.lruList.PushFront(entry)
	shard.items[key] = elem
}

func (c *MLAnalysisCache) Flush() {
	for _, shard := range c.shards {
		shard.Lock()
		shard.items = make(map[string]*list.Element)
		shard.lruList.Init()
		shard.Unlock()
	}
}

// Snapshot extracts items for persistence
func (c *MLAnalysisCache) Snapshot(limit int) map[string]AnalysisResult {
	snapshot := make(map[string]AnalysisResult)
	count := 0

	// Round-robin shards to get a diverse sample
	for _, shard := range c.shards {
		shard.RLock()
		// Iterate from front (most recent)
		for e := shard.lruList.Front(); e != nil; e = e.Next() {
			entry := e.Value.(*mlCacheEntry)
			snapshot[entry.key] = entry.result
			count++
			if count >= limit {
				shard.RUnlock()
				return snapshot
			}
		}
		shard.RUnlock()
	}
	return snapshot
}

