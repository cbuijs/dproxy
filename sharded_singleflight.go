/*
File: sharded_singleflight.go
Version: 1.2.0 (Hash Reuse Fix)
Description: A sharded wrapper around singleflight.Group to reduce mutex contention under high load.
             FIXED: Call h.Reset() before SetSeed to prevent panic when reusing hashers from pool.
*/

package main

import (
	"hash/maphash"
	"sync"

	"golang.org/x/sync/singleflight"
)

const shardedFlightCount = 512

type ShardedGroup struct {
	shards []*singleflight.Group
	seed   maphash.Seed
}

var sgPool = sync.Pool{
	New: func() any {
		return new(maphash.Hash)
	},
}

func NewShardedGroup() *ShardedGroup {
	sg := &ShardedGroup{
		shards: make([]*singleflight.Group, shardedFlightCount),
		seed:   maphash.MakeSeed(),
	}
	for i := 0; i < shardedFlightCount; i++ {
		sg.shards[i] = &singleflight.Group{}
	}
	return sg
}

func (g *ShardedGroup) getShard(key string) *singleflight.Group {
	// Use pool to avoid allocating hasher on every request
	h := sgPool.Get().(*maphash.Hash)
	
	// CRITICAL FIX: Reset hasher before setting seed to avoid panic on reuse
	h.Reset() 
	h.SetSeed(g.seed)
	h.WriteString(key)
	
	idx := h.Sum64() & (shardedFlightCount - 1)
	sgPool.Put(h)
	
	return g.shards[idx]
}

func (g *ShardedGroup) Do(key string, fn func() (interface{}, error)) (v interface{}, err error, shared bool) {
	return g.getShard(key).Do(key, fn)
}

func (g *ShardedGroup) DoChan(key string, fn func() (interface{}, error)) <-chan singleflight.Result {
	return g.getShard(key).DoChan(key, fn)
}

func (g *ShardedGroup) Forget(key string) {
	g.getShard(key).Forget(key)
}

