//go:build linux

/*
File: arp_linux.go
Version: 1.1.0
Description: Linux-specific ARP/NDP table manager using Netlink subscriptions.
             OPTIMIZED: Added deduplication to prevent log spam on state changes (REACHABLE->STALE)
             where the MAC address remains the same.
*/

package main

import (
	"bytes"
	"context"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// maintainARPCache runs the background routine to keep the ARP table fresh.
// On Linux, this uses Netlink subscriptions to receive real-time updates from the kernel.
func maintainARPCache(ctx context.Context) {
	if config.ARP.Mode == "none" {
		LogInfo("[ARP] Maintenance disabled by config")
		return
	}

	LogInfo("[ARP] Starting Netlink subscription for ARP/NDP updates")

	// 1. Initial Population (Snapshot)
	populateNetlinkCache()

	// 2. Event Subscription
	updates := make(chan netlink.NeighUpdate)
	done := make(chan struct{})

	// Subscribe to neighbor updates
	if err := netlink.NeighSubscribe(updates, done); err != nil {
		LogWarn("[ARP] Failed to subscribe to netlink events: %v. Falling back to snapshot-only.", err)
		return
	}

	defer close(done)

	// Filter flags
	doV4 := config.ARP.Mode == "v4" || config.ARP.Mode == "both"
	doV6 := config.ARP.Mode == "v6" || config.ARP.Mode == "both"

	for {
		select {
		case <-ctx.Done():
			LogInfo("[ARP] Stopping Netlink subscription")
			return

		case update := <-updates:
			// Filter by IP family
			isV4 := update.Neigh.Family == netlink.FAMILY_V4
			isV6 := update.Neigh.Family == netlink.FAMILY_V6

			if (isV4 && !doV4) || (isV6 && !doV6) {
				continue
			}

			// Handle different message types
			switch update.Type {
			case syscall.RTM_NEWNEIGH:
				// Add or Update
				// We only want valid entries with a hardware address
				if isValidState(update.Neigh.State) && len(update.Neigh.HardwareAddr) > 0 && update.Neigh.IP != nil {
					ipStr := update.Neigh.IP.String()
					newMac := net.HardwareAddr(update.Neigh.HardwareAddr)

					arpCache.Lock()
					currentMac, exists := arpCache.table[ipStr]
					
					// DEDUPLICATION: Only update/log if the MAC actually changed or is new
					if !exists || !bytes.Equal(currentMac, newMac) {
						arpCache.table[ipStr] = newMac
						if IsDebugEnabled() {
							if exists {
								LogDebug("[ARP] Updated: %s -> %s (was %s)", update.Neigh.IP, newMac, currentMac)
							} else {
								LogDebug("[ARP] New: %s -> %s", update.Neigh.IP, newMac)
							}
						}
					}
					arpCache.Unlock()
					
				} else if update.Neigh.State&netlink.NUD_FAILED != 0 {
					// Explicit failure state, remove it
					if update.Neigh.IP != nil {
						ipStr := update.Neigh.IP.String()
						arpCache.Lock()
						if _, exists := arpCache.table[ipStr]; exists {
							delete(arpCache.table, ipStr)
							if IsDebugEnabled() {
								LogDebug("[ARP] Removed (Failed State): %s", update.Neigh.IP)
							}
						}
						arpCache.Unlock()
					}
				}

			case syscall.RTM_DELNEIGH:
				// Delete
				if update.Neigh.IP != nil {
					ipStr := update.Neigh.IP.String()
					arpCache.Lock()
					if _, exists := arpCache.table[ipStr]; exists {
						delete(arpCache.table, ipStr)
						if IsDebugEnabled() {
							LogDebug("[ARP] Deleted: %s", update.Neigh.IP)
						}
					}
					arpCache.Unlock()
				}
			}
		}
	}
}

// populateNetlinkCache grabs a full snapshot of the neighbor table
func populateNetlinkCache() {
	list, err := netlink.NeighList(0, 0)
	if err != nil {
		LogWarn("[ARP] Failed to list neighbors: %v", err)
		return
	}

	doV4 := config.ARP.Mode == "v4" || config.ARP.Mode == "both"
	doV6 := config.ARP.Mode == "v6" || config.ARP.Mode == "both"

	arpCache.Lock()
	defer arpCache.Unlock()

	count := 0
	for _, neigh := range list {
		isV4 := neigh.Family == netlink.FAMILY_V4
		isV6 := neigh.Family == netlink.FAMILY_V6

		if (isV4 && !doV4) || (isV6 && !doV6) {
			continue
		}

		// Only store entries that have a MAC and are in a valid state
		if isValidState(neigh.State) && len(neigh.HardwareAddr) > 0 && neigh.IP != nil {
			arpCache.table[neigh.IP.String()] = neigh.HardwareAddr
			count++
		}
	}

	LogInfo("[ARP] Initialized with %d entries from Netlink", count)
}

// isValidState returns true if the neighbor state indicates a valid, resolvable MAC.
func isValidState(state int) bool {
	// NUD_REACHABLE: Valid and reachable
	// NUD_PERMANENT: Static entry
	// NUD_STALE: Valid but needs verification (still usable)
	// NUD_DELAY: Valid, waiting for verification
	// NUD_PROBE: Valid, verification in progress
	const validMask = netlink.NUD_REACHABLE | netlink.NUD_PERMANENT | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE
	return (state & validMask) != 0
}

