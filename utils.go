/*
File: utils.go
Description: Common utility functions for IP parsing and network address handling.
OPTIMIZED: Replaced string parsing with direct type assertions for net.Addr types to avoid allocations.
*/

package main

import (
	"fmt"
	"net"
)

func getIPFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		// Fallback for custom implementations or unexpected types
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

func getLocalIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}

func getLocalPort(addr net.Addr) int {
	if addr == nil {
		return 0
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.Port
	case *net.TCPAddr:
		return v.Port
	default:
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0
		}
		var p int
		fmt.Sscanf(port, "%d", &p)
		return p
	}
}

// IsValidARPCandidate returns true if the IP address is a candidate for ARP/NDP lookup.
func IsValidARPCandidate(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// 1. Unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return false
	}

	// 2. Loopback (127.0.0.1 or ::1)
	if ip.IsLoopback() {
		return false
	}

	// 3. Multicast
	if ip.IsMulticast() {
		return false
	}

	// 4. IPv4 Limited Broadcast
	if ip.Equal(net.IPv4bcast) {
		return false
	}

	return true
}

