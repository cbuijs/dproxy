/*
File: utils.go
Description: Common utility functions for IP parsing and network address handling.
UPDATED: IsValidARPCandidate now explicitly ensures all valid IPv6 Unicast types (Global, ULA, Link-Local) are permitted.
*/

package main

import (
	"fmt"
	"net"
)

func getIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		if addr == nil {
			return nil
		}
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

	// 3. Multicast (224.0.0.0/4 or ff00::/8)
	// For IPv6, this strictly filters ff00::/8.
	// It DOES NOT filter:
	// - Link-Local Unicast (fe80::/10) -> VALID
	// - Unique Local Address (ULA) (fc00::/7) -> VALID
	// - Global Unicast (2000::/3) -> VALID
	if ip.IsMulticast() {
		return false
	}

	// 4. IPv4 Limited Broadcast (255.255.255.255)
	// Note: IPv6 does not have a broadcast address (uses multicast instead),
	// so this check only affects IPv4.
	if ip.Equal(net.IPv4bcast) {
		return false
	}

	return true
}

