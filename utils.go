/*
File: utils.go
Description: Common utility functions for IP parsing and network address handling.
OPTIMIZED: ExtractIPFromPTR now parses IP addresses from PTR records without string splitting allocations.
*/

package main

import (
	"net"
	"strconv"
	"strings"
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
		_, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(portStr)
		return p
	}
}

func IsValidARPCandidate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	return true
}

// ExtractIPFromPTR validates if a query name is a valid Reverse DNS (PTR) record
// and returns the IP address it represents.
// OPTIMIZED: Avoids strings.Split and heavy allocations by parsing in-place.
func ExtractIPFromPTR(qName string) net.IP {
	lenName := len(qName)
	
	// IPv4: 4.3.2.1.in-addr.arpa (min length roughly 13: 0.0.0.0.in-addr.arpa)
	const v4Suffix = ".in-addr.arpa"
	if lenName > len(v4Suffix) && strings.HasSuffix(qName, v4Suffix) {
		// Extract the IP part: "4.3.2.1"
		ipPart := qName[:lenName-len(v4Suffix)]
		
		// We expect 4 octets. We can parse them manually to avoid allocating a slice for Split.
		var octets [4]byte
		octetIdx := 0
		val := 0
		hasVal := false
		
		// Iterate backwards to reverse the IP (PTR is reversed)
		// "4.3.2.1" -> 1.2.3.4
		for i := 0; i < len(ipPart); i++ {
			c := ipPart[i]
			if c == '.' {
				if !hasVal || octetIdx >= 3 { return nil } // Empty octet or too many
				octets[3-octetIdx] = byte(val)
				octetIdx++
				val = 0
				hasVal = false
			} else if c >= '0' && c <= '9' {
				val = val*10 + int(c-'0')
				if val > 255 { return nil }
				hasVal = true
			} else {
				return nil // Invalid char
			}
		}
		if !hasVal || octetIdx != 3 { return nil }
		octets[0] = byte(val) // Last octet (which is first in string)
		
		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	} 
	
	// IPv6: b.a.9.8....1.0.0.2.ip6.arpa
	const v6Suffix = ".ip6.arpa"
	if lenName > len(v6Suffix) && strings.HasSuffix(qName, v6Suffix) {
		hexPart := qName[:lenName-len(v6Suffix)]
		
		ip := make(net.IP, 16)
		nibbleIdx := 0
		
		// Iterate backwards (PTR is reversed nibbles)
		// Format is dotted hex: f.e.d.c...
		// We need to fill ip[0] to ip[15]. ip[15] comes from the start of the string.
		
		// "a.b.0.0..." means the address ends in ...00ba
		// The string start corresponds to the LAST byte of the IP.
		
		for i := 0; i < len(hexPart); i++ {
			c := hexPart[i]
			if c == '.' {
				continue
			}
			
			var nibble byte
			if c >= '0' && c <= '9' {
				nibble = byte(c - '0')
			} else if c >= 'a' && c <= 'f' {
				nibble = byte(c - 'a' + 10)
			} else if c >= 'A' && c <= 'F' {
				nibble = byte(c - 'A' + 10)
			} else {
				return nil
			}
			
			if nibbleIdx >= 32 { return nil }
			
			// Map nibble index to byte index.
			// nibbleIdx 0 (start of str) -> ip[15] low nibble
			// nibbleIdx 1 -> ip[15] high nibble
			byteIdx := 15 - (nibbleIdx / 2)
			if nibbleIdx%2 == 0 {
				ip[byteIdx] |= nibble
			} else {
				ip[byteIdx] |= nibble << 4
			}
			nibbleIdx++
		}
		
		if nibbleIdx != 32 { return nil }
		return ip
	}
	
	return nil
}

