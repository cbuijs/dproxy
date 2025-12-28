/*
File: utils.go
Description: Common utility functions for IP parsing and network address handling.
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

