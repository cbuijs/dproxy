/*
File: context.go
Version: 1.0.0
Description: Defines the RequestContext struct and its lifecycle management (pooling).
             Extracted from process.go for modularity.
*/

package main

import (
	"net"
	"sync"
)

type RequestContext struct {
	ClientIP       net.IP
	ClientMAC      net.HardwareAddr
	ClientECS      net.IP
	ClientECSNet   *net.IPNet
	ClientEDNSMAC  net.HardwareAddr
	ServerIP       net.IP
	ServerPort     int
	ServerHostname string
	ServerPath     string
	QueryName      string
	Protocol       string
}

func (rc *RequestContext) Reset() {
	rc.ClientIP = nil
	rc.ClientMAC = nil
	rc.ClientECS = nil
	rc.ClientECSNet = nil
	rc.ClientEDNSMAC = nil
	rc.ServerIP = nil
	rc.ServerPort = 0
	rc.ServerHostname = ""
	rc.ServerPath = ""
	rc.QueryName = ""
	rc.Protocol = ""
}

func (rc *RequestContext) Clone() *RequestContext {
	newRC := &RequestContext{
		ServerPort:     rc.ServerPort,
		ServerHostname: rc.ServerHostname,
		ServerPath:     rc.ServerPath,
		QueryName:      rc.QueryName,
		Protocol:       rc.Protocol,
	}

	if len(rc.ClientIP) > 0 {
		newRC.ClientIP = make(net.IP, len(rc.ClientIP))
		copy(newRC.ClientIP, rc.ClientIP)
	}
	if len(rc.ClientMAC) > 0 {
		newRC.ClientMAC = make(net.HardwareAddr, len(rc.ClientMAC))
		copy(newRC.ClientMAC, rc.ClientMAC)
	}
	if len(rc.ClientECS) > 0 {
		newRC.ClientECS = make(net.IP, len(rc.ClientECS))
		copy(newRC.ClientECS, rc.ClientECS)
	}
	if rc.ClientECSNet != nil {
		mask := make(net.IPMask, len(rc.ClientECSNet.Mask))
		copy(mask, rc.ClientECSNet.Mask)
		ip := make(net.IP, len(rc.ClientECSNet.IP))
		copy(ip, rc.ClientECSNet.IP)
		newRC.ClientECSNet = &net.IPNet{IP: ip, Mask: mask}
	}
	if len(rc.ClientEDNSMAC) > 0 {
		newRC.ClientEDNSMAC = make(net.HardwareAddr, len(rc.ClientEDNSMAC))
		copy(newRC.ClientEDNSMAC, rc.ClientEDNSMAC)
	}
	if len(rc.ServerIP) > 0 {
		newRC.ServerIP = make(net.IP, len(rc.ServerIP))
		copy(newRC.ServerIP, rc.ServerIP)
	}

	return newRC
}

var reqCtxPool = sync.Pool{
	New: func() any {
		return &RequestContext{}
	},
}

