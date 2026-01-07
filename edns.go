/*
File: edns.go
Version: 1.0.1
Last Update: 2026-01-07
Description: Handles all EDNS0 related logic including ECS (Client Subnet) extraction/injection
             and MAC address embedding (Option 65001).
             Extracted from process.go for modularity.
             OPTIMIZED: Removed unconditional string formatting in hot path (logging).
*/

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const EDNS0_OPTION_MAC = 65001

func extractEDNS0ClientInfo(msg *dns.Msg, reqCtx *RequestContext) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}
	for _, option := range opt.Option {
		switch o := option.(type) {
		case *dns.EDNS0_SUBNET:
			reqCtx.ClientECS = o.Address
			family := o.Family
			mask := o.SourceNetmask
			var ipNet *net.IPNet
			if family == 1 {
				if mask > 32 {
					mask = 32
				}
				maskBytes := net.CIDRMask(int(mask), 32)
				ipNet = &net.IPNet{IP: o.Address, Mask: maskBytes}
			} else if family == 2 {
				if mask > 128 {
					mask = 128
				}
				maskBytes := net.CIDRMask(int(mask), 128)
				ipNet = &net.IPNet{IP: o.Address, Mask: maskBytes}
			}
			reqCtx.ClientECSNet = ipNet
			LogDebug("[EDNS0] Extracted ECS: %s/%d (family: %d)", o.Address.String(), mask, family)
		case *dns.EDNS0_LOCAL:
			if o.Code == EDNS0_OPTION_MAC && len(o.Data) > 0 {
				reqCtx.ClientEDNSMAC = net.HardwareAddr(o.Data)
				LogDebug("[EDNS0] Extracted MAC from Option 65001: %s", reqCtx.ClientEDNSMAC.String())
			}
		}
	}
}

func buildUpstreamInfo(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	var sb strings.Builder
	sb.WriteString(q.Name)
	sb.WriteString(" (")
	sb.WriteString(dns.TypeToString[q.Qtype])
	sb.WriteString(")")
	opt := msg.IsEdns0()
	if opt != nil {
		var extra []string
		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_SUBNET:
				extra = append(extra, fmt.Sprintf("ECS:%s/%d", v.Address.String(), v.SourceNetmask))
			case *dns.EDNS0_LOCAL:
				if v.Code == EDNS0_OPTION_MAC {
					extra = append(extra, fmt.Sprintf("MAC65001:%s", net.HardwareAddr(v.Data).String()))
				}
			}
		}
		if len(extra) > 0 {
			sb.WriteString(" [")
			sb.WriteString(strings.Join(extra, " "))
			sb.WriteString("]")
		}
	}
	return sb.String()
}

func addEDNS0Options(msg *dns.Msg, ip net.IP, mac net.HardwareAddr) {
	o := msg.IsEdns0()
	if o == nil {
		msg.SetEdns0(4096, true)
		o = msg.IsEdns0()
	}
	var opts []dns.EDNS0
	var hasECS bool
	var hasMAC bool
	var existingMAC net.HardwareAddr
	ecsMode := config.Server.EDNS0.ECS.Mode
	macMode := config.Server.EDNS0.MAC.Mode
	macSource := config.Server.EDNS0.MAC.Source

	// Debug logs are only generated if enabled to save allocations
	debugEnabled := IsDebugEnabled()

	for _, opt := range o.Option {
		if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			if debugEnabled {
				LogDebug("[EDNS0] Existing ECS: %s/%d", ecs.Address, ecs.SourceNetmask)
			}
		} else if local, ok := opt.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
			hasMAC = true
			existingMAC = net.HardwareAddr(local.Data)
			if debugEnabled {
				LogDebug("[EDNS0] Existing MAC: %s", existingMAC)
			}
		}
	}

	for _, opt := range o.Option {
		switch v := opt.(type) {
		case *dns.EDNS0_SUBNET:
			switch ecsMode {
			case "preserve":
				opts = append(opts, opt)
			case "add":
				if hasECS {
					opts = append(opts, opt)
				}
			case "replace":
				// Skip existing if replacing
			case "remove":
				// Skip
			}
		case *dns.EDNS0_LOCAL:
			if v.Code == EDNS0_OPTION_MAC {
				switch macMode {
				case "preserve":
					opts = append(opts, opt)
				case "add":
					if hasMAC {
						opts = append(opts, opt)
					}
				case "replace":
					// Skip existing
				case "remove":
					// Skip
				case "prefer-edns0":
					if hasMAC {
						opts = append(opts, opt)
					}
				case "prefer-arp":
					// Skip
				}
			} else {
				opts = append(opts, opt)
			}
		default:
			opts = append(opts, opt)
		}
	}

	shouldAddECS := false
	switch ecsMode {
	case "preserve":
		shouldAddECS = false
	case "add":
		shouldAddECS = !hasECS
	case "replace":
		shouldAddECS = true
	case "remove":
		shouldAddECS = false
	}
	if shouldAddECS && ip != nil {
		family := uint16(1)
		mask := uint8(32)
		isIPv6 := false
		if ip.To4() == nil {
			family = 2
			mask = 128
			isIPv6 = true
		}
		if isIPv6 {
			if config.Server.EDNS0.ECS.IPv6Mask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.IPv6Mask)
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
			}
			if mask > 128 {
				mask = 128
			}
		} else {
			if config.Server.EDNS0.ECS.IPv4Mask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.IPv4Mask)
			} else if config.Server.EDNS0.ECS.SourceMask > 0 {
				mask = uint8(config.Server.EDNS0.ECS.SourceMask)
			}
			if mask > 32 {
				mask = 32
			}
		}
		opts = append(opts, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        family,
			SourceNetmask: mask,
			Address:       ip,
		})
		if debugEnabled {
			LogDebug("[EDNS0] Added ECS: %s/%d", ip, mask)
		}
	}

	shouldAddMAC := false
	var macToAdd net.HardwareAddr
	switch macMode {
	case "preserve":
		shouldAddMAC = false
	case "add":
		shouldAddMAC = !hasMAC
		macToAdd = determineMAC(mac, existingMAC, macSource)
	case "replace":
		shouldAddMAC = true
		macToAdd = determineMAC(mac, existingMAC, macSource)
	case "remove":
		shouldAddMAC = false
	case "prefer-edns0":
		if hasMAC {
			shouldAddMAC = false
		} else if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
		}
	case "prefer-arp":
		if mac != nil && (macSource == "arp" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = mac
		} else if hasMAC && (macSource == "edns0" || macSource == "both") {
			shouldAddMAC = true
			macToAdd = existingMAC
		}
	}
	if shouldAddMAC && macToAdd != nil {
		opts = append(opts, &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: macToAdd})
		if debugEnabled {
			LogDebug("[EDNS0] Added MAC: %s", macToAdd)
		}
	}
	o.Option = opts

	if debugEnabled {
		LogDebug("[EDNS0] Final Options Count: %d", len(opts))
	}
}

func determineMAC(arpMAC, edns0MAC net.HardwareAddr, source string) net.HardwareAddr {
	switch source {
	case "arp":
		return arpMAC
	case "edns0":
		return edns0MAC
	case "both":
		if arpMAC != nil {
			return arpMAC
		}
		return edns0MAC
	default:
		return arpMAC
	}
}

func logEDNSDebug(msg *dns.Msg, qID uint16) {
	if opt := msg.IsEdns0(); opt != nil {
		var ednsInfo []string
		for _, option := range opt.Option {
			if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
				ednsInfo = append(ednsInfo, fmt.Sprintf("ECS=%s/%d", ecs.Address, ecs.SourceNetmask))
			} else if local, ok := option.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0_OPTION_MAC {
				ednsInfo = append(ednsInfo, fmt.Sprintf("MAC65001=%s", net.HardwareAddr(local.Data)))
			}
		}
		if len(ednsInfo) > 0 {
			LogDebug("[UPSTREAM_EDNS0] QID:%d | Forwarding with: %s", qID, strings.Join(ednsInfo, ", "))
		}
	}
}

func buildQueryInfo(q dns.Question) string {
	var sb strings.Builder
	sb.Grow(len(q.Name) + 10)
	sb.WriteString(q.Name)
	sb.WriteString(" (")
	sb.WriteString(dns.TypeToString[q.Qtype])
	sb.WriteString(")")
	return sb.String()
}

func appendEDNSInfoToLog(sb *strings.Builder, reqCtx *RequestContext, qInfo string, msg *dns.Msg) string {
	if opt := msg.IsEdns0(); opt != nil {
		sb.WriteString(qInfo)
		firstExtra := true
		if reqCtx.ClientECS != nil {
			sb.WriteString(" [ECS:")
			if reqCtx.ClientECSNet != nil {
				mask, _ := reqCtx.ClientECSNet.Mask.Size()
				sb.WriteString(reqCtx.ClientECS.String())
				sb.WriteString("/")
				sb.WriteString(strconv.Itoa(mask))
			} else {
				sb.WriteString(reqCtx.ClientECS.String())
			}
			sb.WriteString("]")
			firstExtra = false
		}
		if reqCtx.ClientEDNSMAC != nil {
			if !firstExtra {
				sb.WriteString(" ")
			} else {
				sb.WriteString(" [")
			}
			sb.WriteString("MAC65001:")
			sb.WriteString(reqCtx.ClientEDNSMAC.String())
			if firstExtra {
				sb.WriteString("]")
			}
		}
		if sb.Len() > len(qInfo) {
			return sb.String()
		}
	}
	return qInfo
}

