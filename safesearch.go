/*
File: safesearch.go
Version: 2.2.1 (Fix unused imports)
Description: Provides Safe Search domain mappings using netip.Addr for memory efficiency.
             FIXED: Removed unused "net" import.
*/

package main

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Safe Search Target Hostnames (The official CNAME targets)
const (
	// Google - Forces SafeSearch ON
	TargetGoogleStrict = "forcesafesearch.google.com"

	// YouTube - Restricts content maturity
	TargetYouTubeStrict   = "restrict.youtube.com"         // Strict Mode
	TargetYouTubeModerate = "restrictmoderate.youtube.com" // Moderate Mode

	// Bing - Forces Strict Mode
	TargetBingStrict = "strict.bing.com"

	// DuckDuckGo - Forces Safe Search
	TargetDuckDuckGo = "safe.duckduckgo.com"

	// Startpage - Forces Safe Search
	TargetStartpage = "safe.startpage.com"

	// Brave Search - Forces Safe Search
	TargetBrave = "safesearch.brave.com"

	// Qwant - Forces Safe Search
	TargetQwant = "safesearch.qwant.com"

	// DailyMotion - Gatekeeper (Restricted Mode)
	TargetDailyMotion = "gatekeeper.dailymotion.com"

	// Yandex - Family Mode
	TargetYandexFamily = "family.yandex.ru"

	// Pixabay - Safe Search
	TargetPixabay = "safesearch.pixabay.com"
)

// IP Constants for services that do not provide CNAMEs
// Using netip.MustParseAddr for compile-time safety on constants
var (
	// Ecosia SafeSearch IP (Official: 185.136.252.19)
	IPEcosiaSafe = netip.MustParseAddr("185.136.252.19")
)

const (
	SafeSearchModeNone     = "none"
	SafeSearchModeModerate = "moderate"
	SafeSearchModeFull     = "full"
)

// SafeSearchResult contains the overrides using optimized types
type SafeSearchResult struct {
	IPs      map[string][]netip.Addr
	CNAMEs   map[string]string
	Services map[string]string
}

// Cache for resolved VIPs to avoid repeated lookups during config generation
// Key: Hostname -> Value: Slice of netip.Addr
var (
	resolvedVIPs  = make(map[string][]netip.Addr)
	resolvedMutex sync.Mutex
)

// resolveVIP uses the configured bootstrap servers to resolve the hostname.
func resolveVIP(hostname string) []netip.Addr {
	resolvedMutex.Lock()
	if ips, ok := resolvedVIPs[hostname]; ok {
		resolvedMutex.Unlock()
		return ips
	}
	resolvedMutex.Unlock()

	// If no bootstrap servers are configured, fall back to nil (safesearch will use CNAME)
	if len(bootstrapServers) == 0 {
		LogWarn("[SAFESEARCH] No bootstrap servers available to resolve VIP for %s", hostname)
		return nil
	}

	var ips []netip.Addr
	var err error

	// Try each bootstrap server
	for _, server := range bootstrapServers {
		// Ensure port 53 if missing
		target := server
		if !strings.Contains(target, ":") {
			target = target + ":53"
		}

		c := &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		}

		// Try A record
		msgA := new(dns.Msg)
		msgA.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		rA, _, errA := c.Exchange(msgA, target)

		if errA == nil && rA != nil && rA.Rcode == dns.RcodeSuccess {
			for _, ans := range rA.Answer {
				if a, ok := ans.(*dns.A); ok {
					// Convert net.IP to netip.Addr
					if addr, ok := netip.AddrFromSlice(a.A); ok {
						ips = append(ips, addr)
					}
				}
			}
		}

		// Try AAAA record
		msgAAAA := new(dns.Msg)
		msgAAAA.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		rAAAA, _, errAAAA := c.Exchange(msgAAAA, target)

		if errAAAA == nil && rAAAA != nil && rAAAA.Rcode == dns.RcodeSuccess {
			for _, ans := range rAAAA.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					if addr, ok := netip.AddrFromSlice(aaaa.AAAA); ok {
						ips = append(ips, addr)
					}
				}
			}
		}

		// If we got IPs, we are done
		if len(ips) > 0 {
			break
		}

		if errA != nil {
			err = errA
		}
	}

	if len(ips) > 0 {
		resolvedMutex.Lock()
		resolvedVIPs[hostname] = ips
		resolvedMutex.Unlock()
		LogDebug("[SAFESEARCH] Resolved VIP for %s -> %v using bootstrap", hostname, ips)
		return ips
	}

	LogWarn("[SAFESEARCH] Failed to resolve VIP for %s using bootstrap servers: %v. Will fall back to CNAME.", hostname, err)
	return nil
}

// GenerateSafeSearchConfig returns the domain mappings for the requested mode
func GenerateSafeSearchConfig(mode string) *SafeSearchResult {
	m := strings.ToLower(mode)

	// Handle synonyms for "off"
	if m == "" || m == SafeSearchModeNone || m == "off" || m == "disable" || m == "disabled" || m == "false" {
		return nil
	}

	if m != SafeSearchModeModerate && m != SafeSearchModeFull {
		m = SafeSearchModeFull
	}

	res := &SafeSearchResult{
		IPs:      make(map[string][]netip.Addr),
		CNAMEs:   make(map[string]string),
		Services: make(map[string]string),
	}

	// Helper: Resolve Target IP and map domain to it. Fallback to CNAME.
	addRule := func(domain, target, service string) {
		// Try to resolve the target CNAME to IPs using bootstrap servers
		ips := resolveVIP(target)

		if len(ips) > 0 {
			res.IPs[domain] = ips
			res.Services[domain] = service
		} else {
			// Fallback
			res.CNAMEs[domain] = target + "."
			res.Services[domain] = service
		}
	}

	// Helper: Add static IP rule (for services like Ecosia that don't have a CNAME VIP)
	addStaticIPRule := func(domain string, ip netip.Addr, service string) {
		res.IPs[domain] = []netip.Addr{ip}
		res.Services[domain] = service
	}

	// --- Google ---
	for _, domain := range googleDomains {
		addRule(domain, TargetGoogleStrict, "Google")
		addRule("www."+domain, TargetGoogleStrict, "Google")
	}

	// --- YouTube ---
	targetYT := TargetYouTubeStrict
	if m == SafeSearchModeModerate {
		targetYT = TargetYouTubeModerate
	}

	ytDomains := []string{
		"www.youtube.com",
		"m.youtube.com",
		"youtubei.googleapis.com",
		"youtube.googleapis.com",
		"www.youtube-nocookie.com",
	}
	for _, d := range ytDomains {
		addRule(d, targetYT, "YouTube")
	}

	// --- Bing ---
	addRule("bing.com", TargetBingStrict, "Bing")
	addRule("www.bing.com", TargetBingStrict, "Bing")

	// --- DuckDuckGo ---
	addRule("duckduckgo.com", TargetDuckDuckGo, "DuckDuckGo")
	addRule("www.duckduckgo.com", TargetDuckDuckGo, "DuckDuckGo")

	// --- Startpage ---
	addRule("startpage.com", TargetStartpage, "Startpage")
	addRule("www.startpage.com", TargetStartpage, "Startpage")

	// --- Brave Search ---
	addRule("search.brave.com", TargetBrave, "Brave Search")

	// --- Ecosia (IP-based) ---
	if IPEcosiaSafe.IsValid() {
		addStaticIPRule("ecosia.org", IPEcosiaSafe, "Ecosia")
		addStaticIPRule("www.ecosia.org", IPEcosiaSafe, "Ecosia")
	}

	// --- Qwant ---
	addRule("qwant.com", TargetQwant, "Qwant")
	addRule("www.qwant.com", TargetQwant, "Qwant")

	// --- DailyMotion ---
	addRule("dailymotion.com", TargetDailyMotion, "DailyMotion")
	addRule("www.dailymotion.com", TargetDailyMotion, "DailyMotion")

	// --- Yandex ---
	addRule("yandex.com", TargetYandexFamily, "Yandex")
	addRule("yandex.ru", TargetYandexFamily, "Yandex")
	addRule("ya.ru", TargetYandexFamily, "Yandex")

	// --- Pixabay ---
	addRule("pixabay.com", TargetPixabay, "Pixabay")

	return res
}

// Extensive list of Google domains
var googleDomains = []string{
	"google.com", "google.ad", "google.ae", "google.com.af", "google.com.ag", "google.com.ai",
	"google.am", "google.co.ao", "google.com.ar", "google.as", "google.at", "google.com.au",
	"google.az", "google.ba", "google.com.bd", "google.be", "google.bf", "google.bg",
	"google.com.bh", "google.bi", "google.bj", "google.com.bn", "google.com.bo", "google.com.br",
	"google.bs", "google.bt", "google.co.bw", "google.by", "google.com.bz", "google.ca",
	"google.cd", "google.cf", "google.cg", "google.ch", "google.ci", "google.co.ck",
	"google.cl", "google.cm", "google.cn", "google.com.co", "google.co.cr", "google.com.cu",
	"google.cv", "google.com.cy", "google.cz", "google.de", "google.dj", "google.dk",
	"google.dm", "google.com.do", "google.dz", "google.com.ec", "google.ee", "google.com.eg",
	"google.es", "google.com.et", "google.fi", "google.com.fj", "google.fm", "google.fr",
	"google.ga", "google.ge", "google.gg", "google.com.gh", "google.com.gi", "google.gl",
	"google.gm", "google.gp", "google.gr", "google.com.gt", "google.gy", "google.com.hk",
	"google.hn", "google.hr", "google.ht", "google.hu", "google.co.id", "google.ie",
	"google.co.il", "google.im", "google.co.in", "google.iq", "google.is", "google.it",
	"google.je", "google.com.jm", "google.jo", "google.co.jp", "google.co.ke", "google.com.kh",
	"google.ki", "google.kg", "google.co.kr", "google.com.kw", "google.kz", "google.la",
	"google.com.lb", "google.li", "google.lk", "google.co.ls", "google.lt", "google.lu",
	"google.lv", "google.com.ly", "google.co.ma", "google.md", "google.me", "google.mg",
	"google.mk", "google.ml", "google.com.mm", "google.mn", "google.ms", "google.com.mt",
	"google.mu", "google.mv", "google.mw", "google.com.mx", "google.com.my", "google.co.mz",
	"google.com.na", "google.com.nf", "google.com.ng", "google.com.ni", "google.nl", "google.no",
	"google.com.np", "google.nr", "google.nu", "google.co.nz", "google.com.om", "google.com.pa",
	"google.com.pe", "google.com.pg", "google.com.ph", "google.pk", "google.pl", "google.pn",
	"google.com.pr", "google.ps", "google.pt", "google.com.py", "google.qa", "google.ro",
	"google.rs", "google.ru", "google.rw", "google.com.sa", "google.com.sb", "google.sc",
	"google.se", "google.com.sg", "google.sh", "google.si", "google.sk", "google.com.sl",
	"google.sn", "google.so", "google.sm", "google.sr", "google.st", "google.com.sv",
	"google.td", "google.tg", "google.co.th", "google.com.tj", "google.tl", "google.tm",
	"google.tn", "google.to", "google.com.tr", "google.tt", "google.com.tw", "google.co.tz",
	"google.ua", "google.co.ug", "google.co.uk", "google.com.uy", "google.co.uz", "google.com.vc",
	"google.co.ve", "google.co.vi", "google.com.vn", "google.vu", "google.ws", "google.co.za",
	"google.co.zm", "google.co.zw", "google.cat",
}

