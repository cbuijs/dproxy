# dproxy

Steps to compile:
```
git clone https://github.com/cbuijs/dproxy.git
cd dproxy
go mod tidy
go build -v -x -o dproxy main.go
chmod +x dproxy
./dproxy -h
```

# High-Performance Multi-Protocol DNS Proxy

Usage: ./dproxy [options]

Description:
  A robust DNS proxy supporting modern encrypted DNS protocols (DoT, DoH, DoH3, DoQ)
  alongside legacy UDP/TCP. It features smart upstream selection strategies,
  in-memory caching, and connection pooling for optimal performance.
<br><br>
Options:<br>
  -addr string<br>
    	Bind address for all protocols (default "0.0.0.0")<br>
  -cache-size int<br>
    	Maximum number of cached entries (default 10000)<br>
  -cert string<br>
    	Path to TLS certificate file<br>
  -https int<br>
    	DoH/DoH3 listening port (default 443)<br>
  -insecure<br>
    	Allow unverifiable hostnames (DANGEROUS: MITM risk)<br>
  -key string<br>
    	Path to TLS key file<br>
  -no-cache<br>
    	Disable DNS response caching<br>
  -strategy string<br>
    	Upstream selection strategy (failover, fastest, random, round-robin, race) (default "failover")<br>
  -timeout duration<br>
    	Query timeout for all protocols (default 5s)<br>
  -tls int<br>
    	DoT/DoQ listening port (default 853)<br>
  -udp int<br>
    	UDP/TCP listening port (default 53)<br>
  -upstream value<br>
    	Upstream server URL or file path<br>

Strategies (-strategy):<br>
  failover     Use the first valid upstream; switch only if it fails (Default).<br>
  fastest      Measure latency (RTT) and prefer the fastest upstream. Includes epsilon-greedy exploration (10%!c(string=./dproxy)hance) to re-check slower servers.<br>
  round-robin  Rotate through upstreams sequentially for load balancing.<br>
  random       Pick a random upstream for every request.<br>
  race         Send request to ALL upstreams simultaneously; return the first response.<br>
<br><br>
Examples:<br>
  1. Simple UDP/TCP Proxy (defaults to 127.0.0.1:5355 upstream):<br>
     ./dproxy<br>
<br>
  2. Use Cloudflare DoH with "fastest" strategy:<br>
     ./dproxy -upstream doh://cloudflare-dns.com/dns-query -strategy fastest<br>
<br>
  3. Mix Protocols (Google DoT + Quad9 DoQ) with specific listening ports:<br>
     ./dproxy -upstream tls://8.8.8.8 -upstream quic://dns.quad9.net -udp 5300 -tls 8530<br>
<br>
  4. Load upstreams from a file (one URL per line) with caching disabled:<br>
     ./dproxy -upstream ./resolvers.txt -no-cache<br>
<br>
  5. Secure DoH Server (requires certs) proxying to local BIND:<br>
     ./dproxy -cert fullchain.pem -key privkey.pem -upstream udp://127.0.0.1:53<br>
<br>
  6. Bootstrap IP (skip system DNS for upstream resolution):<br>
     ./dproxy -upstream "doh://dns.google/dns-query#8.8.4.4"<br>
<br>
Notes:<br>
  - Default bind address is 0.0.0.0 (all interfaces).<br>
  - Self-signed certificates are generated automatically if -cert/-key are missing (clients may reject these).<br>

