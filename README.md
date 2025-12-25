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
```
Usage: ./dproxy [options]

Description:
  A robust DNS proxy supporting modern encrypted DNS protocols (DoT, DoH, DoH3, DoQ)
  alongside legacy UDP/TCP. It features smart upstream selection strategies,
  in-memory caching, and connection pooling for optimal performance.

Options:
  -addr string
    	Bind address for all protocols (default "0.0.0.0")
  -cache-size int
    	Maximum number of cached entries (default 10000)
  -cert string
    	Path to TLS certificate file
  -https int
    	DoH/DoH3 listening port (default 443)
  -insecure
    	Allow unverifiable hostnames (DANGEROUS: MITM risk)
  -key string
    	Path to TLS key file
  -no-cache
    	Disable DNS response caching
  -strategy string
    	Upstream selection strategy (failover, fastest, random, round-robin, race) (default "failover")
  -timeout duration
    	Query timeout for all protocols (default 5s)
  -tls int
    	DoT/DoQ listening port (default 853)
  -udp int
    	UDP/TCP listening port (default 53)
  -upstream value
    	Upstream server URL or file path

Strategies (-strategy):
  failover     Use the first valid upstream; switch only if it fails (Default).
  fastest      Measure latency (RTT) and prefer the fastest upstream. Includes 
               epsilon-greedy exploration (10%!c(string=./dproxy)hance) to re-check slower servers.
  round-robin  Rotate through upstreams sequentially for load balancing.
  random       Pick a random upstream for every request.
  race         Send request to ALL upstreams simultaneously; return the first response.

Examples:
  1. Simple UDP/TCP Proxy (defaults to 127.0.0.1:5355 upstream):
     ./dproxy

  2. Use Cloudflare DoH with "fastest" strategy:
     ./dproxy -upstream doh://cloudflare-dns.com/dns-query -strategy fastest

  3. Mix Protocols (Google DoT + Quad9 DoQ) with specific listening ports:
     ./dproxy -upstream tls://8.8.8.8 -upstream quic://dns.quad9.net -udp 5300 -tls 8530

  4. Load upstreams from a file (one URL per line) with caching disabled:
     ./dproxy -upstream ./resolvers.txt -no-cache

  5. Secure DoH Server (requires certs) proxying to local BIND:
     ./dproxy -cert fullchain.pem -key privkey.pem -upstream udp://127.0.0.1:53

  6. Bootstrap IP (skip system DNS for upstream resolution):
     ./dproxy -upstream "doh://dns.google/dns-query#8.8.4.4"


Notes:
  - Default bind address is 0.0.0.0 (all interfaces).
  - Self-signed certificates are generated automatically if -cert/-key are missing 
    (clients may reject these).
  - See also "example-upstreams.list" for more information on upstream syntax and usage.
```
