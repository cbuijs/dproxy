# dproxy

NOTE: Use at own risk! Under constant development, testing and screwing it up all together ;-).

dproxy is a high-performance, programmable DNS forwarder and proxy implemented in Go. It integrates advanced protocol support (DoH3, DoQ), machine learning-based threat detection, and predictive caching strategies into a single binary.

It is designed for network administrators and privacy-conscious users requiring granular control over DNS traffic, robust security, and compliance with next-generation standards.

## Core Capabilities

### Multi-Protocol Support
dproxy functions as both a server (listener) and a client (upstream forwarder), supporting the full spectrum of DNS transport protocols:
* **Legacy:** UDP and TCP (RFC 1035).
* **Encrypted:** DNS-over-TLS (DoT - RFC 7858).
* **HTTPS:** DNS-over-HTTPS (DoH) via HTTP/2 and HTTP/3 (QUIC).
* **QUIC:** DNS-over-QUIC (DoQ - RFC 9250) for low-latency encrypted transport.
* **DDR:** Discovery of Designated Resolvers (RFC 9462) to facilitate automatic client upgrades to encrypted protocols.

### ML Guard (Heuristic Threat Detection)
The system moves beyond static blocklists by employing an embedded Machine Learning engine (`ml_guard.go`) to identify malicious domains in real-time.
* **Entropy Analysis:** Calculates Shannon entropy to detect Domain Generation Algorithms (DGA) commonly used by malware command-and-control networks.
* **N-Gram Analysis:** Evaluates character sequences to identify phishing patterns or unusual nomenclature.
* **Dynamic Thresholding:** The engine utilizes a feedback loop to auto-tune blocking thresholds based on local traffic baselines.
* **Local Training:** The model can be trained on local traffic history to reduce false positives specific to the deployment environment.

### Predictive Prefetching
dproxy utilizes a Markov Chain engine (`prefetch.go`) to model query probability.
* **Transition Matrices:** Records sequences of client queries (e.g., `domain.tld` followed by `assets.domain.tld`) to build a probability model.
* **Proactive Resolution:** Prefetches high-probability future queries during idle time, serving the subsequent response from cache with near-zero latency.
* **Stale Refresh:** Automatically identifies and refreshes frequently requested records before their TTL expires.

### Advanced Routing & Policy
Traffic routing decisions are made using a specialized Trie structure allowing for complex split-horizon configurations.
* **Granular Matching:** Rules can be defined based on Client IP, CIDR, MAC Address (resolved via local ARP/NDP table lookups), EDNS0 Client Subnet, or specific Query Domains.
* **Upstream Selection Strategies:**
    * `Fastest`: Tracks RTT to all upstreams and selects the lowest latency path.
    * `Race`: Broadcasts queries to all upstreams simultaneously and accepts the first response.
    * `Failover`, `Round-Robin`, `Random`.

### Security & Privacy
* **High-Performance Filtering:** Uses a radix tree (Trie) implementation for O(k) lookups of blocked domains, supporting massive HOSTS files and domain lists without significant performance degradation.
* **SafeSearch Enforcement:** Manipulates CNAME responses to enforce SafeSearch VIPs for Google, Bing, YouTube, and DuckDuckGo.
* **EDNS0 Privacy:** Options to strip, add, or modify Client Subnet (ECS) and MAC address (Option 65001) data before forwarding to upstreams.
* **Rate Limiting:** Per-client token-bucket rate limiting to mitigate DoS attacks and abuse.

## Architecture & Performance
* **Concurrency:** Utilizes sharded locks and maps for caching and state management to minimize contention on multi-core systems.
* **Connection Pooling:** Maintains persistent TCP and QUIC sessions to upstream resolvers, eliminating handshake overhead for subsequent queries.
* **Memory Management:** Extensive use of `sync.Pool` for byte buffers and DNS message structures to minimize garbage collection pressure (zero-alloc optimizations in hot paths).
* **Circuit Breaking:** Automatically detects upstream failures and temporarily removes unhealthy servers from the rotation.

## Configuration
Configuration is managed via a YAML file. Refer to [full_reference_config.yaml](https://github.com/cbuijs/dproxy/blob/main/full_reference_config.yaml) for the complete schema.

## Compilation
```
go mod tidy
go build -v -ldflags="-s -w" -o dproxy
```

## Disclaimer
This software includes features for traffic inspection, heuristic analysis, and blocking. Deploying this tool requires appropriate authorization on the target network. It can and will break stuff, and as it is mostly vibe-coded: Use at own risk!

