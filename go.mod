module dproxy

go 1.24.0

// Newer versions of quic-go break stuff
replace github.com/quic-go/quic-go => github.com/quic-go/quic-go v0.42.0

replace github.com/quic-go/qpack => github.com/quic-go/qpack v0.4.0

require (
	github.com/miekg/dns v1.1.72
	github.com/quic-go/quic-go v0.59.0
	github.com/vishvananda/netlink v1.3.1
	github.com/yl2chen/cidranger v1.0.2
	golang.org/x/net v0.49.0
	golang.org/x/sync v0.19.0
	golang.org/x/time v0.14.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/onsi/ginkgo/v2 v2.27.5 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
)
