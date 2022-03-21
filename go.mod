module github.com/x186k/deadsfu

go 1.18

require (
	github.com/caddyserver/certmagic v0.14.6-0.20210923203551-1bbe11e2914b
	github.com/google/uuid v1.3.0
	github.com/libdns/cloudflare v0.1.0
	github.com/libdns/duckdns v0.1.1
	github.com/libdns/libdns v0.2.1
	github.com/miekg/dns v1.1.42
	github.com/pion/interceptor v0.1.7
	github.com/pion/rtcp v1.2.9
	github.com/pion/rtp v1.7.4
	github.com/pion/sdp/v3 v3.0.4
	github.com/pion/webrtc/v3 v3.1.24
	github.com/pkg/profile v1.5.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/x186k/ddns5libdns v0.0.0-20210712210115-f62ae7c09b3a
	go.uber.org/zap v1.17.0
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mholt/acmez v1.0.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pion/datachannel v1.5.2 // indirect
	github.com/pion/dtls/v2 v2.1.3 // indirect
	github.com/pion/ice/v2 v2.2.1 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns v0.0.5 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.8.2 // indirect
	github.com/pion/srtp/v2 v2.0.5 // indirect
	github.com/pion/stun v0.3.5 // indirect
	github.com/pion/transport v0.13.0 // indirect
	github.com/pion/turn/v2 v2.0.8 // indirect
	github.com/pion/udp v0.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/crypto v0.0.0-20220131195533-30dcbda58838 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

// replace github.com/spf13/pflag => ../pflag

// replace github.com/libdns/duckdns => ../duckdns
//replace github.com/libdns/cloudflare => ../cloudflare

// replace github.com/x186k/dynamicdns => ../dynamicdns
//replace github.com/pion/webrtc/v3 => ../webrtc
//replace github.com/pion/webrtc/v3 v3.0.4 => github.com/cameronelliott/webrtc/v3 v3.0.5
