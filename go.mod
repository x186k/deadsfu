module github.com/x186k/deadsfu

go 1.16

require (
	github.com/caddyserver/certmagic v0.14.6-0.20210923203551-1bbe11e2914b
	github.com/kr/text v0.2.0 // indirect
	github.com/libdns/cloudflare v0.1.0
	github.com/libdns/duckdns v0.1.1
	github.com/libdns/libdns v0.2.1
	github.com/miekg/dns v1.1.42
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
github.com/pion/interceptor v0.0.13
	github.com/pion/rtcp v1.2.6
	github.com/pion/rtp v1.6.5
	github.com/pion/webrtc/v3 v3.0.32
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.5.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/x186k/ddns5libdns v0.0.0-20210712210115-f62ae7c09b3a
	go.uber.org/zap v1.17.0
	golang.org/x/net v0.0.0-20211215060638-4ddde0e984e9
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210831042530-f4d43177bf5e // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)

// replace github.com/spf13/pflag => ../pflag

// replace github.com/libdns/duckdns => ../duckdns
//replace github.com/libdns/cloudflare => ../cloudflare

// replace github.com/x186k/dynamicdns => ../dynamicdns
//replace github.com/pion/webrtc/v3 => ../webrtc
//replace github.com/pion/webrtc/v3 v3.0.4 => github.com/cameronelliott/webrtc/v3 v3.0.5
