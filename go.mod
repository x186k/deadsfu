module github.com/x186k/deadsfu

go 1.16

require (
	github.com/caddyserver/certmagic v0.14.1-0.20210616191643-647f27cf265e
	github.com/google/gopacket v1.1.19
	github.com/kr/text v0.2.0 // indirect
	github.com/libdns/cloudflare v0.1.0
	github.com/libdns/duckdns v0.1.1
	github.com/libdns/libdns v0.2.1
	github.com/miekg/dns v1.1.42
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pion/interceptor v0.0.12
	github.com/pion/rtcp v1.2.6
	github.com/pion/rtp v1.6.2
	github.com/pion/sdp/v3 v3.0.4
	github.com/pion/webrtc/v3 v3.0.21
	github.com/pkg/profile v1.5.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/x186k/ddns5libdns v0.0.0-20210601224053-e288019a9d55
	go.uber.org/zap v1.17.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)

// replace github.com/spf13/pflag => ../pflag

// replace github.com/libdns/duckdns => ../duckdns
//replace github.com/libdns/cloudflare => ../cloudflare

// replace github.com/x186k/dynamicdns => ../dynamicdns
//replace github.com/pion/webrtc/v3 => ../webrtc
//replace github.com/pion/webrtc/v3 v3.0.4 => github.com/cameronelliott/webrtc/v3 v3.0.5
