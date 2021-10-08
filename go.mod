module github.com/x186k/deadsfu

go 1.16

require (
	github.com/caddyserver/certmagic v0.14.6-0.20210923203551-1bbe11e2914b
	github.com/cameronelliott/redislock v0.0.0-20210921213343-e1aca42b3191
	github.com/gomodule/redigo v1.8.6-0.20210930132055-56d644832b68
	github.com/google/uuid v1.3.0 // indirect
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
	github.com/pkg/profile v1.5.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/x186k/ddns5libdns v0.0.0-20210712210115-f62ae7c09b3a
	github.com/x186k/ftlserver v0.0.0-20211008231422-93a34c3b7195
	go.uber.org/zap v1.17.0
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)

// replace github.com/spf13/pflag => ../pflag

// replace github.com/libdns/duckdns => ../duckdns
//replace github.com/libdns/cloudflare => ../cloudflare

// replace github.com/x186k/dynamicdns => ../dynamicdns
//replace github.com/pion/webrtc/v3 => ../webrtc
//replace github.com/pion/webrtc/v3 v3.0.4 => github.com/cameronelliott/webrtc/v3 v3.0.5
