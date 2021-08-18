package main

import (
	"github.com/spf13/pflag"
)

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")
// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap

var dialIngressURL = pflag.StringP("dial-ingress", "d", "", "Specify a URL for outbound dial for ingress")
var disableHtml = pflag.Bool("disable-html", false, "do not serve any html files, only allow pub/sub API")
var help = pflag.BoolP("help", "h", false, "Print the short usage")
var httpListenAddr = pflag.String("http-listen-addr", ":8080", "The address at which http will bind/listen")
var iceCandidateHost = pflag.String("ice-candidate-host", "", "For forcing the ice host candidate IP address")
var iceCandidateSrflx = pflag.String("ice-candidate-srflx", "", "For forcing the ice srflx candidate IP address")
var obsKey = pflag.String("obs-key", "", "Enable OBS/FTL ingest. Sample value: '123-abc'")
var rtpout = pflag.String("rtpout", "", "addr:port to send rtp, ie: '127.0.0.1:4444'")
var rtpWireshark = pflag.Bool("rtp-wireshark", false, "when on 127.0.0.1, also receive my sent packets")
var stunServer = pflag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")
var htmlFromDiskFlag = pflag.Bool("z-html-from-disk", false, "do not use embed html, use files from disk")
var cpuprofile = pflag.Int("z-cpu-profile", 0, "number of seconds to run + turn on profiling")
var debug = pflag.StringSlice("z-debug", []string{}, "comma separated list of debug flags. use 'help' to view")

var Usage = func() {
	pflag.PrintDefaults()
}
