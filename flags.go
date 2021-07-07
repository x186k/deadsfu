package main

import (

	//xflag "flag"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/spf13/pflag"
)

var ACMEAgreed = pflag.Bool("acme-agree", true, "You AGREE with the CA's terms. ie, LetsEncrypt.")
var ACMEEmailFlag = pflag.String("acme-email", "", "This is the email to provide to the ACME certifcate provider.")

var httpUrl = url.URL{}
var httpsUrl = url.URL{}

const httpsInterfaceFlagname = "https-interface"

var httpsInterfaceFlag = pflag.String(httpsInterfaceFlagname, "",
	`Specify the interface bind IP address for HTTPS, not for HTTP.
This is an advanced setting.
The default should work for most users. 
A V4 or V6 IP address is okay.
Do not provide port infomation here, use -https-url for port information.
Examples: '[::]'  '0.0.0.0' '192.168.2.1'  '10.1.2.3'  '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
Defaults to [::] (all interfaces)`)
var interfaceAddress net.IP

const ddnsPublicFlagName = "ddns-public"

var ddnsPublicFlag = pflag.BoolP(ddnsPublicFlagName, "k", false,
	`Which IP to use for dynamic DNS reg. 'false': use local IP address. 'true': use Public/NATTED IP address.`)

const ddnsRegisterName = "ddns-register"

var ddnsRegisterEnabled = pflag.BoolP(ddnsRegisterName, "f", true,
	`Enable Dynamic DNS registration for HTTPS hostnames.
When true:
1) IPv4/IPv6 addresses will be detected.
2) They will be registered for the given HTTPS hostname.
For Duckdns, the hostname must be already created on the Web.
For Cloudflare, ddns5, the hostname will be created if possible. (Flag -cloudflare may be needed)
When false:
You need to have configured DNS and your IPv4/IPv6 (A/AAAA) addrs yourself`)

// reduce complexity, removed
//var httpsOpenPortsFlag =

//var silenceJanus = flag.Bool("silence-janus", false, "if true will throw away janus output")
var htmlFromDiskFlag = pflag.Bool("z-html-from-disk", false, "do not use embed html, use files from disk")
var ddnsutilDebug = pflag.Bool("z-ddns-debug", false, "enable ddns debug output")
var cpuprofile = pflag.Int("z-cpu-profile", 0, "number of seconds to run + turn on profiling")
var debug = pflag.Bool("z-debug", false, "enable debug output")

//var debugCertmagic = flag.Bool("z-debug-certmagic", false, "enable debug output for certmagic and letsencrypt")
var debugStagingCertificate = pflag.Bool("z-debug-staging", false, "use the LetsEncrypt staging certificate")

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")

// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
var disableHtml = pflag.Bool("disable-html", false, "do not serve any html files, only allow pub/sub API")
var dialIngressURL = pflag.StringP("dial-ingress", "d", "", "Specify a URL for outbound dial for ingress")

//var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")

var obsStudio = pflag.Bool("obs-studio", false, "Enable OBS Studio by tweaking SSL/TLS version numbers")
var helpAll = pflag.BoolP("all", "a", false, "Print usage on all flags")
var help = pflag.BoolP("help", "h", false, "Print usage on the most common flags")
var cloudflareDDNS = pflag.Bool("cloudflare", false, "Use Cloudflare API for DDNS and HTTPS ACME/Let's encrypt")
var stunServer = pflag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")

//var openTab = flag.Bool("opentab", false, "Open a browser tab to the User transmit/receive panel")

type URLValue struct {
	URL *url.URL
}

func (v URLValue) String() string {
	if v.URL != nil {
		return v.URL.String()
	}
	return ""
}

func (v URLValue) Type() string {
	return "URL"
}

func (v URLValue) Set(s string) error {
	if u, err := url.Parse(s); err != nil {
		return err
	} else {
		*v.URL = *u
	}
	return nil
}

func initFlags() {
	pflag.VarP(&URLValue{&httpsUrl}, "https-url", "s",
		`The URL for HTTPS connections.  Most commonly used flag.
Usually this is all you need.
Examples: https://cameron77.ddns5.com:8443  https://foo78.duckdns.org  https://mycloudflaredomain.com
Domain names only, no IP addresses.
Use: *.ddns5.com, for free no-signup dynamic DNS. Quickest way to run your SFU.
Use: *.duckdns.org, for free-signup dynamic DNS. Good alternative to ddns5.com, must set DUCKDNS_TOKEN
Use: *.mycloudflaredomain.com, for Cloudflare DNS. Must set env var: CLOUDFLARE_TOKEN and -cloudflare flag.
See -https-interface for advance binding.
/ path only.`)

	pflag.VarP(&URLValue{&httpUrl}, "http-url", "p",
		`The URL for HTTP connections.
Examples: http://[::]:8080   http://0.0.0.0     # all ipv6 network interfaces, all ipv4 network interfaces
Examples: http://192.168.2.1                    # one interface, port 80
/ path only.
`)

}

func flagParseAndValidate() {

	if *helpAll {
		Usage()
		os.Exit(-1)
	}

	if httpUrl.Scheme == "" && httpsUrl.Scheme == "" {
		Usage()
		os.Exit(-1)
	}

	if httpUrl.Scheme != "" {
		if httpUrl.Scheme != "http" {
			checkFatal(fmt.Errorf("-http-url flag must start with 'http:'"))
		}
		if httpUrl.Path != "" && httpUrl.Path != "/" {
			checkFatal(fmt.Errorf("Root path only on signalling URLs:%s", &httpUrl))
		}
	}

	// if net.ParseIP(httpsUrl.Hostname()) != nil {
	// 	checkFatal(fmt.Errorf("Can ONLY IP addresses for HTTP URLs: %v, please use :: or 0.0.0.0, for all interfaces. ie http://::/", httpsUrl.Hostname()))
	// }

	if len(*httpsInterfaceFlag) > 0 {
		interfaceAddress = net.ParseIP(*httpsInterfaceFlag)
		if interfaceAddress == nil {
			elog.Fatal("Invalid IP address for -https-interface")
		}
	}

	if httpsUrl.Scheme != "" {

		if httpsUrl.Scheme != "https" {
			checkFatal(fmt.Errorf("-https-url flag must start with 'https:'"))
		}
		if httpsUrl.Path != "" && httpsUrl.Path != "/" {
			checkFatal(fmt.Errorf("Root path only on signalling URLs:%s", &httpsUrl))
		}
		if net.ParseIP(httpsUrl.Hostname()) != nil {
			checkFatal(fmt.Errorf("Cannot use IP addresses for HTTPS urls:%v", httpsUrl.Hostname()))
		}
	}
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "At a minimum, -s (-https-url) or -p (-http-url) are required\n\n")

	if *helpAll {
		pflag.PrintDefaults()
	} else {

		fs := pflag.NewFlagSet("foo", pflag.ExitOnError)
		fs.SortFlags = false
		fs.AddFlag(pflag.CommandLine.Lookup("https-url"))
		fs.AddFlag(pflag.CommandLine.Lookup(ddnsPublicFlagName))
		fs.AddFlag(pflag.CommandLine.Lookup(ddnsRegisterName))
		fs.AddFlag(pflag.CommandLine.Lookup("http-url"))
		fs.AddFlag(pflag.CommandLine.ShorthandLookup("a"))
		fs.PrintDefaults()

	}
}
