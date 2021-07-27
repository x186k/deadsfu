package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/spf13/pflag"
)

var ACMEAgreed = pflag.Bool("acme-agree", true, "You AGREE with the CA's terms. ie, LetsEncrypt.")
var ACMEEmailFlag = pflag.String("acme-email", "", "This is the email to provide to the ACME certifcate provider.")

const httpsInterfaceFlagname = "https-interface"

var httpsInterfaceFlag = pflag.String(httpsInterfaceFlagname, "",
	`Specify the interface bind IP address for HTTPS, not for HTTP.
This is an advanced setting.
The default should work for most users. 
A V4 or V6 IP address is okay.
Do not provide port infomation here, use the https url for port information.
Examples: '[::]'  '0.0.0.0' '192.168.2.1'  '10.1.2.3'  '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
Defaults to [::] (all interfaces)`)

var interfaceAddress net.IP

const ddnsPublicFlagName = "ddns-public"

var ddnsPublicFlag = pflag.BoolP(ddnsPublicFlagName, "k", false,
	`Which IP to use for dynamic DNS reg. 'false': use local IP address. 'true': use Public/NATTED IP address.`)

const ddnsRegisterName = "ddns-register"

var ddnsRegisterEnabled = pflag.Bool(ddnsRegisterName, true,
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

var _ = ftlFixOBSConfig
var ftlFixOBSConfig = pflag.Bool("ftl-fix-OBS-config", false,
	`Add a DeadSFU Server entry to OBS. The URL in -ftl-url will be used for new entry.`)

var iceCandidateHost = pflag.String("ice-candidate-host", "", "For forcing the ice host candidate IP address")
var iceCandidateSrflx = pflag.String("ice-candidate-srflx", "", "For forcing the ice srflx candidate IP address")

//var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")

var tlsOldVersions = pflag.Bool("tls-old-versions", false, "Advanced: Enable Cosmo OBS Studio by allowing old TLS versions")
var helpAll = pflag.BoolP("help2", "i", false, "Print the long usage")
var help = pflag.BoolP("help", "h", false, "Print the short usage")
var cloudflareDDNS = pflag.Bool("cloudflare", false, "Use Cloudflare API for DDNS and HTTPS ACME/Let's encrypt")
var stunServer = pflag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")

//var openTab = flag.Bool("opentab", false, "Open a browser tab to the User transmit/receive panel")

var httpUrl = url.URL{}
var httpsUrl = url.URL{}
var ftlUrl = url.URL{}
var rtpUrl = url.URL{}
var _ = rtpUrl

const httpsUrlHelp = `The HTTPS url is for basic input and output signalling. 
Usually this is all you need.
Most commonly used flag. Input is WISH compatible.
Examples: https://cameron77.ddns5.com:8443  https://foo78.duckdns.org  https://mycloudflaredomain.com
Domain names only, no IP addresses.
Use: *.ddns5.com, for free no-signup dynamic DNS. Quickest way to run your SFU.
Use: *.duckdns.org, for free-signup dynamic DNS. Good alternative to ddns5.com, must set DUCKDNS_TOKEN
Use: *.mycloudflaredomain.com, for Cloudflare DNS. Must set env var: CLOUDFLARE_TOKEN and -cloudflare flag.
See -https-interface for advance binding.
/ path only.`

const httpUrlHelp = `The HTTP url is for basic input and output signalling. 
Examples: http://[::]:8080   http://0.0.0.0     # all ipv6 network interfaces, all ipv4 network interfaces
Examples: http://192.168.2.1                    # one interface, port 80
/ path only.`

const ftlUrlHelp = `The FTL url enables FTL ingress, for example from OBS.
Usage of FTL will disable http and https for input, but not output.
For same-system FTL from OBS, please use: 'ftl://localhost:8084'
If hostname is not 'localhost' it will be dynamic DNS registered,
using the ddns5, duckdns, or Cloudflare rules as is for https.`

const rtpUrlHelp = `The RTP url help is coming soon. Please contact me for help.`

// call this after pflag.Parse()
func parseUrlsAndValidate() {

	for _, v := range pflag.Args() {

		u, err := url.Parse(v)
		if err != nil {
			checkFatal(fmt.Errorf("Only urls may be used as non-flag arguments (without - or --)"))
		}

		if u.Path != "" && u.Path != "/" {
			checkFatal(fmt.Errorf("Only root path allowed on signalling URLs: %s", u.String()))
		}

		switch u.Scheme {
		case "http":
			httpUrl = *u
		case "https":
			httpsUrl = *u
		case "ftl":
			ftlUrl = *u
		case "rtp":
			rtpUrl = *u
		}
	}

	if httpUrl.Scheme == "" && httpsUrl.Scheme == "" && *dialIngressURL == "" {
		Usage()
		os.Exit(-1)
	}

	if *iceCandidateHost != "" && *iceCandidateSrflx != "" {
		checkFatal(fmt.Errorf("only one type of ice candidate flag permitted"))
	}

	if *ftlFixOBSConfig {
		panic(99)
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
		if net.ParseIP(httpsUrl.Hostname()) != nil {
			checkFatal(fmt.Errorf("Cannot use IP addresses for HTTPS urls:%v", httpsUrl.Hostname()))
		}
	}
}

func urlHelp(x string) {
	a := strings.Split(x, "\n")

	fmt.Fprintln(os.Stderr, a[0])
	for _, b := range a[1:] {
		fmt.Fprintln(os.Stderr, "     ", b)
	}
	fmt.Fprintln(os.Stderr, "")
}

var Usage = func() {
	myname := path.Base(os.Args[0])
	//usage: cat [-benstuv] [file ...]
	fmt.Fprintf(os.Stderr, "usage: %s [options...] <url...>\n\n", myname)

	fmt.Fprintf(os.Stderr, "An https or http url is required, unless using --dial-ingress.\n")
	fmt.Fprintf(os.Stderr, "ftl, rtp urls are optional.\n\n")

	if *helpAll {

		pflag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "")
		urlHelp(httpsUrlHelp)
		urlHelp(httpUrlHelp)
		urlHelp(ftlUrlHelp)
		urlHelp(rtpUrlHelp)
	} else {
		fmt.Fprintf(os.Stderr, "This is the short usage, please use -i for the long usage.\n\n")

		fs := pflag.NewFlagSet("foo", pflag.ExitOnError)
		fs.SortFlags = false
		// fs.AddFlag(pflag.CommandLine.Lookup(ddnsPublicFlagName))
		// fs.AddFlag(pflag.CommandLine.Lookup(ddnsRegisterName))
		fs.AddFlag(pflag.CommandLine.Lookup("help2"))
		fs.PrintDefaults()

	}
}
