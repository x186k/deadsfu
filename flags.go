package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/spf13/pflag"
	"github.com/x186k/ddns5libdns"
)

type SfuConfig struct {
	Http        string
	HttpsDomain string
}

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")
// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap

var ftlKey = pflag.String("ftl-key", "", "Set the ftl/obs Settings/Stream/Stream-key. LIKE A PASSWORD! CHANGE THIS FROM DEFAULT! ")
var ftlUdpPort = pflag.Int("ftl-udp-port", 8084, "The UDP port to use for FTL UDP rx. Zero is valid. Zero for ephemeral port num")
var clusterMode = pflag.Bool("cluster-mode", false, "non-standalone DeadSFU mode. Requires REDIS. See docs.")

var dialIngressURL = pflag.StringP("dial-ingress", "d", "", "Specify a URL for outbound dial for ingress. Used for SFU chaining!")

var httpsDnsProvider = pflag.StringP("https-dns-provider", "2", "", "One of ddns5, duckdns or cloudflare")
var httpsDnsRegisterIp = pflag.BoolP("https-dns-register-ip", "3", false, "DNS-Register the IP of this box, at provider, for name: --https-domain. Uses interface addrs")
var httpsDnsRegisterIpPublic = pflag.BoolP("https-dns-register-ip-public", "4", false, "DNS-Register the IP of this box, at provider, for name: --https-domain. Detects public addrs")
var httpsUseDns01Challenge = pflag.BoolP("https-dns01-challenge", "5", false, "When registering at Let's Encrypt, use the DNS challenge, not HTTP/HTTPS. Recommended behind firewalls")

var iceCandidateHost = pflag.String("ice-candidate-host", "", "For forcing the ice host candidate IP address")
var iceCandidateSrflx = pflag.String("ice-candidate-srflx", "", "For forcing the ice srflx candidate IP address")

var rtptx = pflag.String("rtp-tx", "", "addr:port to send rtp to. ie: '127.0.0.1:4444'")
var rtprx = pflag.String("rtp-rx", "", "addr:port to receive rtp on. ie: ':5004'. payload96=h264 vid, 97=opus aud")
var rtpWireshark = pflag.Bool("rtp-wireshark", false, "when on 127.0.0.1, also receive my sent packets")
var stunServer = pflag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")
var htmlSource = pflag.String("html", "", "required. 'internal' suggested. HTML source: internal, none, <file-path>, <url>")
var cpuprofile = pflag.Int("cpu-profile", 0, "number of seconds to run + turn on profiling")
var pprofFlag = pflag.Bool("pprof", false, "enable pprof based profiling on :6060")
var debug = pflag.StringSlice("debug", []string{}, "comma separated list of debug flags. use 'help' for details")
var idleExitDuration = pflag.Duration("idle-exit-duration", time.Duration(0), `If there is no input video for duration, exit process/container. eg: '1h' one hour, '30m': 30 minutes`)

var help = pflag.BoolP("help", "h", false, "Print the short help")
var fullhelp = pflag.BoolP("fullhelp", "9", false, "Print the long help")

var idleClipServerURL = pflag.String("idle-clip-server-url", "http://localhost:8088/idle-clip", "what server to hit when using --idle-clip-server-input")
var idleClipServerInput = pflag.String("idle-clip-server-input", "", "a .jpg, .png, .mov, etc to use for your Idle Clip")
var idleClipZipfile = pflag.String("idle-clip-zipfile", "", "provide a zipfile for the Idle Clip")

//

var Usage = func() {
	x := pflag.NewFlagSet("xxx", pflag.ExitOnError)
	x.AddFlag(pflag.CommandLine.Lookup("http"))
	x.AddFlag(pflag.CommandLine.Lookup("html"))
	x.AddFlag(pflag.CommandLine.Lookup("fullhelp"))
	x.SortFlags = false
	x.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nOne of --http or --https-domain is required.\n")
	fmt.Fprint(os.Stderr, "Using '--http :8080 --html internal' is the suggested starting place.\n\n")
}

func parseFlags() SfuConfig {

	var conf SfuConfig

	pflag.StringVar(&conf.Http, "http", "", "The addr:port at which http will bind/listen. addr may be empty. like ':80' or ':8080' ")
	pflag.StringVarP(&conf.HttpsDomain, "https-domain", "1", "", "Domain name for https. Use 'help' for more examples. Can add :port if needed")

	pflag.Usage = Usage // my own usage handle

	pflag.Parse()
	if *help {
		Usage()
		os.Exit(0)
	} else if *fullhelp {
		pflag.CommandLine.SortFlags = false
		pflag.PrintDefaults()
		os.Exit(0)
	}

	log.Default().SetOutput(io.Discard)

	return conf
}
func oneTimeFlagsActions(conf *SfuConfig) {

	if *pprofFlag {
		go func() {
			elog.Fatal(http.ListenAndServe(":6060", nil))
		}()
	}

	for _, v := range *debug {
		switch v {
		case "":
			// do nothing
		case "media":
			mediaDebugTickerChan = time.NewTicker(4 * time.Second).C
			mediaDebug = true
			medialog = log.New(os.Stdout, "M ", log.Lmicroseconds|log.LUTC)
		case "main":
			log.SetFlags(log.Lmicroseconds | log.LUTC)
			log.SetPrefix("D ")
			log.SetOutput(os.Stdout)
		case "ddns":
			ddnslog = log.New(os.Stdout, "X ", log.Lmicroseconds|log.LUTC)
		case "help":
			fallthrough
		default:
			elog.Fatal("--z-debug sub-flags are: main, help, media")
		}
	}

	if *rtptx != "" {
		raddr, err := net.ResolveUDPAddr("udp", *rtptx)
		checkFatal(err)
		var laddr *net.UDPAddr = nil
		if raddr.IP.IsLoopback() && *rtpWireshark {
			//when sending packets to loopback, if there is no receiver
			// we would get icmp dest unreachables
			// so we open it to/from ourself, we won't  read the pkts, but
			// the OS will throw them away when they overflow
			// without this, and the ICMP errors, we lose packets
			// this allows us to use wireshark on 127.0.0.1 without issues
			//note, if I want to use gstreamer or ffprobe, etc, this must not be done

			laddr = raddr

		}
		rtpoutConn, err = net.DialUDP("udp", laddr, raddr)
		checkFatal(err)
	}

	if conf.HttpsDomain != "" {
		if conf.HttpsDomain == "help" {
			println(httpsHelp)
			os.Exit(0)
		}

		_, _, err := net.SplitHostPort(conf.HttpsDomain)
		if err != nil && strings.Contains(err.Error(), "missing port") {
			foo := conf.HttpsDomain + ":443"
			conf.HttpsDomain = foo
		}
		host, _, err := net.SplitHostPort(conf.HttpsDomain)
		checkFatal(err)

		var provider DDNSUnion
		switch *httpsDnsProvider {
		case "":
		default:
			checkFatal(fmt.Errorf("Invalid DNS provider name, see help"))
		case "ddns5":
			provider = &ddns5libdns.Provider{}
		case "duckdns":
			token := os.Getenv("DUCKDNS_TOKEN")
			if token == "" {
				checkFatal(fmt.Errorf("env var DUCKDNS_TOKEN is not set"))
			}
			provider = &duckdns.Provider{APIToken: token}
		case "cloudflare":
			token := os.Getenv("CLOUDFLARE_TOKEN")
			if token == "" {
				checkFatal(fmt.Errorf("env var CLOUDFLARE_TOKEN is not set"))
			}
			provider = &cloudflare.Provider{APIToken: token}
		}

		if *httpsDnsRegisterIp {
			addrs, err := getDefaultRouteInterfaceAddresses()
			checkFatal(err)
			ddnsRegisterIPAddresses(provider, host, 2, addrs)
		}

		if *httpsDnsRegisterIpPublic {
			myipv4, err := getMyPublicIpV4()
			checkFatal(err)
			ddnsRegisterIPAddresses(provider, host, 2, []net.IP{myipv4})
		}

		if *httpsUseDns01Challenge {
			certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
				//DNSProvider:        provider.(certmagic.ACMEDNSProvider),
				DNSProvider:        provider,
				TTL:                0,
				PropagationTimeout: 0,
				Resolvers:          []string{},
			}
		}

	}

}

const httpsHelp = `
https related flags help:

-1 or --https-domain <domain>
	Use this option the domain name, and optional port for https. 
	Defaults to port 443 for the port. Use domain:port if you need something else.
	Port zero is valid, for auto-assign.
	With this flag,  a certificate will be aquired from Let's Encrypt.
	BY USING THIS FLAG, you consent to agreeing to the Let's Encrypt's terms.

-2 or --https-dns-provider <provider>
	You can use: ddns5, duckdns, cloudflare
	This flag is required when using --https-domain, as a DNS TXT record must be set for Let's Encrypt
	ddns5: does not require a token! Domain must be: <name>.ddns5.com
	duckdns: uses the environment variable DUCKDNS_TOKEN for the API token. Domain must be: <name>.duckdns.org
	cloudflare: uses the environment variable CLOUDFLARE_TOKEN for the API token

-3 or --https-dns-register-ip
	Register the IP addresses of this system at the DNS provider.
	Looks at interfaces addresses. Sets DNS A/AAAA.

-4 or --https-dns-register-ip-public
	Register the IP addresses of this system at the DNS provider.
	Queries Internet for my public address. Sets DNS A/AAAA.
	Mutually exclusive with -3.

-5 or --https-acme-challenge-dns01
	Switch from the default ACME challenge of HTTP/HTTPS to DNS.
	Use this when Let's Encrypt can't reach your system behind a firewall.
	Great for corporate private-IP video transfer. ie: 192.168.* or 10.*

Examples:
$ ./deadsfu -1 foof.duckdns.org -2 duckdns
$ DUCKDNS_TOKEN=xxxx ./deadsfu -1 cameron4321.ddns5.com -2 ddns5
$ CLOUDFLARE_TOKEN=xxxx ./deadsfu -1 my.example.com -2 cloudflare



`
