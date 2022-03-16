package sfu

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/spf13/pflag"
	"github.com/x186k/ddns5libdns"
)

var httpFlag = pflag.String("http", "", "The addr:port at which http will bind/listen. addr may be empty, for example ':80' or ':8080' ")
var httpsDomainFlag = pflag.StringP("https-domain", "q", "", "Domain name for https. Can add :port if needed. Uses port 443 when :port not provided")
var httpsDnsProvider = pflag.StringP("https-dns-provider", "r", "", "One of ddns5, duckdns or cloudflare")
var httpsDnsRegisterIp = pflag.BoolP("https-dns-register-ip", "s", false, "DNS-Register the IP of this box, at provider, for name: --https-domain. Uses interface addrs")
var httpsDnsRegisterIpPublic = pflag.BoolP("https-dns-register-ip-public", "t", false, "DNS-Register the IP of this box, at provider, for name: --https-domain. Detects public addrs")
var httpsUseDns01Challenge = pflag.BoolP("https-dns01-challenge", "u", false, "When registering at Let's Encrypt, use the DNS challenge, not HTTP/HTTPS. Recommended behind firewalls")

var dialUpstreamUrlFlag = pflag.StringP("dial-upstream", "d", "", "Specify a URL for upstream SFU. No path, no params. Used for SFU chaining!. Upstream dial triggered on subscriber connection to room.")

var iceCandidateHost = pflag.String("ice-candidate-host", "", "For forcing the ice host candidate IP address")
var iceCandidateSrflx = pflag.String("ice-candidate-srflx", "", "For forcing the ice srflx candidate IP address")

var ftlKey = pflag.String("ftl-key", "", "Set the ftl/obs Settings/Stream/Stream-key. LIKE A PASSWORD! CHANGE THIS FROM DEFAULT! ")
var ftlUdpPort = pflag.Int("ftl-udp-port", 8084, "The UDP port to use for FTL UDP rx. Zero is valid. Zero for ephemeral port num")

//var ffmpeg =pflag.StringToString("ffmpeg","","ffmpeg shortcut to spawn for RTP ingress into room"
//var rtptx = pflag.String("rtp-tx", "", "addr:port to send rtp to. ie: '127.0.0.1:4444'")
//var rtprx = pflag.StringArray("rtp-rx", nil, "use :port or addr:port. eg: '--rtp-rx :5004 --rtp-rx :5006' payload 96 for h264, 97 for opus")
//var rtpWireshark = pflag.Bool("rtp-wireshark", false, "when on 127.0.0.1, also receive my sent packets")
var stunServer = pflag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")
var htmlSource = pflag.String("html", "", "required. 'internal' suggested. HTML source: internal, none, <file-path>, <url>")
var cpuprofile = pflag.Bool("profile", false, "Enable Go runtime profiling. Developer tool. Press enter to start/stop on console")
var pprofFlag = pflag.Bool("pprof", false, "enable pprof based profiling on :6060")

//var idleExitDuration = pflag.Duration("idle-exit-duration", time.Duration(0), `If there is no input video for duration, exit process/container. eg: '1h' one hour, '30m': 30 minutes`)

var idleClipServerURL = pflag.String("idle-clip-server-url", "http://localhost:8088/idle-clip", "what server to hit when using --idle-clip-server-input")
var idleClipServerInput = pflag.String("idle-clip-server-input", "", "a .jpg, .png, .mov, etc to use for your Idle Clip")
var idleClipZipfile = pflag.String("idle-clip-zipfile", "", "provide a zipfile for the Idle Clip")

var getStatsLogging = pflag.String("getstats-url", "", "The url of a server for getStats() logging")

var debugFlag = pflag.StringSlice("debug", nil, "use '--debug help' to see options. use comma to seperate multiple options")

var helpShortFlag = pflag.BoolP("help", "h", false, "Print the short, getting-started help")
var helpFullFlag = pflag.BoolP("help2", "2", false, "Print the full, long help")
var helpHttpsFlag = pflag.BoolP("help3", "3", false, "Print the help on using HTTPS")

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")
// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap

const bearerHelp = `
Bearer Authentication. Like a password. Required on HTTP/S requests.
Provide via URL: https://base.url?access_token=<secret>
Provide via headers: 'Authorization: Bearer <secret>'
`

var bearerToken = pflag.StringP("bearer-token", "b", "", bearerHelp)

func printShortHelp() {
	fmt.Println("Short flags list:")
	fmt.Println()
	x := pflag.NewFlagSet("xxx", pflag.ExitOnError)
	x.AddFlag(pflag.CommandLine.Lookup("http"))
	x.AddFlag(pflag.CommandLine.Lookup("html"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("h"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("2"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("3"))
	x.SortFlags = false
	x.PrintDefaults()
	fmt.Println(`

Suggested new-user command: './deadsfu --http :8080 --html internal'
(Next, open browser to http://localhost:8080/)

Minimum required flags: --html is required, and either --http or --https-domain is required.`)
	fmt.Println()
}

func printHttpsHelp() {
	fmt.Println("Https flags list:")
	fmt.Println()

	x := pflag.NewFlagSet("xxx", pflag.ExitOnError)
	x.AddFlag(pflag.CommandLine.ShorthandLookup("q"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("r"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("s"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("t"))
	x.AddFlag(pflag.CommandLine.ShorthandLookup("u"))

	x.SortFlags = false
	x.PrintDefaults()
	fmt.Println(`
    https related flags help:
    
    -q or --https-domain <domain>
        Use this option the domain name, and optional port for https. 
        Defaults to port 443 for the port. Use domain:port if you need something else.
        Port zero is valid, for auto-assign.
        With this flag,  a certificate will be aquired from Let's Encrypt.
        BY USING THIS FLAG, you consent to agreeing to the Let's Encrypt's terms.
    
    -r or --https-dns-provider <provider>
        You can use: ddns5, duckdns, cloudflare
        This flag is required when using --https-domain, as a DNS TXT record must be set for Let's Encrypt
        ddns5: does not require a token! Domain must be: <name>.ddns5.com
        duckdns: uses the environment variable DUCKDNS_TOKEN for the API token. Domain must be: <name>.duckdns.org
        cloudflare: uses the environment variable CLOUDFLARE_TOKEN for the API token
    
    -s or --https-dns-register-ip
        Register the IP addresses of this system at the DNS provider.
        Looks at interfaces addresses. Sets DNS A/AAAA.
    
    -t or --https-dns-register-ip-public
        Register the IP addresses of this system at the DNS provider.
        Queries Internet for my public address. Sets DNS A/AAAA.
        Mutually exclusive with -3.
    
    -u or --https-acme-challenge-dns01
        Switch from the default ACME challenge of HTTP/HTTPS to DNS.
        Use this when Let's Encrypt can't reach your system behind a firewall.
        Great for corporate private-IP video transfer. ie: 192.168.* or 10.*
    
    Examples:
    $ ./deadsfu -1 foof.duckdns.org -2 duckdns
    $ DUCKDNS_TOKEN=xxxx ./deadsfu -1 cameron4321.ddns5.com -2 ddns5
    $ CLOUDFLARE_TOKEN=xxxx ./deadsfu -1 my.example.com -2 cloudflare`)
	fmt.Println()
}

var dbg = struct {
	Url                 FastLogger
	Media               FastLogger
	Https               FastLogger
	Ice                 FastLogger
	Main                FastLogger
	Ftl                 FastLogger
	Ddns                FastLogger
	PeerConn            FastLogger
	Switching           FastLogger
	Goroutine           FastLogger
	ReceiverLostPackets FastLogger
	Roomcleaner         FastLogger
	Numgoroutine        FastLogger
}{
	Url:                 FastLogger{},
	Media:               FastLogger{},
	Https:               FastLogger{},
	Ice:                 FastLogger{},
	Main:                FastLogger{},
	Ftl:                 FastLogger{},
	Ddns:                FastLogger{},
	PeerConn:            FastLogger{},
	Switching:           FastLogger{},
	Goroutine:           FastLogger{},
	ReceiverLostPackets: FastLogger{},
	Roomcleaner:         FastLogger{},
	Numgoroutine:        FastLogger{help: "periodically print goroutine count"},
}

func getDbgMap() map[string]reflect.Value {

	loggers := make(map[string]reflect.Value)
	v := reflect.ValueOf(&dbg)
	typeOfS := v.Elem().Type()
	for i := 0; i < v.Elem().NumField(); i++ {
		name := typeOfS.Field(i).Name
		//pl(name,v.Elem().Field(i).CanSet())

		loggers[name] = v.Elem().Field(i)
	}
	return loggers
}

func processDebugFlag() {

	for _, v := range *debugFlag {
		if v == "help" {
			printDebugFlagHelp()
			os.Exit(0)
		}
	}

	flags := make(map[string]struct{})

	for _, name := range *debugFlag {
		flags[name] = struct{}{}
	}

	loggers := getDbgMap()

	for name := range flags {
		if _, ok := loggers[name]; !ok {
			checkFatal(fmt.Errorf("'%s' is not a valid debug option", name))
		}
	}

	for name, l := range loggers {
		a := FastLogger{
			Logger:  log.New(io.Discard, name, 0),
			enabled: false,
		}
		l.Set(reflect.ValueOf(a))
	}

	for name := range flags {
		if l, ok := loggers[name]; ok {
			a := FastLogger{
				Logger:  log.New(os.Stdout, name, logFlags),
				enabled: true,
			}
			l.Set(reflect.ValueOf(a))
		}
	}

}

func printDebugFlagHelp() {
	fmt.Println()
	fmt.Println("debug options may be comma seperated.")
	fmt.Println("debug options available:")
	for k, v := range getDbgMap() {
		fastlogger := v.Interface().(FastLogger)
		fmt.Println("--debug", fmt.Sprintf("%-25s", k), "#", fastlogger.help)
	}
	fmt.Println()
	fmt.Println(`Examples:
$ ./deadsfu --debug help                    # show this help
$ ./deadsfu --debug Url,Media               # print url and media info
$ ./deadsfu --debug Ice                     # print debug log on ice-candidates`)
}

func parseFlags() {

	pflag.Usage = printShortHelp

	pflag.Parse()
	if *helpShortFlag {
		printShortHelp()
		os.Exit(0)
	} else if *helpHttpsFlag {
		printHttpsHelp()
		os.Exit(0)
	} else if *helpFullFlag {
		fmt.Println("Full flags list:")
		fmt.Println()
		pflag.CommandLine.SortFlags = false
		pflag.PrintDefaults()
		os.Exit(0)
	}

	processDebugFlag()

}
func oneTimeFlagsActions() {

	if *pprofFlag {
		go func() {
			log.Fatal(http.ListenAndServe(":6060", nil))
		}()
	}

	if *httpsDomainFlag != "" {

		_, _, err := net.SplitHostPort(*httpsDomainFlag)
		if err != nil && strings.Contains(err.Error(), "missing port") {
			foo := *httpsDomainFlag + ":443"
			*httpsDomainFlag = foo
		}
		host, _, err := net.SplitHostPort(*httpsDomainFlag)
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
