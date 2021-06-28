package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pkg/profile"
	//"github.com/x186k/dynamicdns"

	"golang.org/x/sync/semaphore"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"

	_ "embed"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"

	"github.com/x186k/ddns5libdns"
	"github.com/x186k/sfu1/rtpstuff"
)

//go:embed html/*
var htmlContent embed.FS

//go:embed sfu1-binaries/idle.screen.h264.pcapng
var idleScreenH264Pcapng []byte

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:" + *stunServer},
		},
	},
}

var myMetrics struct {
	dialConnectionRefused uint64
}

// nolint:gochecknoglobals
var rtpPacketPool = sync.Pool{
	New: func() interface{} {
		return &rtp.Packet{}
	},
}

// https://tools.ietf.org/id/draft-ietf-mmusic-msid-05.html
// msid:streamid trackid/appdata
// per RFC appdata is "application-specific data", we use a/b/c for simulcast
const (
	mediaStreamId = "x186k"
	ddns5Suffix   = ".ddns5.com"
	duckdnsSuffix = ".duckdns.org"
	videoMimeType = "video/h264"
	audioMimeType = "audio/opus"
	pubPath       = "/pub"
	subPath       = "/sub" // 2nd slash important
)

var (
	ingressSemaphore = semaphore.NewWeighted(int64(1)) // concurrent okay
	txidMap          = make(map[uint64]struct{})       // no concurrent
	txidMapMutex     sync.Mutex
)

var ticker = time.NewTicker(100 * time.Millisecond)

var httpsUsingDDNS = false
var httpsHasCertificate = false

type Subid uint64

type MsgRxPacket struct {
	rxidstate   *RxidState
	rxClockRate uint32
	packet      *rtp.Packet
}

type MsgSubscriberAddTrack struct {
	txtrack *Track
}

type MsgSubscriberSwitchTrack struct {
	subid Subid   // 64bit subscriber key
	txid  TrackId // track number from subscriber's perspective
	rxid  TrackId // where txid will get it's input from
}

var rxMediaCh chan MsgRxPacket = make(chan MsgRxPacket, 10)
var subAddTrackCh chan MsgSubscriberAddTrack = make(chan MsgSubscriberAddTrack, 10)
var subSwitchTrackCh chan MsgSubscriberSwitchTrack = make(chan MsgSubscriberSwitchTrack, 10)

// size optimized, not readability
type RtpSplicer struct {
	lastUnixnanosNow int64
	lastSSRC         uint32
	lastTS           uint32
	tsOffset         uint32
	lastSN           uint16
	snOffset         uint16
}

// size optimized, not readability
type Track struct {
	track    *webrtc.TrackLocalStaticRTP
	splicer  *RtpSplicer
	subid    Subid   // 64bit subscriber key
	txid     TrackId // track number from subscriber's perspective
	rxid     TrackId
	pending  TrackId
	rxidsave TrackId
}

// subid to txid to txtrack index
var sub2txid2track map[Subid]map[TrackId]*Track = make(map[Subid]map[TrackId]*Track)

type TrackId int

const (
	XInvalid   TrackId = Spacing * 0
	XVideo     TrackId = Spacing * 1
	XAudio     TrackId = Spacing * 2
	XData      TrackId = Spacing * 3
	XIdleVideo TrackId = Spacing * 4
)

var rxid2state map[TrackId]*RxidState = make(map[TrackId]*RxidState)

type RxidState struct {
	lastReceipt time.Time //unixnanos
	rxid        TrackId
	active      bool
}

var txtracks []*Track

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func redirectHttpToHttpsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http vs https https://github.com/golang/go/issues/28940
		isHttp := r.TLS == nil
		//isIPAddr := net.ParseIP(r.Host) != nil
		// reqhost, _, _ := net.SplitHostPort(r.Host)
		// if reqhost == "" {
		// 	reqhost = r.Host
		// }

		// port := 0
		// a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		// if ok {
		// 	ta, ok := a.(*net.TCPAddr)
		// 	if !ok {
		// 		panic("not tcp")
		// 	}
		// 	port = ta.Port
		// }

		// if this is a port 80 http request, can we find an https endpoint to redirect it to?
		if httpsUrl != nil && isHttp {
			//if  httpsUrl.Hostname() == reqhost {
			uri := "https://" + httpsUrl.Host + r.RequestURI
			log.Println("Redirecting HTTP req to ", uri)
			http.Redirect(w, r, uri, http.StatusMovedPermanently)
			return
		}

		//w.Header().Set("Foo", "Bar")
		h.ServeHTTP(w, r)
	})
}

type TrackCounts struct {
	numVideo, numAudio, numIdleVideo, numIdleAudio int
}

var trackCounts = TrackCounts{
	numVideo:     *flag.Int("num-video", 10, "number of video tracks"),
	numAudio:     *flag.Int("num-audio", 1, "number of audio tracks"),
	numIdleVideo: 1,
	numIdleAudio: 0,
}

var Version = "version-unset"

// var urlsFlag urlset
// const urlsFlagName = "urls"
// const urlsFlagUsage = "One or more urls for HTTP, HTTPS. Use commas to seperate."

// Docker,systemd have Stdin from null, so there is no explicit prompt for ACME terms.
// Just like Caddy under Docker and Caddy under Systemd
var ACMEAgreed = flag.Bool("acme-agree", true, "Default: true. You AGREE with the CA's terms. ie, LetsEncrypt,\nwhen you are using this software with a CA, like LetsEncrypt.")
var ACMEEmailFlag = flag.String("acme-email", "", "This is the email to provide to the ACME certifcate provider.")

var httpUrlFlag = flag.String("http-url", "",
	`The URL for HTTP connections.
Examples: http://[::]:8080   http://0.0.0.0     # wildcard ipv6 and then wildcard ipv4
Examples: http://192.168.2.1                    # one interface, port 80
/ path only.
`)
var httpsUrlFlag = flag.String("https-url", "",
	`The URL for HTTPS connections.  Most commonly used flag.
Usually this is all you need.
Examples: https://cameron77.ddns5.com:8443  https://foo78.duckdns.org  https://mycloudflaredomain.com
Domain names only, no IP addresses.
Use: *.ddns5.com, for free no-signup dynamic DNS. Quickest way to run your SFU.
Use: *.duckdns.org, for free-signup dynamic DNS. Good alternative to ddns5.com, must set DUCKDNS_TOKEN
Use: *.mycloudflaredomain.com, for Cloudflare DNS. Must set env var: CLOUDFLARE_TOKEN.
See -https-interface for advance binding.
/ path only.`)
var httpUrl, httpsUrl *url.URL

var httpsInterfaceFlag = flag.String("https-interface", "",
	`Specify the interface bind IP address for HTTPS, not for HTTP.
This is an advanced setting.
The default should work for most users. 
A V4 or V6 IP address is okay.
Do not provide port infomation here, use -https-url for port information.
Examples: '[::]'  '0.0.0.0' '192.168.2.1'  '10.1.2.3'  '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
Defaults to [::] (all interfaces)`)
var interfaceAddress net.IP

//var httpsCaddyFlag = flag.Bool("https-caddy", true, "Aquire HTTPS certificates auto-magically using Caddy and Letsencrypt")
// NO/reduce complexity.
//var httpsDDNSFlag = flag.Bool("https-ddns", true, "Register HTTPS IP addresses using DDNS")
var httpsAutoFlag = flag.String("https-auto", "local",
	`One of: 'local', 'public', or 'none'.   The default is 'local'.
This controls which IP addresses will be auto-detected for HTTPS usage.
local: Detect my local on-system IP addresses.
public: Detect my public (natted or local) Internet IP addresses (TCP to Internet)
none: Do not detect IP addresses`)

// reduce complexity, removed
//var httpsOpenPortsFlag = flag.Bool("https-open-ports", true, "Use Stun5 Proxy server to show if my HTTPS ports are open.\nOnly when -https-auto=public")

//var silenceJanus = flag.Bool("silence-janus", false, "if true will throw away janus output")
var htmlFromDiskFlag = flag.Bool("z-html-from-disk", false, "do not use embed html, use files from disk")
var ddnsutilDebug = flag.Bool("z-ddns-debug", false, "enable ddns debug output")
var cpuprofile = flag.Int("z-cpu-profile", 0, "number of seconds to run + turn on profiling")
var debug = flag.Bool("z-debug", false, "enable debug output")
var debugCertmagic = flag.Bool("z-debug-certmagic", false, "enable debug output for certmagic and letsencrypt")
var debugStagingCertificate = flag.Bool("z-debug-staging", false, "use the LetsEncrypt staging certificate")

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")

// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
var disableHtml = flag.Bool("disable-html", false, "do not serve any html files, only allow pub/sub API")
var dialIngressURL = flag.String("dial-ingress", "", "Specify a URL for outbound dial for ingress")

//var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")

var obsStudio = flag.Bool("obs-studio", false, "Enable OBS Studio by tweaking SSL/TLS version numbers")
var helpAll = flag.Bool("all", false, "Show the full set of advanced flags")
var cloudflareDDNS = flag.Bool("cloudflare", false, "Use Cloudflare API for DDNS and HTTPS ACME/Let's encrypt")
var stunServer = flag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")

//var openTab = flag.Bool("opentab", false, "Open a browser tab to the User transmit/receive panel")

// var logPacketIn = log.New(os.Stdout, "I ", log.Lmicroseconds|log.LUTC)
// var logPacketOut = log.New(os.Stdout, "O ", log.Lmicroseconds|log.LUTC)

// This should allow us to use checkFatal() more, and checkPanic() less
var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)
var ddnslog = log.New(os.Stderr, "X ", log.Lmicroseconds|log.LUTC)

func logGoroutineCountToDebugLog() {
	n := runtime.NumGoroutine()
	for {
		time.Sleep(2 * time.Second)
		nn := runtime.NumGoroutine()
		if nn != n {
			log.Println("NumGoroutine", nn)
			n = nn
		}
	}
}

// should this be 'init' or 'initXXX'
// if we want this func to be called everyttime we run tests, then
// it should be init(), otherwise initXXX()
// I suppose testing in this package/dir should be related to the
// running SFU engine, so we use 'init()'
// But! this means we need to determine if we are a test or not,
// so we can not call flag.Parse() or not
func init() {

	// dir, err := content.ReadDir(".")
	// checkPanic(err)
	// for k, v := range dir {
	// 	println(88, k, v.Name())
	// }
	// panic(99)

	if _, err := htmlContent.ReadFile("html/index.html"); err != nil {
		panic("index.html failed to embed correctly")
	}

	if strings.HasPrefix(string(idleScreenH264Pcapng[0:10]), "version ") {
		panic("You have NOT built the binaries correctly. You must use \"git lfs\" to fill in files under /lfs")
	}

	istest := strings.HasSuffix(os.Args[0], ".test")
	if !istest {
		flag.Usage = Usage // my own usage handle
		flag.Parse()
		flagParseAndValidate()

		if *debug {
			log.SetFlags(log.Lmicroseconds | log.LUTC)
			log.SetPrefix("D ")
			log.SetOutput(os.Stdout)
			log.Printf("debug output IS enabled Version=%s", Version)
		} else {
			//elog.Println("debug output NOT enabled")
			silenceLogger(log.Default())
		}
	}
	if !*ddnsutilDebug {
		silenceLogger(ddnslog)
	}

	initMediaHandlerState(trackCounts)

	go logGoroutineCountToDebugLog()

	log.Printf("idleScreenH264Pcapng len=%d md5=%x", len(idleScreenH264Pcapng), md5.Sum(idleScreenH264Pcapng))
	p, _, err := rtpstuff.ReadPcap2RTP(bytes.NewReader(idleScreenH264Pcapng))
	checkPanic(err)

	go idleLoopPlayer(p)

	go msgLoop()
}

func flagParseAndValidate() {
	var err error

	if len(*httpUrlFlag) == 0 && len(*httpsUrlFlag) == 0 && !*helpAll {
		checkFatal(fmt.Errorf("One of -http-url or -https-url or -all must be given."))
	}

	if len(*httpUrlFlag) > 0 {
		httpUrl, err = url.Parse(*httpUrlFlag)
		checkFatal(err)
		if httpUrl.Scheme != "http" {
			checkFatal(fmt.Errorf("-http-url flag must start with 'http:'"))
		}

		if httpUrl.Path != "" && httpUrl.Path != "/" {
			checkFatal(fmt.Errorf("Root path only on signalling URLs:%s", httpUrl))
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

	if len(*httpsUrlFlag) > 0 {
		httpsUrl, err = url.Parse(*httpsUrlFlag)
		checkFatal(err)
		if httpsUrl.Scheme != "https" {
			checkFatal(fmt.Errorf("-https-url flag must start with 'https:'"))
		}
		if httpsUrl.Path != "" && httpsUrl.Path != "/" {
			checkFatal(fmt.Errorf("Root path only on signalling URLs:%s", httpsUrl))
		}
		if net.ParseIP(httpsUrl.Hostname()) != nil {
			checkFatal(fmt.Errorf("Cannot use IP addresses for HTTPS urls:%v", httpsUrl.Hostname()))
		}
	}

	if *httpsAutoFlag != "local" && *httpsAutoFlag != "public" && *httpsAutoFlag != "none" {
		elog.Fatal("Invalid value for -https-auto flag")
	}

}

func silenceLogger(l *log.Logger) {
	l.SetOutput(ioutil.Discard)
	l.SetPrefix("")
	l.SetFlags(0)
}

func main() {
	var err error

	if false {
		go func() {
			tk := time.NewTicker(time.Second * 2)
			for range tk.C {
				for i, v := range txtracks {
					//RACEY
					println("track", i, v.pending, v.rxid)
				}
			}
		}()
	}

	if *helpAll {
		flag.Usage()
		os.Exit(0)
	}

	log.Println("NumGoroutine", runtime.NumGoroutine())

	// BEYOND HERE is needed for real operation
	// but is not needed for unit testing

	// MUX setup
	mux := http.NewServeMux()

	if !*disableHtml {

		var f fs.FS

		if *htmlFromDiskFlag {
			f = os.DirFS("html")
		} else {
			f, err = fs.Sub(htmlContent, "html")
			checkPanic(err)
		}

		mux.Handle("/", redirectHttpToHttpsHandler(http.FileServer(http.FS(f))))

	}
	mux.HandleFunc(subPath, SubHandler)
	if *dialIngressURL == "" {
		mux.HandleFunc(pubPath, pubHandler)
	}

	//https first
	if httpsUrl != nil {
		go reportHttpsReadyness()

		ddnsProvider := ddnsDetermineProvider(httpsUrl)

		switch *httpsAutoFlag {
		case "local":
			addrs, err := getLocalIPAddresses()
			checkFatal(err)
			httpsUsingDDNS = true
			ddnsRegisterIPAddresses(ddnsProvider, httpsUrl.Hostname(), 2, addrs)
			ddnsEnableDNS01Challenge(ddnsProvider)

		case "public":
			if *httpsInterfaceFlag != "" {
				checkFatal(fmt.Errorf("Cannot combine -https-auto=public -https-interface."))
			}
			myipv4 := getMyPublicIpV4()
			if myipv4 == nil {
				checkFatal(fmt.Errorf("Unable to detect my PUBLIC IPv4 address."))
			}
			ddnsRegisterIPAddresses(ddnsProvider, httpsUrl.Hostname(), 2, []net.IP{myipv4})

			// NO LONGER DO ANY PORT OPENNESS CHECKING
			// NOR CHECK WHETHER
			// if the ACME port 80 and port 443 challenges can't possibly work
			//httpsOn443 := httpsUrl.Port() == "" || httpsUrl.Port() == "443"
			//httpOn80 := httpUrl != nil && (httpUrl.Port() == "" || httpUrl.Port() == "80")

			// DO NOT CHECK if http is running on 80, as certmagic will run its own
			// WE USED TO CHECK IF WE ARE RUNNING HTTP on 80, thinking this is necessary for certmagic.
			// IT IS NOT, certmagic run's it's own http on 80, if we do not
			// if  !httpsOn443 {
			// if !httpOn80 && !httpsOn443 {
			// 	// the TCP/HTTPx challenges won't work
			// 	elog.Printf("Using ACME DNS01 for LetsEncrypt: Port 443, and Port 80 is not in use.")
			// 	x := getMyPublicIpV4()
			// 	if x == nil {
			// 		checkFatal(fmt.Errorf("Unable to detect my PUBLIC IPv4 address."))
			// 	}
			// 	httpsUsingDDNS = true
			// 	registerDDNS(httpsUrl, []net.IP{x})
			// }

		case "none":
			elog.Printf("Registering NO DNS hosts.")
		default:
			checkFatal(fmt.Errorf("Invalid value for -https-auto: %s", *httpsAutoFlag))
		}

		var tlsConfig *tls.Config = nil

		ca := certmagic.LetsEncryptProductionCA
		if *debugStagingCertificate {
			ca = certmagic.LetsEncryptStagingCA
		}

		mgrTemplate := certmagic.ACMEManager{
			CA:                      ca,
			Email:                   *ACMEEmailFlag,
			Agreed:                  *ACMEAgreed,
			DisableHTTPChallenge:    false,
			DisableTLSALPNChallenge: false,
		}
		magic := certmagic.NewDefault()
		magic.OnEvent = func(s string, i interface{}) {
			switch s {
			// called at time of challenge passing
			case "cert_obtained":
				// elog.Println("Let's Encrypt Certificate Aquired")
				// called every run where cert is found in cache including when the challenge passes
				// since the followed gets called for both obained and found in cache, we use that
			case "cached_managed_cert":
				httpsHasCertificate = true
				elog.Println("sfu1 HTTPS READY: TLS Certificate Acquired")
			case "tls_handshake_started":
				//silent
			case "tls_handshake_completed":
				//silent
			default:
				elog.Println("certmagic event:", s) //, i)
			}
		}

		if *debug || *debugCertmagic {

			zaplog, err := zap.NewProduction()
			checkFatal(err)
			mgrTemplate.Logger = zaplog
		}
		// use certmsgic for manual certificates, as it
		// will manage oscp stapling
		// CacheUnmanagedCertificatePEMBytes()
		// CacheUnmanagedCertificatePEMFile()
		// CacheUnmanagedTLSCertificate()
		myACME := certmagic.NewACMEManager(magic, mgrTemplate)
		magic.Issuers = []certmagic.Issuer{myACME}

		// this call is why we don't use higher level certmagic functions
		// so agreement isn't always so verbose
		err = magic.ManageAsync(context.Background(), []string{httpsUrl.Host})
		checkFatal(err)
		tlsConfig = magic.TLSConfig()

		if *obsStudio { /// XXX to work with OBS studio for now
			tlsConfig.MinVersion = 0
		}

		laddr := *httpsInterfaceFlag + ":" + getPort(httpsUrl)
		go func() {
			httpsLn, err := tls.Listen("tcp", laddr, tlsConfig)
			checkPanic(err)
			panic(http.Serve(httpsLn, mux))
		}()
		//elog.Printf("%v IS READY", httpsUrl.String())

	}

	//http next
	if httpUrl != nil {

		go func() {
			// httpLn, err := net.Listen("tcp", laddr)
			err := http.ListenAndServe(httpUrl.Host, certmagic.DefaultACME.HTTPChallengeHandler(mux))
			panic(err)
		}()
		elog.Printf("%v IS READY", httpUrl.String())
	}

	//the user can specify zero for port, and Linux/etc will choose a port

	if *dialIngressURL != "" {
		elog.Printf("Publisher Ingress API URL: none (using dial)")
		go func() {
			for {
				err = ingressSemaphore.Acquire(context.Background(), 1)
				checkPanic(err)
				log.Println("dial: got sema, dialing upstream")
				dialUpstream(*dialIngressURL)
			}
		}()
	}

	// block here
	if *cpuprofile == 0 {
		select {}
	}

	println("profiling enabled, runtime seconds:", *cpuprofile)

	defer profile.Start(profile.CPUProfile).Stop()

	time.Sleep(time.Duration(*cpuprofile) * time.Second)

	println("profiling done, exit")
}

func getLocalIPAddresses() ([]net.IP, error) {
	if len(*httpsInterfaceFlag) > 0 {
		addr := net.ParseIP(*httpsInterfaceFlag)
		if addr == nil {
			elog.Fatal("-http-interface is not valid a IP address")
		}
		return []net.IP{addr}, nil
	}
	z := getDefaultRouteInterfaceAddresses()
	if z == nil {
		return nil, errors.New("Cannot auto-detect any IP addresses on this system")
	}
	return z, nil
}

func routableMessage(ip net.IP) string {
	if ip.To4() == nil {
		return "an IPv6 address"
	} else {
		if IsPrivate(ip) {
			return "an RFC1918 PRIVATE, NOT-ROUTABLE address"
		} else {
			return "a NON-RFC1918 PUBLIC, ROUTABLE address"
		}
	}
}

type DDNSUnion interface {
	libdns.RecordAppender
	libdns.RecordDeleter
	libdns.RecordSetter
}

func ddnsDetermineProvider(u *url.URL) DDNSUnion {

	if strings.HasSuffix(u.Hostname(), ddns5Suffix) {
		return &ddns5libdns.Provider{}
	} else if strings.HasSuffix(u.Hostname(), duckdnsSuffix) {
		token := duckdnsorg_Token()
		return &duckdns.Provider{APIToken: token}
	} else if *cloudflareDDNS {
		token := cloudflare_Token()
		return &cloudflare.Provider{APIToken: token}
	}
	elog.Fatal(
		`Not able to determine which DDNS provider to use:
*.ddns5.com indicates: ddns5.com
*.duckdns.org indicates: DuckDNS
* with the flag -cloudflare indicates: Cloudflare.
`)
	panic("no")
}

func initRxid2state(n int, id TrackId) {
	log.Printf("Creating %v %v tracks", n, id.String())

	for i := 0; i < n; i++ {
		rxid := TrackId(i) + id
		rxid2state[rxid] = &RxidState{
			lastReceipt: time.Time{},
			rxid:        rxid,
		}
	}
}
func initMediaHandlerState(t TrackCounts) {
	initRxid2state(t.numAudio, XAudio)
	initRxid2state(t.numVideo, XVideo)
	initRxid2state(t.numIdleVideo, XIdleVideo)
	//	initRxid2state(t.numIdleVideo, Xidleaudio
}

// func getExplicitHostPort(u *url.URL) string {
// 	return u.Hostname() + ":" + getPort(u)
// }

func getPort(u *url.URL) string {
	if u.Scheme == "https" {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	if u.Scheme == "http" {
		if u.Port() == "" {
			return "80"
		}
		return u.Port()
	}
	panic("bad scheme")
}

// ddnsRegisterIPAddresses will register IP addresses to hostnames
// zone might be duckdns.org
// subname might be server01
func ddnsRegisterIPAddresses(provider certmagic.ACMEDNSProvider, fqdn string, suffixCount int, addrs []net.IP) {

	//timestr := strconv.FormatInt(time.Now().UnixNano(), 10)
	// ddnsHelper.Present(nil, *ddnsDomain, timestr, dns.TypeTXT)
	// ddnsHelper.Wait(nil, *ddnsDomain, timestr, dns.TypeTXT)
	for _, v := range addrs {

		var dnstype uint16

		if v.To4() != nil {
			dnstype = dns.TypeA
		} else {
			dnstype = dns.TypeAAAA
		}

		normalip := NormalizeIP(v.String(), dnstype)

		pubpriv := "Public"
		if IsPrivate(v) {
			pubpriv = "Private"
		}
		log.Printf("Registering DNS %v %v %v %v IP-addr", fqdn, dns.TypeToString[dnstype], normalip, pubpriv)

		x := provider.(DDNSProvider)
		//log.Println("DDNS setting", fqdn, suffixCount, normalip, dns.TypeToString[dnstype])
		err := ddnsSetRecord(context.Background(), x, fqdn, suffixCount, normalip, dnstype)
		checkFatal(err)

		log.Println("DDNS waiting for propagation", fqdn, suffixCount, normalip, dns.TypeToString[dnstype])
		err = ddnsWaitUntilSet(context.Background(), fqdn, normalip, dnstype)
		checkFatal(err)

		elog.Printf("DNS registered %v  %v  %v", httpsUrl.Hostname(), v, routableMessage(v))

		//log.Println("DDNS propagation complete", fqdn, suffixCount, normalip)
	}
}

func duckdnsorg_Token() string {
	token := os.Getenv("DUCKDNS_TOKEN")
	if len(token) > 0 {
		log.Println("Got Duckdns token from env: DUCKDNS_TOKEN ")
		return token
	}

	elog.Fatal("You must set the environment variable: DDNS5_TOKEN to use Duckdns.org")
	panic("no")
}

func cloudflare_Token() string {
	token := os.Getenv("CLOUDFLARE_TOKEN")
	if len(token) > 0 {
		log.Println("Got Cloudflare token from env: CLOUDFLARE_TOKEN ")
		return token
	}

	elog.Fatal("You must set the environment variable: CLOUDFLARE_TOKEN in order to use Cloudflare for DDNS or ACME")
	panic("no2")
}

//why ddns5 uses tokens
//we must use tokens, unfortunatly.
//why?
// if our ddns provider just did A,AAAA records and no TXT
// records, we could allow write-once A,AAAA records.
// But! by supporting TXT records we CANNOT allow
// TXT records to be created in a FQDN by anyone BUT
// the creator of the A and AAAA record for that FQDN

// So, its a security issue, we CANNOT allow Bob to
// Create bob.ddns5.com/A/192.168.1.1
// and then allow Alice to create bob.ddns5.com/TXT/xxxxxxxxx
// if we did, Alice could get a cert for bob.ddns5.com

func ddnsEnableDNS01Challenge(foo certmagic.ACMEDNSProvider) {

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		//DNSProvider:        provider.(certmagic.ACMEDNSProvider),
		DNSProvider:        foo,
		TTL:                0,
		PropagationTimeout: 0,
		Resolvers:          []string{},
	}
}

func newPeerConnection() *webrtc.PeerConnection {

	// Do NOT share MediaEngine between PC!  BUG of 020321
	// with Sean & Orlando. They are so nice.
	m := &webrtc.MediaEngine{}

	i := &interceptor.Registry{}
	_ = i
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		panic(err)
	}

	//rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i))
	rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(m))

	//rtcApi = webrtc.NewAPI()
	//if *videoCodec == "h264" {
	if true {
		err := RegisterH264AndOpusCodecs(m)
		checkPanic(err)
	} else {
		log.Fatalln("only h.264 supported")
		// err := m.RegisterDefaultCodecs()
		// checkPanic(err)
	}

	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	checkPanic(err)

	return peerConnection
}

func mstime() string {
	const timeformatutc = "2006-01-02T15:04:05.000Z07:00"
	return time.Now().UTC().Format(timeformatutc)
}

// sends error to stderr and http.ResponseWriter with time
func teeErrorStderrHttp(w http.ResponseWriter, err error) {
	m := mstime() + " :: " + err.Error()
	elog.Println(m)
	http.Error(w, m, http.StatusInternalServerError)
}

// sfu ingress setup
func pubHandler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	log.Println("pubHandler request:", req.URL.String())

	if req.Header.Get("Content-Type") != "application/sdp" {
		teeErrorStderrHttp(w, fmt.Errorf("Content-Type==application/sdp required on /pub"))
		return
	}

	if req.Method != "POST" {
		teeErrorStderrHttp(w, fmt.Errorf("only POST allowed"))
		return
	}

	offer, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// cam
		// handle this error, although it is of low value [probability,frequency]
		teeErrorStderrHttp(w, err)
		return
	}

	// it takes 5 seconds to drop peerconnection on page reload
	// so, if a new connection comes in, we wait upto seven seconds to get the
	// semaphore
	ctx, cancel := context.WithTimeout(req.Context(), 7*time.Second)
	defer cancel() // releases resources if slowOperation completes before timeout elapses)

	err = ingressSemaphore.Acquire(ctx, 1)
	if err != nil {
		teeErrorStderrHttp(w, errors.New("ingress busy"))
		return
	}

	// if !ingressSemaphore.TryAcquire(1) {
	// 	teeErrorStderrHttp(w, errors.New("ingress busy"))
	// 	return
	// }
	// inside here will panic if something prevents success/by design
	answersd := createIngressPeerConnection(string(offer))

	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write([]byte(answersd.SDP))
	checkPanic(err) // cam/if this write fails, then fail hard!

	//NOTE, Do NOT ever use http.error to return SDPs
}

//number of video media sections
//will be 1 for simulcast
// will be 3 for three m=video
func numVideoMediaDesc(sdpsd *sdp.SessionDescription) (n int) {
	for _, v := range sdpsd.MediaDescriptions {
		if v.MediaName.Media == "video" {
			n++
		}
	}
	return
}

// sfu egress setup
// 041521 Decided checkPanic() is the correct way to handle errors in this func.
func SubHandler(w http.ResponseWriter, httpreq *http.Request) {
	defer httpreq.Body.Close()
	var err error

	log.Println("subHandler request", httpreq.URL.String())

	var txid uint64

	rawtxid := httpreq.URL.Query().Get("txid")
	if rawtxid != "" {
		if len(rawtxid) != 16 {
			teeErrorStderrHttp(w, fmt.Errorf("txid value must be 16 hex chars long"))
			return
		}

		txid, err = strconv.ParseUint(rawtxid, 16, 64)
		if err != nil {
			teeErrorStderrHttp(w, fmt.Errorf("txid value must be 16 hex chars only"))
			return
		}
	} else {
		log.Println("assigning random txid")
		txid = mrand.Uint64()
	}
	log.Println("txid is", txid)

	txidMapMutex.Lock()
	_, foundTxid := txidMap[txid]
	txidMapMutex.Unlock()

	rid := httpreq.URL.Query().Get("level")
	//issfu := httpreq.URL.Query().Get("issfu") != ""

	if rid != "" {
		//validate transaction id
		//not strictly required as message handler would ignore on bad transaction id
		if !foundTxid {
			teeErrorStderrHttp(w, fmt.Errorf("no such transaction id"))
			return
		}

		trackid, err := parseTrackid(rid)
		if err != nil {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. only video<N>, audio<N> are okay"))
			return
		}

		if _, ok := rxid2state[trackid]; !ok {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. rid=%v not found", rid))
			return
		}

		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: Subid(txid),
			txid:  XVideo + 0, //can only switch output track 0
			rxid:  trackid,
		}

		w.WriteHeader(http.StatusAccepted)
		return
	}

	// got here: thus there was no rid=xxx param

	// rx offer, tx answer

	if httpreq.Method != "POST" {
		teeErrorStderrHttp(w, fmt.Errorf("only POST allowed"))
		return
	}

	if httpreq.Header.Get("Content-Type") != "application/sdp" {
		teeErrorStderrHttp(w, fmt.Errorf("Content-Type==application/sdp required on /sub when not ?level=..."))
		return
	}

	// offer from browser
	offersdpbytes, err := ioutil.ReadAll(httpreq.Body)
	if err != nil {
		teeErrorStderrHttp(w, err)
		return
	}

	if foundTxid {
		teeErrorStderrHttp(w, fmt.Errorf("cannot re-use txid for subscriber"))
		return
	}
	txidMapMutex.Lock()
	txidMap[txid] = struct{}{}
	txidMapMutex.Unlock()

	// Create a new PeerConnection
	log.Println("created PC")
	peerConnection := newPeerConnection()

	logTransceivers("new-pc", peerConnection)

	// NO!
	// peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {...}
	// Pion says:
	// "OnTrack sets an event handler which is called when remote track arrives from a remote peer."
	// the 'sub' side of our SFU just Pushes tracks, it can't receive them,
	// so there is no OnTrack handler

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		log.Println("sub ICE Connection State has changed", icecs.String())
	})
	// XXX is this switch case necessary?, will the pc eventually reach Closed after Failed or Disconnected
	peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		log.Printf("subscriber 0x%016x newstate: %s", txid, cs.String())
		switch cs {
		case webrtc.PeerConnectionStateConnected:
		case webrtc.PeerConnectionStateFailed:
			peerConnection.Close()
		case webrtc.PeerConnectionStateDisconnected:
			peerConnection.Close()
		case webrtc.PeerConnectionStateClosed:
			//we do not delete txid from txidMap, you can't reuse the numbers/slots
			//we hope that since it is closed and unreferenced it will just disappear,
			// (from the heap), but I have my doubts
			// XXX
		}
	})

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdpbytes)}

	if !ValidateSDP(offer) {
		teeErrorStderrHttp(w, fmt.Errorf("invalid offer SDP received"))
		return
	}

	logSdpReport("publisher", offer)

	err = peerConnection.SetRemoteDescription(offer)
	checkPanic(err)

	logTransceivers("offer-added", peerConnection)

	sdsdp, err := offer.Unmarshal()
	checkPanic(err)

	/* logic
	when browser subscribes, we always give it one video track
	and we just switch simulcast to that subscriber's RtpSender using replacetrack

	when another sfu subscribes, we really want to add a track for each
	track it has prepared an m=video section for

	so, we count the number of m=video sections using numVideoMediaDesc()

	this 'numvideo' logic should do that
	*/

	//should be 1 from browser sub, almost always
	//should be 3 from x186k sfu, typically
	videoTrackCount := numVideoMediaDesc(sdsdp)
	log.Println("videoTrackCount", videoTrackCount)

	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	checkPanic(err)
	rtpSender, err := peerConnection.AddTrack(track)
	checkPanic(err)
	go processRTCP(rtpSender)

	subAddTrackCh <- MsgSubscriberAddTrack{
		txtrack: &Track{
			txid:    XAudio + 0,
			subid:   Subid(txid),
			track:   track,
			splicer: &RtpSplicer{},
			rxid:    XAudio + 0,
		},
	}

	for i := 0; i < videoTrackCount; i++ {
		name := fmt.Sprintf("video%d", i)
		track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, name, mediaStreamId)
		checkPanic(err)
		rtpSender, err := peerConnection.AddTrack(track)
		checkPanic(err)
		go processRTCP(rtpSender)

		subAddTrackCh <- MsgSubscriberAddTrack{
			txtrack: &Track{
				txid:    XVideo + TrackId(i),
				subid:   Subid(txid),
				track:   track,
				splicer: &RtpSplicer{},
				rxid:    XVideo + TrackId(i),
			},
		}
	}

	logTransceivers("subHandler-tracksadded", peerConnection)

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	checkPanic(err)

	// Create channel that is blocked until ICE Gathering is complete
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

	// Sets the LocalDescription, and starts our UDP listeners
	err = peerConnection.SetLocalDescription(sessdesc)
	checkPanic(err)

	t0 := time.Now()
	// Block until ICE Gathering is complete, disabling trickle ICE
	// we do this because we only can exchange one signaling message
	// in a production application you should exchange ICE Candidates via OnICECandidate
	<-gatherComplete

	log.Println("ICE gather time is ", time.Since(t0).String())

	// Get the LocalDescription and take it to base64 so we can paste in browser
	ansrtcsd := peerConnection.LocalDescription()

	logSdpReport("sub-answer", *ansrtcsd)

	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write([]byte(ansrtcsd.SDP))
	if err != nil {
		elog.Println(fmt.Errorf("sub sdp write failed:%f", err))
		return
	}

}

func logTransceivers(tag string, pc *webrtc.PeerConnection) {
	if len(pc.GetTransceivers()) == 0 {
		log.Printf("%v transceivers is empty", tag)
	}
	for i, v := range pc.GetTransceivers() {
		rx := v.Receiver()
		tx := v.Sender()
		log.Printf("%v transceiver %v,%v,%v,%v nilrx:%v niltx:%v", tag, i, v.Direction(), v.Kind(), v.Mid(), rx == nil, tx == nil)

		if rx != nil && len(rx.GetParameters().Codecs) > 0 {
			log.Println(" rtprx ", rx.GetParameters().Codecs[0].MimeType)
		}
		if tx != nil && len(tx.GetParameters().Codecs) > 0 {
			log.Println(" rtptx ", tx.GetParameters().Codecs[0].MimeType)
		}
	}
}

func ValidateSDP(rtcsd webrtc.SessionDescription) bool {
	good := strings.HasPrefix(rtcsd.SDP, "v=")
	if !good {
		return false
	}
	_, err := rtcsd.Unmarshal()
	return err == nil
}

func logSdpReport(wherefrom string, rtcsd webrtc.SessionDescription) {
	good := strings.HasPrefix(rtcsd.SDP, "v=")
	nlines := len(strings.Split(strings.Replace(rtcsd.SDP, "\r\n", "\n", -1), "\n"))
	log.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	log.Println("fullsdp", wherefrom, rtcsd.SDP)

	sd, err := rtcsd.Unmarshal()
	if err != nil {
		elog.Printf(" n/0 fail to unmarshal")
		return
	}
	log.Printf(" n/%d media descriptions present", len(sd.MediaDescriptions))
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	checkPanic(err)
	return hex.EncodeToString(bytes)
}

func idleLoopPlayer(p []rtp.Packet) {

	n := len(p)
	delta1 := time.Second / time.Duration(n)
	delta2 := uint32(90000 / n)
	mrand.Seed(time.Now().UnixNano())
	seq := uint16(mrand.Uint32())
	ts := mrand.Uint32()

	id := XIdleVideo + 0
	rxidstate, ok := rxid2state[id]
	if !ok {
		panic("cannot find idle video loop track")
	}

	for {
		for _, tmp := range p {
			v := tmp // critical!, if we use original packets, something bad happens.
			// (not sure what exactly)

			time.Sleep(delta1)
			v.SequenceNumber = seq
			seq++
			v.Timestamp = ts
			// if *logPackets {
			// 	logPacket(logPacketIn, &v)
			// }

			//fmt.Printf(" tx idle msg %x iskey %v len %v\n", v.Payload[0:10],rtpstuff.IsH264Keyframe(v.Payload),len(v.Payload))

			rxMediaCh <- MsgRxPacket{rxidstate: rxidstate, packet: &v, rxClockRate: 90000}

		}
		ts += delta2
	}
}

func dialUpstream(baseurl string) {

	txid := randomHex(8)

	dialurl := baseurl + "?issfu=1&txid=" + txid

	log.Println("dialUpstream url:", dialurl)

	peerConnection := newPeerConnection()

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingressOnTrack(peerConnection, track, receiver)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		log.Println("dial ICE Connection State has changed", icecs.String())
	})

	//XXXX

	recvonly := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}
	// create transceivers for 1x audio, 3x video
	_, err := peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)

	// Create an offer to send to the other process
	offer, err := peerConnection.CreateOffer(nil)
	checkPanic(err)

	logSdpReport("dialupstream-offer", offer)

	// Sets the LocalDescription, and starts our UDP listeners
	// Note: this will start the gathering of ICE candidates
	err = peerConnection.SetLocalDescription(offer)
	checkPanic(err)

	setupIngressStateHandler(peerConnection)

	// send offer, get answer

	delay := time.Second
tryagain:
	log.Println("dialing", dialurl)
	resp, err := http.Post(dialurl, "application/sdp", strings.NewReader(offer.SDP))

	// yuck
	// back-off redialer
	if err != nil && strings.HasSuffix(strings.ToLower(err.Error()), "connection refused") {
		log.Println("connection refused")
		atomic.AddUint64(&myMetrics.dialConnectionRefused, 1)
		time.Sleep(delay)
		if delay <= time.Second*30 {
			delay *= 2
		}
		goto tryagain
	}
	checkPanic(err)
	defer resp.Body.Close()

	log.Println("dial connected")

	answerraw, err := ioutil.ReadAll(resp.Body)
	checkPanic(err) //cam

	anssd := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	logSdpReport("dial-answer", anssd)

	err = peerConnection.SetRemoteDescription(anssd)
	checkPanic(err)

}

func processRTCP(rtpSender *webrtc.RTPSender) {

	if true {
		rtcpBuf := make([]byte, 1500)
		for {
			_, _, rtcpErr := rtpSender.Read(rtcpBuf)
			if rtcpErr != nil {
				return
			}
		}
	} else {
		for {
			packets, _, rtcpErr := rtpSender.ReadRTCP()
			if rtcpErr != nil {
				return
			}
			if true {
				for _, pkt := range packets {
					switch v := pkt.(type) {
					case *rtcp.SenderReport:
						//fmt.Printf("rtpSender Sender Report %s \n", v.String())
					case *rtcp.ReceiverReport:
						fmt.Printf("rtpSender Receiver Report %s \n", v.String())
					case *rtcp.ReceiverEstimatedMaximumBitrate:
					case *rtcp.PictureLossIndication:

					default:
						// fmt.Printf("foof %#v\n", v)
						// panic(v)
					}
				}
			}
		}
	}
}

var _ = text2pcapLog

func text2pcapLog(log *log.Logger, inbuf []byte) {
	var b bytes.Buffer
	b.Grow(20 + len(inbuf)*3)
	b.WriteString("000000 ")
	for _, v := range inbuf {
		b.WriteString(fmt.Sprintf("%02x ", v))
	}
	b.WriteString("!text2pcap")

	log.Print(b.String())
}

var _ = logPacket

// logPacket writes text2pcap compatible lines
func logPacket(log *log.Logger, packet *rtp.Packet) {
	text2pcapLog(log, packet.Raw)
}

// logPacketNewSSRCValue writes text2pcap compatible lines
// but, this packet will NOT contain RTP,
// // but rather: ether/ip/udp/special_token
// func logPacketNewSSRCValue(log *log.Logger, ssrc webrtc.SSRC, src rtpsplice.RtpSource) {
// 	text2pcapSentinel := []byte{0, 31, 0xde, 0xad, 0xbe, 0xef}
// 	buf := new(bytes.Buffer)
// 	buf.Write(text2pcapSentinel)

// 	source := []uint64{1, uint64(ssrc), uint64(src)}
// 	err := binary.Write(buf, binary.LittleEndian, source)
// 	checkPanic(err)

// 	text2pcapLog(log, buf.Bytes())
// }

func ingressOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	_ = receiver //silence warnings

	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		s, ok := rxid2state[XAudio]
		if !ok {
			panic("cannot find idle video loop track2")
		}

		inboundTrackReader(track, s, track.Codec().ClockRate)
		//here on error
		log.Printf("audio reader %p exited", track)
		return
	}

	// audio callbacks never get here
	// video will proceed here

	if strings.ToLower(mimetype) != videoMimeType {
		panic("unexpected kind or mimetype:" + track.Kind().String() + ":" + mimetype)
	}

	log.Println("OnTrack RID():", track.RID())
	log.Println("OnTrack MediaStream.id [msid ident]:", track.StreamID())
	log.Println("OnTrack MediaStreamTrack.id [msid appdata]:", track.ID())

	var trackname string // store trackname here, reduce locks
	if track.RID() == "" {
		//not proper simulcast!
		// either upstream SFU we are downstream of,
		// or we are getting ingress request from non-simulcast browser (or OBS)

		log.Println("using TrackId/msid: stream trackid for trackname:", track.ID())
		if *dialIngressURL != "" {
			// we are dialing, and thus we are downstream of SFU
			if !strings.HasPrefix(track.ID(), "video") {
				panic("Non conforming track.ID() on ingress")
			}
			trackname = track.ID()
		} else {
			// we are downstream of Browser and there is no RID on this video track
			// presume this is a non-simulcast browser sending
			// track ID will just be a guid or random data from browser
			trackname = "video0"
			// we could check for multiple video tracks and panic()
			// but maybe ignoring this issue will help some poor soul.
			// var numNonRIDVideoTracks int32
			// if atomic.AddInt32(&numNonRIDVideoTracks,1)>1 {
			// 	panic("")
			// }
		}

	} else {
		log.Println("using RID for trackname:", track.RID())
		trackname = track.RID()
	}

	if trackname != "video0" && trackname != "video1" && trackname != "video2" {
		panic("only track names video0,video1,video2 supported:" + trackname)
	}

	go func() {
		var err error

		for {
			err = sendPLI(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			}
			checkPanic(err)

			err = sendREMB(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			}
			checkPanic(err)

			time.Sleep(3 * time.Second)
		}
	}()

	rxid, err := parseTrackid(trackname)
	checkPanic(err)

	s, ok := rxid2state[rxid]
	if !ok {
		elog.Printf("invalid track name: %s, will not read/forward track", trackname)
	}

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, s, track.Codec().ClockRate)
	//here on error
	log.Printf("video reader %p exited", track)

}

func parseTrackid(trackname string) (t TrackId, err error) {
	if strings.HasPrefix(trackname, "video") {
		i, xerr := strconv.Atoi(strings.TrimPrefix(trackname, "video"))
		if xerr != nil {
			err = fmt.Errorf("fail to parse trackid: %v", trackname)
			return
		}

		t = XVideo + TrackId(i)
		return
	}

	if strings.HasPrefix(trackname, "audio") {
		i, xerr := strconv.Atoi(strings.TrimPrefix(trackname, "audio"))
		if xerr != nil {
			err = fmt.Errorf("fail to parse trackid: %v", trackname)
			return
		}

		t = XAudio + TrackId(i)
		return
	}

	err = fmt.Errorf("need video<N> or audio<N> for track num, got:[%s]", trackname)
	return
}

func inboundTrackReader(rxTrack *webrtc.TrackRemote, rxidstate *RxidState, clockrate uint32) {

	for {
		p, _, err := rxTrack.ReadRTP()
		if err == io.EOF {
			return
		}
		checkPanic(err)

		rxMediaCh <- MsgRxPacket{rxidstate: rxidstate, packet: p, rxClockRate: clockrate}
	}
}

const Spacing = 100

func (e TrackId) String() string {

	switch e.XTrackId() {
	case XVideo:
		return "XVideo"
	case XAudio:
		return "XAudio"
	case XData:
		return "XData"
	case XIdleVideo:
		return "XIdleVideo"
	case XInvalid:
		return "XInvalid"
	}

	return "<bad TrackId>"
}

func (e TrackId) XTrackId() TrackId {

	return (e / Spacing) * Spacing
}

// XXX it would be possible to replace 'map[Rxid]' elements with '[]' elements
// if we compact down the rx track numbers (no audio=10000)

func msgLoop() {
	for {
		msgOnce()
	}
}

func msgOnce() {

	select {

	case m := <-rxMediaCh:
		//fmt.Printf(" xtx %x\n",m.packet.Payload[0:10])
		//println(6666,m.rxidstate.rxid)

		m.rxidstate.lastReceipt = time.Now()

		isaudio := m.rxidstate.rxid.XTrackId() == XAudio
		if !isaudio {
			if !rtpstuff.IsH264Keyframe(m.packet.Payload) {
				goto not_keyframe
			}
		}

		//is keyframe switch any pending Tracks
		for _, v := range txtracks {
			if v.pending == m.rxidstate.rxid {
				v.rxid = v.pending
				// no! v.pending = XInvalid
				// pending should never be XInvalid
			}
		}

	not_keyframe:
		rxid := m.rxidstate.rxid
		for i, tr := range txtracks {

			send := tr.rxid == rxid
			if !send {
				continue
			}

			//fmt.Printf("%d ", int(rxid))

			var packet *rtp.Packet = m.packet
			var ipacket interface{}

			if tr.splicer != nil {
				ipacket = rtpPacketPool.Get()
				packet = ipacket.(*rtp.Packet)
				*packet = *m.packet
				packet = SpliceRTP(tr.splicer, packet, time.Now().UnixNano(), int64(m.rxClockRate))
			}

			//fmt.Printf("write send=%v ix=%d mediarxid=%d txtracks[i].rxid=%d  %x %x %x\n",
			//	send, i, rxid, tr.rxid, packet.SequenceNumber, packet.Timestamp, packet.SSRC)

			if true {
				err := tr.track.WriteRTP(packet)
				if err == io.ErrClosedPipe {
					log.Printf("track io.ErrClosedPipe, removing track %v %v %v", tr.subid, tr.txid, tr.rxid)

					//first remove from sub2txid2track
					// if _, ok := sub2txid2track[tr.subid][tr.txid]; !ok {
					// 	panic("invalid tr.txid")
					// }
					delete(sub2txid2track[tr.subid], tr.txid)

					// slice tricks non-order preserving delete
					txtracks[i] = txtracks[len(txtracks)-1]
					txtracks[len(txtracks)-1] = nil
					txtracks = txtracks[:len(txtracks)-1]

				}
			}

			if tr.splicer != nil {
				*packet = rtp.Packet{}
				rtpPacketPool.Put(ipacket)
			}

		}

	case m := <-subAddTrackCh:

		tr := m.txtrack

		txtracks = append(txtracks, tr)

		if _, ok := sub2txid2track[tr.subid]; !ok {
			sub2txid2track[tr.subid] = make(map[TrackId]*Track)
		}

		if !rxid2state[tr.rxid].active && tr.rxid.XTrackId() == XVideo {
			tr.rxidsave = tr.rxid
			tr.pending = XIdleVideo
		}

		sub2txid2track[tr.subid][tr.txid] = tr

	case m := <-subSwitchTrackCh:

		if a, ok := sub2txid2track[m.subid]; ok {
			if tr, ok := a[m.txid]; ok {
				if m.rxid == XInvalid {
					panic("bad msg 99")
				}
				tr.pending = m.rxid
			} else {
				elog.Println("invalid txid", m.txid)
			}
		} else {
			elog.Println("invalid subid", m.subid)
		}

	case now := <-ticker.C:

		//fmt.Println("Tick at", tk)

		for _, v := range rxid2state {

			isvideo := v.rxid.XTrackId() == XVideo

			if !isvideo {
				continue // we only do idle switching on video right now
			}

			duration := now.Sub(v.lastReceipt)
			active := duration < time.Second

			transition := v.active != active

			//println(999,active,v.active )

			if !transition {
				continue
			}

			v.active = active

			if active {
				// became ready, thus no longer idle
				// find all tracks on XIdleVideo or pending: XIdleVideo
				// change their source,pending value to the idle track
				for _, tr := range txtracks {
					if tr.rxid == XIdleVideo || tr.pending == XIdleVideo {
						tr.pending = tr.rxidsave
					}
				}

			} else {
				// became idle.
				// find all tracks on this rxid, or pending this rxid
				// change their source,pending value to the idle track
				// okay
				for _, tr := range txtracks {
					if tr.rxid == v.rxid || tr.pending == v.rxid {
						tr.rxidsave = tr.pending
						tr.pending = XIdleVideo
					}
				}

			}

			// idle transition has occurred on this Rxid

		}
	}
}

func sendREMB(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.ReceiverEstimatedMaximumBitrate{Bitrate: 10000000, SenderSSRC: uint32(track.SSRC())}})
}

func sendPLI(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}})
}

/*
	IMPORTANT
	read this like your life depends upon it.
	########################
	any error that prevents peerconnection setup this line MUST MUST MUST panic()
	why?
	1. pubStartCount is now set
	2. sublishers will be connected because pubStartCount>0
	3. if ingress cannot proceed, we must Panic to live upto the
	4. single-shot, fail-fast manifesto I envision
*/
// error design:
// this does not return an error
// if an error occurs, we panic
// single-shot / fail-fast approach
//
func createIngressPeerConnection(offersdp string) *webrtc.SessionDescription {

	var err error
	log.Println("createIngressPeerConnection")

	// Set the remote SessionDescription

	//	ofrsd, err := rtcsd.Unmarshal()
	//	checkPanic(err)

	// Create a new RTCPeerConnection
	peerConnection := newPeerConnection()

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingressOnTrack(peerConnection, track, receiver)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		log.Println("ingress ICE Connection State has changed", icecs.String())
	})

	// XXX 1 5 20 cam
	// not sure reading rtcp helps, since we should not have any
	// senders on the ingress.
	// leave for now
	//
	// Read incoming RTCP packets
	// Before these packets are retuned they are processed by interceptors. For things
	// like NACK this needs to be called.

	// we dont have, wont have any senders for the ingress.
	// it is just a receiver
	// log.Println("num senders", len(peerConnection.GetSenders()))
	// for _, rtpSender := range peerConnection.GetSenders() {
	// 	go processRTCP(rtpSender)
	// }

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdp)}
	logSdpReport("publisher", offer)

	err = peerConnection.SetRemoteDescription(offer)
	checkPanic(err)

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	checkPanic(err)

	// Create channel that is blocked until ICE Gathering is complete
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

	// Sets the LocalDescription, and starts our UDP listeners
	err = peerConnection.SetLocalDescription(sessdesc)
	checkPanic(err)

	// Block until ICE Gathering is complete, disabling trickle ICE
	// we do this because we only can exchange one signaling message
	// in a production application you should exchange ICE Candidates via OnICECandidate
	<-gatherComplete

	logSdpReport("listen-ingress-answer", *peerConnection.LocalDescription())

	setupIngressStateHandler(peerConnection)

	// Get the LocalDescription and take it to base64 so we can paste in browser
	return peerConnection.LocalDescription()
}

func setupIngressStateHandler(peerConnection *webrtc.PeerConnection) {

	peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		log.Println("ingress Connection State has changed", cs.String())
		switch cs {
		case webrtc.PeerConnectionStateConnected:
		case webrtc.PeerConnectionStateFailed:
			peerConnection.Close()
		case webrtc.PeerConnectionStateDisconnected:
			peerConnection.Close()
		case webrtc.PeerConnectionStateClosed:
			ingressSemaphore.Release(1)
		}
	})
}

func getDefaultRouteInterfaceAddresses() []net.IP {

	// we don't send a single packets to these hosts
	// but we use their addresses to discover our interface to get to the Internet
	// These addresses could be almost anything

	var ipaddrs []net.IP

	addr := getDefRouteIntfAddrIPv4()
	if addr != nil {
		ipaddrs = append(ipaddrs, addr)
	}

	addr = getDefRouteIntfAddrIPv6()
	if addr != nil {
		ipaddrs = append(ipaddrs, addr)
	}

	if len(ipaddrs) == 0 {
		return nil
	}

	return ipaddrs
}

func getDefRouteIntfAddrIPv6() net.IP {
	const googleDNSIPv6 = "[2001:4860:4860::8888]:8080" // not important, does not hit the wire
	cc, err := net.Dial("udp6", googleDNSIPv6)          // doesnt send packets
	if err == nil {
		cc.Close()
		return cc.LocalAddr().(*net.UDPAddr).IP
	}
	return nil
}

func getDefRouteIntfAddrIPv4() net.IP {
	const googleDNSIPv4 = "8.8.8.8:8080"       // not important, does not hit the wire
	cc, err := net.Dial("udp4", googleDNSIPv4) // doesnt send packets
	if err == nil {
		cc.Close()
		return cc.LocalAddr().(*net.UDPAddr).IP
	}
	return nil
}

// SpliceRTP
// this is carefully handcrafted, be careful
//
// we may want to investigate adding seqno deltas onto a master counter
// as a way of making seqno most consistent in the face of lots of switching,
// and also more robust to seqno bug/jumps on input
//
// This grabs mutex after doing a fast, non-mutexed check for applicability
func SpliceRTP(s *RtpSplicer, o *rtp.Packet, unixnano int64, rtphz int64) *rtp.Packet {

	forceKeyFrame := false

	copy := *o
	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	if o.SSRC != s.lastSSRC || forceKeyFrame {
		log.Printf("SpliceRTP: %p: ssrc changed new=%v cur=%v", s, o.SSRC, s.lastSSRC)

		td := unixnano - s.lastUnixnanosNow // nanos
		if td < 0 {
			td = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		td *= rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		if td == 0 {
			td = 1
		}
		s.tsOffset = o.Timestamp - (s.lastTS + uint32(td))
		s.snOffset = o.SequenceNumber - s.lastSN - 1

		//log.Println(11111,	copy.SequenceNumber - s.snOffset,s.lastSN)
		// old approach/abandoned
		// timestamp := unixnano * rtphz / int64(time.Second)
		// s.addTS = uint32(timestamp)

		//2970 is just a number that worked very with with chrome testing
		// is it just a fallback
		//clockDelta := s.findMostFrequentDelta(uint32(2970))

		//s.tsFrequencyDelta = s.tsFrequencyDelta[:0] // reset frequency table

		//s.addTS = s.lastSentTS + clockDelta
	}

	// we don't want to change original packet, it gets
	// passed into this routine many times for many subscribers

	copy.Timestamp -= s.tsOffset
	copy.SequenceNumber -= s.snOffset
	//	tsdelta := int64(copy.Timestamp) - int64(s.lastSentTS) // int64 avoids rollover issues
	// if !ssrcChanged && tsdelta > 0 {              // Track+measure uint32 timestamp deltas
	// 	s.trackTimestampDeltas(uint32(tsdelta))
	// }

	s.lastUnixnanosNow = unixnano
	s.lastTS = copy.Timestamp
	s.lastSN = copy.SequenceNumber
	s.lastSSRC = copy.SSRC

	return &copy
}

// remove with go 1.17 arrival
func IsPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Following RFC 4193, Section 3. Local IPv6 Unicast Addresses which says:
		//   The Internet Assigned Numbers Authority (IANA) has reserved the
		//   following three blocks of the IPv4 address space for private internets:
		//     10.0.0.0        -   10.255.255.255  (10/8 prefix)
		//     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		//     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Following RFC 4193, Section 3. Private Address Space which says:
	//   The Internet Assigned Numbers Authority (IANA) has reserved the
	//   following block of the IPv6 address space for local internets:
	//     FC00::  -  FDFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF (FC00::/7 prefix)
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

// To implement this, requires we run an API that 'calls-back' to see if ports are open
// let's see if users are happy with curl directions on checking access for now:
// curl -v telnet://127.0.0.1:22
func IsAccessibleFromInternet(addrPort string) bool {
	return false
}

var _ = IsAccessibleFromInternet

// returns nil on failure
func getMyPublicIpV4() net.IP {
	var publicmyip []string = []string{"https://api.ipify.org", "http://checkip.amazonaws.com/"}

	client := http.Client{
		Timeout: 3 * time.Second,
	}
	for _, v := range publicmyip {
		res, err := client.Get(v)
		if err != nil {
			return nil
		}
		ipraw, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil
		}
		ip := net.ParseIP(string(ipraw))
		if ip != nil {
			return ip
		}
	}
	return nil
}

func reportHttpsReadyness() {

	const interval = 5
	for i := 0; ; i += interval {

		time.Sleep(time.Second * interval)

		if httpsHasCertificate {
			return
		}

		if i < 5 {
			continue
		}

		elog.Printf("sfu1 HTTPS NOT READY: Waited %d seconds.", i)

		if httpsUsingDDNS && i > 30 {
			elog.Printf("No HTTPS certificate: Please check DNS setup, or change DDNS provider")
			break
		}
		if !httpsUsingDDNS && i > 15 {
			elog.Printf("No HTTPS certificate: Please check firewall port 80 and/or 443")
			break
		}

	}

	elog.Printf("No HTTPS certificate: Ceasing status messages about certificate.")
}
