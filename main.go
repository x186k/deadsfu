package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
	"sync"

	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/miekg/dns"

	"github.com/pkg/profile"
	//"github.com/x186k/dynamicdns"

	"golang.org/x/sync/semaphore"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"

	_ "embed"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"

	"github.com/x186k/ddns5libdns"
	"github.com/x186k/sfu1/rtpstuff"
)

// content is our static web server content.
//go:embed html/index.html
var indexHtml []byte

//go:embed lfs/idle.screen.h264.pcapng
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
	docsurl       = "https://sfu1.com/docs"
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

func checkFatal(err error) {
	if err != nil {
		elog.Fatal(err)
	}
}

func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func slashHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Scheme == "http" && *httpsPort != 0 {
		uri := "https://" + r.Host + ":" + strconv.Itoa(*httpsPort) + r.RequestURI
		log.Println("Redirecting HTTP req to ", uri)
		http.Redirect(w, r, uri, http.StatusMovedPermanently)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if r.URL.Path != "/" {
		http.Error(w, "404 - page not found", http.StatusNotFound)
		return
	}

	//XXX fix
	if true || len(indexHtml) == 0 {
		buf, err := ioutil.ReadFile("html/index.html")
		if err != nil {
			http.Error(w, "can't open index.html", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf)
	} else {
		_, _ = w.Write(indexHtml)
	}
}

var numVideoTracks = flag.Int("num-video", 6, "number of video tracks")
var numAudioTracks = flag.Int("num-audio", 1, "number of audio tracks")

//var silenceJanus = flag.Bool("silence-janus", false, "if true will throw away janus output")
var debug = flag.Bool("z-debug", false, "enable debug output")
var cpuprofile = flag.Int("z-cpu-profile", 0, "number of seconds to run + turn on profiling")

// var logPackets = flag.Bool("z-log-packets", false, "log packets for later use with text2pcap")
// var logSplicer = flag.Bool("z-log-splicer", false, "log RTP splicing debug info")

// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
var nohtml = flag.Bool("no-html", false, "do not serve any html files, only allow pub/sub API")
var dialIngressURL = flag.String("dial-ingress", "", "Specify a URL for outbound dial for ingress")

//var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")

const httpPortMsg = `
Port number to bind/listen for HTTP requests.
May both: serve HTML and/or perform WebRTC signalling.
If https-port also used, HTTP will redirect to HTTPS.
HTTP is preferred when using in conjunction with a front-end load balancer.
Common choices are 80 or 8080, or 0.
Default is zero (0), which means do not enable/bind/listen for HTTP.
`

var httpPort = flag.Int("http-port", 0, httpPortMsg)

const httpsPortMsg = `
Port number to bind/listen for HTTPS requests.
May both: serve HTML and/or perform WebRTC signalling.
Must use -domain when using HTTPS
Common choices are 443 or 8443, or 0.
Default is zero (0), which means do not enable/bind/listen for HTTPS.
`

var httpsPort = flag.Int("https-port", 0, httpsPortMsg)

var obsStudio = flag.Bool("obs-studio", false, "Enable OBS Studio by tweaking SSL/TLS version numbers")

var helpAll = flag.Bool("all", false, "Show the full set of advanced flags\n")

//var ddnsFlag = flag.Bool("ddns-domain", false, "Use -domain <name> to register IP addresses for: A/AAAA DNS records")

//var acmeFlag = flag.Bool("acme-domain", false, "Use -domain <name> to get HTTPS/Acme/Let's-encrypt certificate")

//var openTab = flag.Bool("opentab", false, "Open a browser tab to the User transmit/receive panel")

// var logPacketIn = log.New(os.Stdout, "I ", log.Lmicroseconds|log.LUTC)
// var logPacketOut = log.New(os.Stdout, "O ", log.Lmicroseconds|log.LUTC)

var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)

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

var stunServer = flag.String("stun-server", "stun.l.google.com:19302", "hostname:port of STUN server")

func main() {
	var err error

	go logGoroutineCountToDebugLog()

	go idleLoopPlayer(idleScreenH264Pcapng)

	go msgLoop()

	var cloudflareDDNS = flag.Bool("cloudflare", false, "Use Cloudflare API for DDNS and HTTPS ACME/Let's encrypt")
	var domain = flag.String("domain", "", "Domain name for either: DDNS registration or HTTPS ACME/Let's encrypt")
	var interfaceAddr = flag.String("interface", "", "The ipv4/v6 interface to bind the web server, ie: 192.168.2.99")

	flag.Usage = Usage // my own usage handle
	flag.Parse()

	initMediaHandlerState(*numVideoTracks, *numAudioTracks)

	if *httpPort == 0 && *httpsPort == 0 {

		fmt.Fprintf(flag.CommandLine.Output(), "\nError: either -http-port or -https-port must be used.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *helpAll {
		flag.Usage()
		os.Exit(0)
	}

	if *debug {
		log.SetFlags(log.Lmicroseconds | log.LUTC)
		log.SetPrefix("D ")
		log.SetOutput(os.Stdout)
		log.Println("debug output IS enabled")
	} else {
		elog.Println("debug output NOT enabled")
		log.SetOutput(ioutil.Discard)
		log.SetPrefix("")
		log.SetFlags(0)
	}
	log.Println("NumGoroutine", runtime.NumGoroutine())

	// MUX setup
	mux := http.NewServeMux()

	if !*nohtml {
		mux.HandleFunc("/", slashHandler)
	}
	mux.HandleFunc(subPath, subHandler)
	if *dialIngressURL == "" {
		mux.HandleFunc(pubPath, pubHandler)
	}

	if *httpsPort != 0 {
		if *domain == "" {
			xdomain := randomHex(4) + ".ddns5.com"
			elog.Fatalf("-domain <name> flag must be used with -https or -http-https\nFor example, you could use: -domain %s\nddns5.com is a no-auth dynamic dns sevice\nsee the Docs online: %s\n", xdomain, docsurl)
		} else if strings.HasSuffix(*domain, ddns5Suffix) {
			// zone := string(ddns5Suffix[1:])
			// subname := strings.TrimSuffix(*domain, ddns5Suffix)

			//token := ddns5com_Token()
			ddnsProvider := &ddns5libdns.Provider{}
			ddnsRegisterIPAddresses(ddnsProvider, *domain, 2, *interfaceAddr)

			acmeConfigureProvider(ddnsProvider)
		} else if strings.HasSuffix(*domain, duckdnsSuffix) {
			token := duckdnsorg_Token()
			// zone := string(duckdnsSuffix[1:])
			// subname := strings.TrimSuffix(*domain, duckdnsSuffix)

			ddnsProvider := &duckdns.Provider{APIToken: token}
			ddnsRegisterIPAddresses(ddnsProvider, *domain, 2, *interfaceAddr)

			acmeConfigureProvider(ddnsProvider)
		} else if *cloudflareDDNS {
			//cloudflare can have any zone, not just duckdns.org
			token := cloudflare_Token()

			// split := dns.SplitDomainName(*domain)
			// zone := strings.Join(split[len(split)-2:], ".")
			// subname := strings.TrimSuffix(*domain, "."+zone)

			ddnsProvider := &cloudflare.Provider{APIToken: token}
			ddnsRegisterIPAddresses(ddnsProvider, *domain, 2, *interfaceAddr)

			acmeConfigureProvider(ddnsProvider)
		} else {
			elog.Printf("We assume you have pointed the IP for domain: %s to this machine.", *domain)
			elog.Printf("And adjusted your firewall")
			elog.Printf("Also, LetsEncrypt certificates will only work if port 80/443 are reachable from the Internet")
		}
	}

	if *interfaceAddr == "::" {
		*interfaceAddr = ""
	}

	if *httpPort != 0 {

		// httpLn, err := net.Listen("tcp", laddr)
		// checkPanic(err)
		// hostport := httpLn.Addr().String()

		port := strconv.Itoa(*httpPort)

		if *interfaceAddr == "" {
			if addr := getDefRouteIntfAddrIPv4(); addr != nil {
				printURLS("http", addr.String(), port)
			} else if addr := getDefRouteIntfAddrIPv6(); addr != nil {
				printURLS("http", addr.String(), port)
			}
		} else {
			printURLS("http", *interfaceAddr, port)
		}

		go func() {
			laddr := *interfaceAddr + ":" + port
			err := http.ListenAndServe(laddr, certmagic.DefaultACME.HTTPChallengeHandler(mux))
			panic(err)
		}()
		elog.Printf("HTTP listener started")
	}
	if *httpsPort != 0 {
		//tlsConfig := certmagic.NewDefault().TLSConfig()
		tlsConfig, err := certmagic.TLS([]string{*domain})
		checkPanic(err)

		/// XXX to work with OBS studio for now
		if *obsStudio {
			tlsConfig.MinVersion = 0
		}
		port := strconv.Itoa(*httpsPort)

		printURLS("https", *domain, port)

		go func() {
			laddr := *interfaceAddr + ":" + port
			httpsLn, err := tls.Listen("tcp", laddr, tlsConfig)
			checkPanic(err)
			panic(http.Serve(httpsLn, mux))
		}()
		elog.Printf("HTTPS listener started")
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

func initMediaHandlerState(numvideo, numaudio int) {
	log.Printf("Creating %v audio tracks", numaudio)
	for i := 0; i < numaudio; i++ {
		ii := Rxid(i) + Rxid(Audio0)
		rxid2track[ii] = make(map[*Track]struct{})
		pendingSwitch[ii] = make(map[*Track]struct{})
	}
	log.Printf("Creating %v video tracks", numvideo)
	for i := 0; i < numvideo; i++ {
		ii := Rxid(i) + Rxid(Video0)
		rxid2track[ii] = make(map[*Track]struct{})
		pendingSwitch[ii] = make(map[*Track]struct{})
	}
}

func printURLS(proto string, host string, port string) {
	hostport := net.JoinHostPort(host, port)
	if host == "" {
		elog.Println(proto, " is bound to ALL interfaces")
	}

	reportURL("URL for End-user HTML control panel", proto, hostport, "/")

	if *dialIngressURL == "" {
		reportURL("URL for Publisher Ingress API ", proto, hostport, pubPath)
	}
	reportURL("URL for Subscriber Egress API", proto, hostport, subPath)
}

func reportURL(description string, protocol string, hostport string, path string) {
	// we want something like:
	//"Publisher Ingress API URL: http://foo.bar/pub"

	if protocol == "https" {
		hostport = strings.TrimSuffix(hostport, ":443")
	}
	if protocol == "http" {
		hostport = strings.TrimSuffix(hostport, ":80")
	}

	url := fmt.Sprintf("%s://%s%s", protocol, hostport, path)

	elog.Println(url, "   ==> ", description)
}

// ddnsRegisterIPAddresses will register IP addresses to hostnames
// zone might be duckdns.org
// subname might be server01
func ddnsRegisterIPAddresses(provider DDNSProvider, fqdn string, suffixCount int, interfaceAddr string) {
	var addrs []net.IP
	if interfaceAddr != "" {
		addrs = []net.IP{net.ParseIP(interfaceAddr)}
	} else {
		addrs = getDefaultRouteInterfaceAddresses()
	}

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

		log.Println("DDNS setting", fqdn, suffixCount, normalip)
		err := ddnsSetRecord(context.Background(), provider, fqdn, suffixCount, normalip, dnstype)
		checkFatal(err)

		log.Println("DDNS waiting for propagation", fqdn, suffixCount, normalip)
		err = ddnsWaitUntilSet(context.Background(), fqdn, normalip, dnstype)
		checkFatal(err)

		log.Println("DDNS propagation complete", fqdn, suffixCount, normalip)

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

func acmeConfigureProvider(provider interface{}) {
	foo := provider.(certmagic.ACMEDNSProvider)

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
	m := webrtc.MediaEngine{}
	rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(&m))

	//rtcApi = webrtc.NewAPI()
	//if *videoCodec == "h264" {
	if true {
		err := RegisterH264AndOpusCodecs(&m)
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
func subHandler(w http.ResponseWriter, httpreq *http.Request) {
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
		trackNum, err := parseTrackname(rid)
		if err != nil {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. only video<N>, audio<N> are okay"))
			return
		}

		// This isn't required.
		// but nice to tell the HTTP requestor something if the operation can't be executed
		if !foundTxid {
			teeErrorStderrHttp(w, fmt.Errorf("no such sub"))
			return
		}

		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: Subid(txid),
			txid:  Video0, //in v1, we only allow switching of Video0, SFUs don't switch
			rxid:  trackNum,
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

	if !validateSDP(offer) {
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
			txid:            Audio0,
			subid:           Subid(txid),
			track:           track,
			splicer:         &RtpSplicer{},
			rxid:            Rxid(Audio0),
			rxidLastPending: 0,
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
				txid:            Txid(i) + Video0,
				subid:           Subid(txid),
				track:           track,
				splicer:         &RtpSplicer{},
				rxid:            0,
				rxidLastPending: 0,
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

	// Block until ICE Gathering is complete, disabling trickle ICE
	// we do this because we only can exchange one signaling message
	// in a production application you should exchange ICE Candidates via OnICECandidate
	<-gatherComplete

	// Get the LocalDescription and take it to base64 so we can paste in browser
	ansrtcsd := peerConnection.LocalDescription()

	logSdpReport("sub-answer", *ansrtcsd)

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

func validateSDP(rtcsd webrtc.SessionDescription) bool {
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

func idleLoopPlayer(xxx []byte) {

	p, _, err := rtpstuff.ReadPcap2RTP(bytes.NewReader(xxx))
	checkPanic(err)

	n := len(p)
	delta1 := time.Second / time.Duration(n)
	delta2 := uint32(90000 / n)
	mrand.Seed(time.Now().UnixNano())
	seq := uint16(mrand.Uint32())
	ts := mrand.Uint32()

	for {
		for _, v := range p {
			time.Sleep(delta1)
			v.SequenceNumber = seq
			seq++
			v.Timestamp = ts
			// if *logPackets {
			// 	logPacket(logPacketIn, &v)
			// }

			rxMediaCh <- MsgRxPacket{rxid: -1, packet: &v, rxClockRate: 90000}

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
	rtcpBuf := make([]byte, 1500)
	for {
		if _, _, rtcpErr := rtpSender.Read(rtcpBuf); rtcpErr != nil {
			return
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

		inboundTrackReader(track, Rxid(Audio0), track.Codec().ClockRate)
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

	rxid, err := parseTrackname(trackname)
	checkPanic(err)

	if rxid >= Rxid(Audio0) {
		panic("bad trackname got audio, need video")
	}

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, rxid, track.Codec().ClockRate)
	//here on error
	log.Printf("video reader %p exited", track)

}

func parseTrackname(trackname string) (Rxid, error) {
	if strings.HasPrefix(trackname, "video") {
		i, err := strconv.Atoi(strings.TrimPrefix(trackname, "video"))
		if err != nil {
			return -1, fmt.Errorf("bad number after video")
		}

		return Rxid(i) + Rxid(Video0), nil
	}

	if strings.HasPrefix(trackname, "audio") {
		i, err := strconv.Atoi(strings.TrimPrefix(trackname, "audio"))
		if err != nil {
			return -1, fmt.Errorf("bad number after audio")
		}
		return Rxid(i) + Rxid(Audio0), nil
	}

	return -1, fmt.Errorf("need video<N> or audio<N> for track num")
}

func inboundTrackReader(rxTrack *webrtc.TrackRemote, rxid Rxid, clockrate uint32) {

	for {
		p, _, err := rxTrack.ReadRTP()
		if err == io.EOF {
			return
		}
		checkPanic(err)

		rxMediaCh <- MsgRxPacket{rxid: rxid, packet: p, rxClockRate: clockrate}
	}
}

var ticker = time.NewTicker(100 * time.Millisecond)

type Subid uint64

type MsgRxPacket struct {
	rxid        Rxid
	rxClockRate uint32
	packet      *rtp.Packet
}

type Txid int // 0 = video0, 1=video1, 10000=audio0 ...
type Rxid int // 0 = video0, 1=video1, 10000=audio0 ...

// We don't define constants for Video2...Video9999 nor Audio 2...
const (
	Video0 Txid = 0
	//Video1 TrkId = 1
	Audio0 Txid = 10000
	//Audio1 TrkId = 10001
)

type MsgSubscriberAddTrack struct {
	txtrack *Track // can be nil when just changing the channel
}

type MsgSubscriberSwitchTrack struct {
	subid Subid // 64bit subscriber key
	txid  Txid  // track number from subscriber's perspective
	rxid  Rxid  // where txid will get it's input from
}

var rxMediaCh chan MsgRxPacket = make(chan MsgRxPacket, 10)
var subAddTrackCh chan MsgSubscriberAddTrack = make(chan MsgSubscriberAddTrack, 10)
var subSwitchTrackCh chan MsgSubscriberSwitchTrack = make(chan MsgSubscriberSwitchTrack, 10)

// type Subscriber struct {
// 	txTracks []*Track
// }
// var zz map[Subid]Subscriber = make(map[Subid]Subscriber)

// reviewed
type RtpSplicer struct {
	debugName        string
	lastSSRC         uint32
	lastSN           uint16
	lastTS           uint32
	lastUnixnanosNow int64
	snOffset         uint16
	tsOffset         uint32
}

type Track struct {
	subid           Subid // 64bit subscriber key
	txid            Txid  // track number from subscriber's perspective
	rxid            Rxid
	rxidLastPending Rxid
	track           *webrtc.TrackLocalStaticRTP
	splicer         *RtpSplicer
}

/*
It has seemed at times that using arrays instead of maps
would be simpler (and faster).
The nice thing about maps, is the individual elements can be deleted.
*/

// subid to txid to track
// used mainly to handle control messages from http handlers
var sub2txid2track map[Subid]map[Txid]*Track = make(map[Subid]map[Txid]*Track)

// rxid to list of txtrack
// mainly for distributing received packets
// we could use array for first component if we compressed Rxid space
var _ = *numVideoTracks + *numAudioTracks // determines the max value for first component of type
// someday?: var [Rxid]map[*Track]struct{} = make(map[Rxid]map[*Track]struct{})
var rxid2track map[Rxid]map[*Track]struct{} = make(map[Rxid]map[*Track]struct{})

// list of txtracks waiting for a keyframe in order to switch input/rx
// while this shares the same type as rxid2track, they cannot be joined
var pendingSwitch map[Rxid]map[*Track]struct{} = make(map[Rxid]map[*Track]struct{})

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

		if trackList, ok := pendingSwitch[m.rxid]; ok {

			isaudio := m.rxid > Rxid(Audio0)
			if !isaudio {
				if !rtpstuff.IsH264Keyframe(m.packet.Payload) {
					goto finished_switches
				}
			}

			for tr := range trackList {

				//remove the current entry
				delete(rxid2track[tr.rxid], tr)

				// rxid2track[] entries get created after flag.parse()

				if _, ok := rxid2track[m.rxid]; !ok {
					//no	rxid2track[m.rxid] = make(map[*Track]struct{})
					panic("bad index for rxid2track, should not be in pending list")
				}

				// save the track
				rxid2track[m.rxid][tr] = struct{}{}

				//update the track
				tr.rxid = m.rxid //overwrite old value

			}

			//remove the set of tracks pending on m.rxid
			for k := range pendingSwitch[m.rxid] { // optimized: https://golang.org/doc/go1.11#performance-compiler
				delete(pendingSwitch[m.rxid], k)
			}

		}

	finished_switches:

		trackList := rxid2track[m.rxid]

		for tr := range trackList {
			var packet *rtp.Packet = m.packet
			var ipacket interface{}

			if tr.splicer != nil {

				ipacket = rtpPacketPool.Get()
				packet = ipacket.(*rtp.Packet)
				*packet = *m.packet
				SpliceRTP(tr.splicer, packet, time.Now().UnixNano(), int64(m.rxClockRate))
			}

			if !disableWriteRTP {
				err := tr.track.WriteRTP(packet)
				if err == io.ErrClosedPipe {
					log.Printf("track io.ErrClosedPipe, removing track %v %v %v", tr.subid, tr.txid, tr.rxid)
					removeTrack(tr)
				}
			}

			if tr.splicer != nil {
				*packet = rtp.Packet{}
				rtpPacketPool.Put(ipacket)
			}
		}

	case m := <-subAddTrackCh:

		if m.txtrack == nil {
			panic("fail")
		}

		tr := m.txtrack

		if _, ok := sub2txid2track[tr.subid]; !ok {
			sub2txid2track[tr.subid] = make(map[Txid]*Track)
		}

		sub2txid2track[tr.subid][tr.txid] = tr

		if _, ok := rxid2track[tr.rxid]; !ok {
			rxid2track[tr.rxid] = make(map[*Track]struct{})
		}

		rxid2track[tr.rxid][m.txtrack] = struct{}{}

	case m := <-subSwitchTrackCh:

		// state checklist, do not remove
		_ = sub2txid2track // no change!
		_ = rxid2track     // no change! this gets updated on new media
		_ = pendingSwitch  // this gets new entry for switch

		// pendingTrackChange
		txid2track, ok := sub2txid2track[m.subid]
		if ok {
			track := txid2track[m.txid]

			// remove the last entry we put in the pendingSwitch queue, if any
			delete(pendingSwitch[track.rxidLastPending], track)

			// make note of the new requested RXID
			// incase we need to delete it again
			track.rxidLastPending = m.rxid

			// check validity of m.rxid
			//if this track wasn't ADDED we can't switch it.
			if _, ok := rxid2track[m.rxid]; !ok {
				elog.Printf("bad: bad switch msg for rxid %d, not present1", m.rxid)
				break
			}

			if _, ok := pendingSwitch[m.rxid]; !ok {
				elog.Printf("bad: bad switch msg for rxid %d, not present2", m.rxid)
				break
			}

			pendingSwitch[m.rxid][track] = struct{}{}

		} else {
			elog.Printf("bad: invalid subid 0x%x", m.subid)
		}

		// txtrack/nochange
		// subid2Track/nochange
		// currentRxid/nochange

	case tk := <-ticker.C:
		_ = tk
		//fmt.Println("Tick at", tk)
	}
}

// removeTrack will remove all references to a track
// io.ErrClosedPipe on WriteRTP() is main cause
func removeTrack(t *Track) {
	//state checklist
	_ = sub2txid2track //affected
	_ = rxid2track     //affected
	_ = pendingSwitch  //affected

	delete(sub2txid2track[t.subid], t.txid)
	delete(rxid2track[t.rxid], t)
	delete(pendingSwitch[t.rxidLastPending], t)
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
		elog.Fatal("cant find any IP addresses")
	}

	return ipaddrs
}

func getDefRouteIntfAddrIPv6() net.IP {
	const googleDNSIPv6 = "[2001:4860:4860::8888]:8080"
	cc, err := net.Dial("udp6", googleDNSIPv6)
	if err == nil {
		defer cc.Close()
		return cc.LocalAddr().(*net.UDPAddr).IP
	}
	return nil
}

func getDefRouteIntfAddrIPv4() net.IP {
	const googleDNSIPv4 = "8.8.8.8:8080"
	cc, err := net.Dial("udp4", googleDNSIPv4)
	if err == nil {
		defer cc.Close()
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
		log.Printf("SpliceRTP: %v: ssrc changed new=%v cur=%v", s.debugName, o.SSRC, s.lastSSRC)

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
