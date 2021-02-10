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

	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/x186k/sfu1net"

	"github.com/caddyserver/certmagic"

	"github.com/pkg/browser"
	"github.com/pkg/profile"
	"github.com/x186k/sfu1/rtpsplice"
	"golang.org/x/sync/semaphore"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"

	_ "embed"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"
)

// content is our static web server content.
//go:embed html/index.html
var indexHtml []byte

//go:embed lfs/idle.screen.h264.pcapng
var idleScreenH264Pcapng []byte

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
	},
}

var myMetrics struct {
	dialConnectionRefused uint64
}

// https://tools.ietf.org/id/draft-ietf-mmusic-msid-05.html
// msid:streamid trackid/appdata
// per RFC appdata is "application-specific data", we use a/b/c for simulcast
const mediaStreamId = "x186k"

var (
	h264IdleRtpPackets           []rtp.Packet           // concurrent okay
	videoMimeType                string                 = "video/h264"
	audioMimeType                string                 = "audio/opus"
	subMap                       map[string]*Subscriber = make(map[string]*Subscriber) // concurrent okay 013121
	subMapMutex                  sync.Mutex                                            // concurrent okay 013121	//audioTrack                   *webrtc.TrackLocalStaticRTP                                      // concurrent okay 013121
	video1, video2, video3       *SplicableTrack                                       // Downstream SFU shared tracks
	audio                        *SplicableTrack
	ingressSemaphore             = semaphore.NewWeighted(int64(1)) // concurrent okay
	lastTimeIngressVideoReceived int64                             // concurrent okay
)

type SplicableTrack struct {
	track   *webrtc.TrackLocalStaticRTP
	splicer rtpsplice.RtpSplicer
}

//XXXXXXXX fixme add time & purge occasionally
type Subscriber struct {
	conn         *webrtc.PeerConnection // peerconnection
	browserVideo *SplicableTrack        // will be nil for sfu, non-nil for browser, browser needs own seqno+ts for rtp, thus this
	xsource      rtpsplice.RtpSource
}

func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func checkFatal(err error) {
	if err != nil {
		elog.Fatal(err)
	}
}

func slashHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/html")

	if req.URL.Path != "/" {
		http.Error(res, "404 - page not found", http.StatusNotFound)
		return
	}

	//XXX fix
	if true || len(indexHtml) == 0 {
		buf, err := ioutil.ReadFile("html/index.html")
		if err != nil {
			http.Error(res, "can't open index.html", http.StatusInternalServerError)
			return
		}
		_, _ = res.Write(buf)
	} else {
		_, _ = res.Write(indexHtml)
	}
}

//var silenceJanus = flag.Bool("silence-janus", false, "if true will throw away janus output")
var debug = flag.Bool("debug", false, "enable debug output")
var cpuprofile = flag.Int("cpu-profile", 0, "number of seconds to run + turn on profiling")
var logPackets = flag.Bool("log-packets", false, "log packets for later use with text2pcap")
var logSplicer = flag.Bool("log-splicer", false, "log rrp splicing debug info")

// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
var nohtml = flag.Bool("no-html", false, "do not serve any html files, only do WHIP")
var dialIngressURL = flag.String("dial-ingress", "", "do not take http WHIP for ingress, dial for ingress")
var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")
var listenHTTPS = flag.String("https", "", "HTTPS listener address of the form \"host:port\", details: Go:net.Dial()")
var listenHTTP = flag.String("http", "", "HTTP listener address of the form \"host:port\", details: Go:net.Dial()")
var domain = flag.String("domain", "", "Explicit override domain name to use for Let's Encrypt certificate")
var openTab = flag.Bool("opentab", false, "Open a browser tab to the pub/sub panel")
var cloudflareDDNS = flag.Bool("ddns-cloudflare", false, "Use Cloudflare for Dynamic DNS. env token in CLOUDFLARE_TOKEN")
var duckdnsDDNS = flag.Bool("ddns-duckdns", false, "Use Duckdns for Dynamic DNS. env token in DUCKDNS_TOKEN")
var sfu1netDDNS = flag.Bool("ddns-sfu1net", false, "Use sfu1.net for Dynamic DNS. env token in SFU1NET_TOKEN")

var logPacketIn = log.New(os.Stdout, "I ", log.Lmicroseconds|log.LUTC)
var logPacketOut = log.New(os.Stdout, "O ", log.Lmicroseconds|log.LUTC)

var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)

func init() {
	var err error

	audio = &SplicableTrack{splicer: rtpsplice.RtpSplicer{Name: "audio"}}
	video1 = &SplicableTrack{splicer: rtpsplice.RtpSplicer{Name: "vid1"}}
	video2 = &SplicableTrack{splicer: rtpsplice.RtpSplicer{Name: "vid2"}}
	video3 = &SplicableTrack{splicer: rtpsplice.RtpSplicer{Name: "vid3"}}

	// Create a audio track
	audio.track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	checkPanic(err)
	video1.track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video0", mediaStreamId)
	checkPanic(err)
	video2.track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video1", mediaStreamId)
	checkPanic(err)
	video3.track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video2", mediaStreamId)
	checkPanic(err)

	h264IdleRtpPackets, _, err = rtpsplice.ReadPcap2RTP(bytes.NewReader(idleScreenH264Pcapng))
	checkPanic(err)

	go idleLoopPlayer(h264IdleRtpPackets, video1, video2, video3)
	go pollingVideoSourceController()
	go oncePerSecond()

}

func oncePerSecond() {
	n := runtime.NumGoroutine()
	for {
		time.Sleep(time.Second)
		nn := runtime.NumGoroutine()
		if nn != n {
			log.Println("NumGoroutine", nn)
			n = nn
		}
	}
}

func main() {

	var err error

	flag.Parse()

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

	mux := http.NewServeMux()

	pubPath := "/pub"
	subPath := "/sub" // 2nd slash important

	if !*nohtml {
		mux.HandleFunc("/", slashHandler)
	}
	mux.HandleFunc(subPath, subHandler)

	var ln net.Listener
	httpType := ""
	host := ""
	port := ""

	if *listenHTTPS != "" {
		host, port, err = net.SplitHostPort(*listenHTTPS)
		checkFatal(err)

		//certmagic.DefaultACME.Agreed = true
		//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA // XXXXXXXXXXX

		if *cloudflareDDNS {
			cloudflareConfigure()
		}

		if *duckdnsDDNS {
			duckdnsConfigure()
		}

		if *sfu1netDDNS {
			sfu1netConfigure()
		}

		if *domain != "" {
			host = *domain
		}
		// We do NOT do port 80 redirection, as certmagic.HTTPS()
		tlsConfig, err := certmagic.TLS([]string{host})
		checkPanic(err)
		/// XXX ro work with OBS studio for now
		tlsConfig.MinVersion = 0

		ln, err = tls.Listen("tcp", *listenHTTPS, tlsConfig)
		checkPanic(err)
		httpType = "https"
	} else if *listenHTTP != "" {
		host, port, err = net.SplitHostPort(*listenHTTP)
		checkPanic(err)

		ln, err = net.Listen("tcp", *listenHTTP)
		checkPanic(err)
		httpType = "http"
	}

	browserUrl := fmt.Sprintf("%s://%s:%s%s", httpType, host, port, "/")

	elog.Printf("Browser HTML URL: %v", browserUrl)

	if *dialIngressURL == "" {
		elog.Printf("Publisher API URL: %s://%s:%s%s", httpType, host, port, pubPath)
		mux.HandleFunc(pubPath, pubHandler)
	} else {
		elog.Printf("Publisher API URL: none")
		go func() {
			for {
				err = ingressSemaphore.Acquire(context.Background(), 1)
				checkPanic(err)
				log.Println("dial: got sema, dialing upstream")
				dialUpstream(*dialIngressURL)
			}
		}()
	}
	elog.Printf("Subscriber API URL: %s://%s:%s%s", httpType, host, port, subPath)
	elog.Printf("Bound listener interface address: %s", ln.Addr().String())

	go func() {
		err = http.Serve(ln, mux)
		panic(err)
	}()

	if *openTab {
		_ = browser.OpenURL(browserUrl)
	}

	if *cpuprofile == 0 {
		select {}
	}

	println("profiling enabled, runtime seconds:", *cpuprofile)

	defer profile.Start(profile.CPUProfile).Stop()

	time.Sleep(time.Duration(*cpuprofile) * time.Second)

	println("profiling done, exit")
}

func duckdnsConfigure() {
	duckdnsToken := os.Getenv("DUCKDNS_TOKEN")
	if duckdnsToken == "" {
		elog.Fatal("DUCKDNS_TOKEN environment variable not found")
	} else {
		log.Printf("DUCKDNS_TOKEN environment variable found")

		dnsProvider := duckdns.Provider{APIToken: duckdnsToken}

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider:        &dnsProvider,
			TTL:                0,
			PropagationTimeout: 0,
			Resolvers:          []string{},
		}
	}
}

func cloudflareConfigure() {
	cloudflareToken := os.Getenv("CLOUDFLARE_TOKEN")

	if cloudflareToken == "" {
		elog.Fatal("CLOUDFLARE_TOKEN environment variable not found")
	} else {
		log.Println("CLOUDFLARE_TOKEN environment variable found")

		dnsProvider := cloudflare.Provider{APIToken: cloudflareToken}

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider:        &dnsProvider,
			TTL:                0,
			PropagationTimeout: 0,
			Resolvers:          []string{},
		}
	}
}

func sfu1netConfigure() {
	token := os.Getenv("SFU1NET_TOKEN")

	if token == "" {
		elog.Fatal("SFU1NET_TOKEN environment variable not found")
	} else {
		log.Println("SFU1NET_TOKEN environment variable found")

		dnsProvider := sfu1net.Provider{APIToken: token}

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider:        &dnsProvider,
			TTL:                0,
			PropagationTimeout: 0,
			Resolvers:          []string{},
		}
	}
}

func newPeerConnection() *webrtc.PeerConnection {
	// Do NOT share MediaEngine between PC!  BUG of 020321
	// with Sean & Orlando. They are so nice.
	m := webrtc.MediaEngine{}
	rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(&m))

	//rtcApi = webrtc.NewAPI()
	if *videoCodec == "h264" {
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
func subHandler(w http.ResponseWriter, httpreq *http.Request) {
	defer httpreq.Body.Close()

	log.Println("subHandler request", httpreq.URL.String())

	txid := httpreq.URL.Query().Get("txid")
	if txid == "" {
		teeErrorStderrHttp(w, fmt.Errorf("txid missing"))
		return
	}

	if len(txid) < 15 {
		teeErrorStderrHttp(w, fmt.Errorf("txid value must be 15 chars or more"))
		return
	}

	log.Println("txid is", txid)

	rid := httpreq.URL.Query().Get("level")
	issfu := httpreq.URL.Query().Get("issfu") != ""

	if rid != "" {
		if rid != "video0" && rid != "video1" && rid != "video2" {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. only video-a,video-b,video-c are valid"))
			return
		}

		subMapMutex.Lock()
		sub, ok := subMap[txid]
		subMapMutex.Unlock()
		if !ok {
			teeErrorStderrHttp(w, fmt.Errorf("no such sub"))
			return
		}

		if sub.browserVideo == nil {
			teeErrorStderrHttp(w, fmt.Errorf("rid param not meaningful for SFU"))
			return
		}

		switch rid {
		case "video0":
			sub.xsource = rtpsplice.Video1
		case "video1":
			sub.xsource = rtpsplice.Video2
		case "video2":
			sub.xsource = rtpsplice.Video3
		}

		// XXX
		//sub.requestedRID = rid
		w.WriteHeader(http.StatusAccepted)
		return
	} else {
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

		subMapMutex.Lock()
		_, ok := subMap[txid]
		subMapMutex.Unlock()
		if ok {
			teeErrorStderrHttp(w, fmt.Errorf("cannot re-use or re-nego subscriber"))
			return
		}

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
		peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
			log.Println("subscriber Connection State has changed", cs.String())
			switch cs {
			case webrtc.PeerConnectionStateConnected:
			case webrtc.PeerConnectionStateFailed:
				peerConnection.Close()
			case webrtc.PeerConnectionStateDisconnected:
				peerConnection.Close()
			case webrtc.PeerConnectionStateClosed:
				subMapMutex.Lock()
				delete(subMap, txid)
				subMapMutex.Unlock()
			}
		})

		offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdpbytes)}
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

		//should be 1 from browser sub
		//should be 3 from x186k sfu
		numvideo := numVideoMediaDesc(sdsdp)
		log.Println("numvideo", numvideo)

		sub := &Subscriber{}
		sub.conn = peerConnection

		if !issfu {
			// browser path
			sub.browserVideo = &SplicableTrack{}
			sub.browserVideo.track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "subvideo", mediaStreamId)
			checkPanic(err)

			if ingressVideoIsHappy() {
				sub.xsource = rtpsplice.Video1
				sub.browserVideo.splicer.Pending = rtpsplice.Video1
			} else {
				sub.xsource = rtpsplice.Idle
				sub.browserVideo.splicer.Pending = rtpsplice.Idle
			}

			// 020221 The transceivers should already be okay, no addtransceiver is needed.
			//there should already be 2x recvonly transceivers (recv from offerer's perspective,not mine)

			// We do need an add-track to associate the track with the pc/transceiver

			// mdn: addTrack() adds a new media track to the set of
			//   tracks which will be transmitted to the other peer.

			// trans,err:=sub.conn.AddTransceiverFromTrack(audioTrack,webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
			// checkPanic(err)
			// go processRTCP(trans.Sender())

			//will associate or create new tx/rtpsender in pc
			rtpSender, err := sub.conn.AddTrack(audio.track)
			checkPanic(err)
			go processRTCP(rtpSender)

			//will associate or create new tx/rtpsender in pc
			rtpSender, err = sub.conn.AddTrack(sub.browserVideo.track)
			checkPanic(err)
			go processRTCP(rtpSender)

			logTransceivers("tracksadd", peerConnection)

		} else {
			// sfu path
			sub.browserVideo = nil

			//will associate or create new tx/rtpsender in pc
			rtpSender, err := sub.conn.AddTrack(audio.track)
			checkPanic(err)
			go processRTCP(rtpSender)

			//will associate or create new tx/rtpsender in pc
			rtpSender, err = sub.conn.AddTrack(video1.track)
			checkPanic(err)
			go processRTCP(rtpSender)

			//will associate or create new tx/rtpsender in pc
			rtpSender, err = sub.conn.AddTrack(video2.track)
			checkPanic(err)
			go processRTCP(rtpSender)

			//will associate or create new tx/rtpsender in pc
			rtpSender, err = sub.conn.AddTrack(video3.track)
			checkPanic(err)
			go processRTCP(rtpSender)
		}

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
		_, _ = w.Write([]byte(ansrtcsd.SDP))

		subMapMutex.Lock()
		subMap[txid] = sub
		subMapMutex.Unlock()

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

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func ingressVideoIsHappy() bool {
	const maxTimeNoVideo = int64(float64(time.Second) * 1.5)
	t := atomic.LoadInt64(&lastTimeIngressVideoReceived)
	happy := (time.Now().UnixNano() - t) < maxTimeNoVideo
	return happy
}

func changeSourceIfNeeded(spv *SplicableTrack, src rtpsplice.RtpSource) {
	if spv.splicer.Active != src && spv.splicer.Pending != src {
		spv.splicer.Pending = src
	}
}

func pollingVideoSourceController() {

	changeSourceIfNeeded(audio, rtpsplice.Audio)

	for {
		time.Sleep(time.Millisecond * 100) // polling somewhere for lack of rx rtp is unavoidable

		// downstream sfu business
		if ingressVideoIsHappy() {
			changeSourceIfNeeded(audio, rtpsplice.Audio)
			changeSourceIfNeeded(video1, rtpsplice.Video1)
			changeSourceIfNeeded(video2, rtpsplice.Video2)
			changeSourceIfNeeded(video3, rtpsplice.Video3)
		} else {
			changeSourceIfNeeded(video1, rtpsplice.Idle)
			changeSourceIfNeeded(video2, rtpsplice.Idle)
			changeSourceIfNeeded(video3, rtpsplice.Idle)
		}

		// downstream browser business
		subMapMutex.Lock()
		for _, sub := range subMap {
			subMapMutex.Unlock()

			if sub.browserVideo != nil {
				if ingressVideoIsHappy() {
					changeSourceIfNeeded(sub.browserVideo, sub.xsource)
				} else {
					//not happy
					changeSourceIfNeeded(sub.browserVideo, rtpsplice.Idle)
				}
			}

			subMapMutex.Lock()
		}
		subMapMutex.Unlock()

	}

}

func idleLoopPlayer(p []rtp.Packet, tracks ...*SplicableTrack) {
	n := len(p)
	delta1 := time.Second / time.Duration(n)
	delta2 := uint32(90000 / n)
	seq := uint16(mrand.Uint32())
	ts := mrand.Uint32()

	if tracks[0].track == nil {
		panic(888)
	}
	if tracks[1].track == nil {
		panic(888)
	}
	if tracks[2].track == nil {
		panic(888)
	}

	for {
		for _, v := range p {
			time.Sleep(delta1)
			v.SequenceNumber = seq
			seq++
			v.Timestamp = ts
			if *logPackets {
				logPacket(logPacketIn, &v)
			}
			// subscribers
			sendRTPToEachSubscriber(&v, rtpsplice.Idle)

			// sfus
			for _, splicable := range tracks {

				if splicable.splicer.IsActiveOrPending(rtpsplice.Idle) {
					pprime := splicable.splicer.SpliceRTP(&v, rtpsplice.Idle, time.Now().UnixNano(), int64(90000), rtpsplice.H264)
					if pprime != nil {
						err := LogAndWriteRTP(pprime, &v, splicable)
						if err == io.ErrClosedPipe {
							return
						}
						checkPanic(err)
					}
				}
			}
		}
		ts += delta2
	}

}

func dialUpstream(baseurl string) {

	txid, err := randomHex(10)
	checkPanic(err)
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
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkPanic(err)

	// Create an offer to send to the other process
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		panic(err)
	}

	logSdpReport("dialupstream-offer", offer)

	// Sets the LocalDescription, and starts our UDP listeners
	// Note: this will start the gathering of ICE candidates
	if err = peerConnection.SetLocalDescription(offer); err != nil {
		panic(err)
	}

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

	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		// forever loop
		for {
			p, _, err := track.ReadRTP()
			if err == io.EOF {
				return
			}
			checkPanic(err)

			if audio.splicer.IsActiveOrPending(rtpsplice.Audio) {
				pprime := audio.splicer.SpliceRTP(p, rtpsplice.Audio, time.Now().UnixNano(), int64(track.Codec().ClockRate), rtpsplice.Opus)
				if pprime != nil {
					err := LogAndWriteRTP(pprime, p, audio)
					if err == io.ErrClosedPipe {
						return
					}
					checkPanic(err)
				}
			}
		}
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

	var rtpsource rtpsplice.RtpSource
	switch trackname {
	case "video0":
		rtpsource = rtpsplice.Video1
	case "video1":
		rtpsource = rtpsplice.Video2
	case "video2":
		rtpsource = rtpsplice.Video3
	}

	var splicable *SplicableTrack
	switch trackname {
	case "video0":
		splicable = video1
	case "video1":
		splicable = video2
	case "video2":
		splicable = video3
	}

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	for {
		// Read RTP packets being sent to Pion
		//fmt.Println(99,rid)
		packet, _, err := track.ReadRTP()
		if err == io.EOF {
			return
		}
		checkPanic(err)

		// if lastts != packet.Timestamp && trackname == "a" {
		// 	log.Println("xts", packet.Timestamp-lastts)
		// 	lastts = packet.Timestamp
		// }

		atomic.StoreInt64(&lastTimeIngressVideoReceived, time.Now().UnixNano())

		if *logPackets {
			logPacket(logPacketIn, packet)
		}

		if splicable.splicer.IsActiveOrPending(rtpsource) {
			pprime := splicable.splicer.SpliceRTP(packet, rtpsource, time.Now().UnixNano(), int64(track.Codec().ClockRate), rtpsplice.H264)
			if pprime != nil {
				err := LogAndWriteRTP(pprime, packet, splicable)
				if err == io.ErrClosedPipe {
					return
				}
				checkPanic(err)
			}
		}

		// send video to subscribing Browsers
		sendRTPToEachSubscriber(packet, rtpsource)

	}
}

func sendRTPToEachSubscriber(p *rtp.Packet, src rtpsplice.RtpSource) {

	/* pseudo code

	if ingress == simulcast {
		for s := range subscribers {
			if s.type == Browser {
					forward selected 1 of 3 input to sub.simuTrack
			}
		}
	}

	for o := range outputtracks {
		write to localVidTracks
	}

	*/

	// for each subscriber

	subMapMutex.Lock()
	for _, sub := range subMap {
		subMapMutex.Unlock()

		if sub.browserVideo != nil {
			if sub.browserVideo.splicer.IsActiveOrPending(src) {
				pprime := sub.browserVideo.splicer.SpliceRTP(p, src, time.Now().UnixNano(), int64(90000), rtpsplice.H264)
				if pprime != nil {
					err := LogAndWriteRTP(pprime, p, sub.browserVideo)
					if err == io.ErrClosedPipe {
						return
					}
					checkPanic(err)
				}
			}
		}

		subMapMutex.Lock()
	}
	subMapMutex.Unlock()
}

func LogAndWriteRTP(pprime *rtp.Packet, original *rtp.Packet, splicable *SplicableTrack) error {
	if *logPackets {
		logPacket(logPacketOut, pprime)
	}
	if *logSplicer {
		logPacketOut.Println("splicerx", splicable.splicer.Active, splicable.splicer.Pending, original.SSRC, original.Timestamp, original.SequenceNumber, rtpsplice.ContainSPS(original.Payload))
		logPacketOut.Println("splicetx", splicable.splicer.Active, splicable.splicer.Pending, pprime.SSRC, pprime.Timestamp, pprime.SequenceNumber, rtpsplice.ContainSPS(pprime.Payload),
			pprime.Timestamp <= original.Timestamp)
	}

	return splicable.track.WriteRTP(pprime)
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
