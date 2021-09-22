package main

//force new build

import (
	"archive/zip"
	"bytes"
	"context"
	"embed"
	"errors"
	"math/rand"
	"net"
	"strconv"

	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"path/filepath"
	"runtime"
	"sync"

	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/pkg/profile"
	"golang.org/x/sync/semaphore"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"

	"github.com/x186k/ftlserver"

	"github.com/cameronelliott/redislock"
	redislockx "github.com/cameronelliott/redislock/examples/redigo/redisclient"
	redigo "github.com/gomodule/redigo/redis"
)

var lastVideoRxTime time.Time

var sendingIdleVid bool

var redisPool *redigo.Pool
var redisLocker *redislock.Client

//go:embed html/*
var htmlContent embed.FS

//go:embed deadsfu-binaries/idle-clip.zip
var idleClipZipBytes []byte

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

//XXX remove
var _ = &rtpPacketPool

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
	videoMimeType = "video/h264"
	audioMimeType = "audio/opus"
	pubPath       = "/pub"
	subPath       = "/sub" // 2nd slash important
)

var ingressSemaphore = semaphore.NewWeighted(int64(1)) // concurrent okay
var mediaDebugTickerChan = make(<-chan time.Time)
var mediaDebug = false

type MsgRxPacket struct {
	rxid        TrackId
	rxClockRate uint32
	packet      *rtp.Packet
}
type MsgSubscriberAddTrack struct {
	txtrack *TxTrack
}

var rxMediaCh chan MsgRxPacket = make(chan MsgRxPacket, 10)
var subAddTrackCh chan MsgSubscriberAddTrack = make(chan MsgSubscriberAddTrack, 10)

//var rxidStateCh chan MsgGetRxidState = make(chan MsgGetRxidState)

// size optimized, not readability
type RtpSplicer struct {
	lastUnixnanosNow int64
	lastSSRC         uint32
	lastTS           uint32
	tsOffset         uint32
	lastSN           uint16
	snOffset         uint16
}

type TrackId int32

const (
	IdleVideo  TrackId = 0
	Video      TrackId = iota
	Audio      TrackId = iota
	Data       TrackId = iota
	NumTrackId         = iota
)

// size optimized, not readability
type TxTrack struct {
	track   *webrtc.TrackLocalStaticRTP
	splicer *RtpSplicer
	txid    TrackId
}

var txtracks []*TxTrack

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

var _ = pline

func pline() {
	_, fileName, fileLine, _ := runtime.Caller(1)
	fmt.Println("pline:", filepath.Base(fileName), fileLine)
}

var Version = "version-unset"

// var urlsFlag urlset
// const urlsFlagName = "urls"
// const urlsFlagUsage = "One or more urls for HTTP, HTTPS. Use commas to seperate."

// Docker,systemd have Stdin from null, so there is no explicit prompt for ACME terms.
// Just like Caddy under Docker and Caddy under Systemd

// var logPacketIn = log.New(os.Stdout, "I ", log.Lmicroseconds|log.LUTC)
// var logPacketOut = log.New(os.Stdout, "O ", log.Lmicroseconds|log.LUTC)

// This should allow us to use checkFatal() more, and checkFatal() less
var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC|log.Lshortfile)
var medialog = log.New(io.Discard, "", 0)
var ddnslog = log.New(io.Discard, "", 0)

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

// var pcapFile *os.File
// var pcapWr *pcapgo.Writer
var rtpoutConn *net.UDPConn

//var startTime time.Time = time.Now()

// should this be 'init' or 'initXXX'
// if we want this func to be called everyttime we run tests, then
// it should be init(), otherwise initXXX()
// I suppose testing in this package/dir should be related to the
// running SFU engine, so we use 'init()'
// But! this means we need to determine if we are a test or not,
// so we can not call flag.Parse() or not
func init() {

	if _, err := htmlContent.ReadFile("html/index.html"); err != nil {
		panic("index.html failed to embed correctly")
	}

	istest := strings.HasSuffix(os.Args[0], ".test")
	if !istest {
		parseAndHandleFlags()
	}

	go logGoroutineCountToDebugLog()

	go idleLoopPlayer()

	// XXX msgLoop touches rxid2state, so we have 2 GR touching a map
	// but, let's be honest, it's the only toucher of rxid2state after this point
	// so, probably okay
	go msgLoop()
}

func newRedisPool() {

	url := os.Getenv("REDIS_URL")
	if url == "" {
		checkFatal(fmt.Errorf("REDIS_URL must be set for cluster mode"))
	}

	redisPool = &redigo.Pool{
		MaxIdle:     3,
		IdleTimeout: 5 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		DialContext: func(ctx context.Context) (redigo.Conn, error) {
			return DialURLContext(ctx, url)
		},
	}

	// threadsafe
	redisLocker = redislock.New(redislockx.NewRedisLockClient(redisPool))
}

func main() {
	var err error

	ctx := context.Background()

	println("deadsfu Version " + Version)

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
			checkFatal(err)
		}

		mux.Handle("/", http.FileServer(http.FS(f)))
		mux.HandleFunc("/ipv4", func(rw http.ResponseWriter, r *http.Request) {
			x, err := getDefRouteIntfAddrIPv4()
			if err == nil {
				_, _ = rw.Write([]byte(x.String()))
			}
		})
		mux.HandleFunc("/ipv6", func(rw http.ResponseWriter, r *http.Request) {
			x, err := getDefRouteIntfAddrIPv6()
			if err == nil {
				_, _ = rw.Write([]byte(x.String()))
			}
		})

	}
	mux.HandleFunc(subPath, SubHandler)

	dialingout := *dialIngressURL != ""

	if !dialingout {
		mux.HandleFunc(pubPath, pubHandler)
	}

	// if *clusterMode && *httpsDomain == "" {
	// 	elog.Fatalln("--https-domain must be used with --cluster--mode")
	// 	os.Exit(0)
	// }

	if *httpFlag == "" && *httpsDomain == "" {
		Usage()
		os.Exit(-1)
	}
	if *clusterMode {
		newRedisPool()
	}

	if *ftlKey != "" {

		ftludp, err := net.ListenPacket("udp", ":0")
		checkFatal(err)
		defer ftludp.Close()
		ftlport := ftludp.(*net.UDPConn).LocalAddr().(*net.UDPAddr).Port

		if *clusterMode {

			privateip := getMyIPFromRedis(ctx)

			go clusterFtlReceive(ctx, ftludp) //recieve udp loop

			go clusterFtlRedisRegister(ctx, privateip, ftlport) // register with redis loop

		} else {

			go startFtlListener(elog, log.Default())

		}

	}

	// https
	if *httpsDomain != "" {

		_, port, err := net.SplitHostPort(*httpsDomain)
		checkFatal(err)
		ln, err := net.Listen("tcp", ":"+port)
		checkFatal(err)

		if *clusterMode {

			port := ln.(*net.TCPListener).Addr().(*net.TCPAddr).Port
			privateip := getMyIPFromRedis(ctx)
			go clusterHttpsRedisRegister(ctx, *httpsDomain, privateip, port)

		}

		go startHttpsListener(ln, *httpsDomain, mux)

		elog.Println("SFU HTTPS IS READY ON", ln.Addr())

	}

	go func() {
		if *httpsDomain != "" {
			a := certmagic.DefaultACME.HTTPChallengeHandler(mux)
			panic(http.ListenAndServe(*httpFlag, a))
		} else {
			panic(http.ListenAndServe(*httpFlag, mux))
		}
	}()

	elog.Printf("SFU HTTP IS READY")

	//the user can specify zero for port, and Linux/etc will choose a port

	if *dialIngressURL != "" {
		elog.Printf("Publisher Ingress API URL: none (using dial)")
		go func() {
			for {
				err = ingressSemaphore.Acquire(context.Background(), 1)
				checkFatal(err)
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

func newPeerConnection() *webrtc.PeerConnection {

	// Do NOT share MediaEngine between PC!  BUG of 020321
	// with Sean & Orlando. They are so nice.
	m := &webrtc.MediaEngine{}

	i := &interceptor.Registry{}
	_ = i
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		panic(err)
	}

	se := webrtc.SettingEngine{}

	if *iceCandidateHost != "" {
		se.SetNAT1To1IPs([]string{*iceCandidateHost}, webrtc.ICECandidateTypeHost)
	}
	if *iceCandidateSrflx != "" {
		se.SetNAT1To1IPs([]string{*iceCandidateSrflx}, webrtc.ICECandidateTypeSrflx)
		peerConnectionConfig.ICEServers = []webrtc.ICEServer{} // yuck
	}

	//rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i))
	rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithSettingEngine(se))

	//rtcApi = webrtc.NewAPI()
	//if *videoCodec == "h264" {
	if true {
		err := RegisterH264AndOpusCodecs(m)
		checkFatal(err)
	} else {
		log.Fatalln("only h.264 supported")
		// err := m.RegisterDefaultCodecs()
		// checkFatal(err)
	}

	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	checkFatal(err)

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

	log.Println("pubHandler request", req.URL.String(), req.Header.Get("Content-Type"))

	if handlePreflight(req, w) {
		return
	}

	requireStrictWISH := false
	if requireStrictWISH {
		if req.Header.Get("Content-Type") != "application/sdp" {
			teeErrorStderrHttp(w, fmt.Errorf("Content-Type==application/sdp required on /pub"))
			return
		}
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
	checkFatal(err) // cam/if this write fails, then fail hard!

	//NOTE, Do NOT ever use http.error to return SDPs
}

func handlePreflight(req *http.Request, w http.ResponseWriter) bool {
	if req.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusAccepted)

		return true
	}

	//put this on every request
	w.Header().Set("Access-Control-Allow-Origin", "*")

	return false
}

// sfu egress setup
// 041521 Decided checkFatal() is the correct way to handle errors in this func.
func SubHandler(w http.ResponseWriter, httpreq *http.Request) {
	defer httpreq.Body.Close()
	var err error

	log.Println("subHandler request", httpreq.URL.String())

	if handlePreflight(httpreq, w) {
		return
	}

	// rx offer, tx answer

	if httpreq.Method != "POST" {
		teeErrorStderrHttp(w, fmt.Errorf("only POST allowed"))
		return
	}

	requireStrictWISH := false
	if requireStrictWISH {
		if httpreq.Header.Get("Content-Type") != "application/sdp" {
			teeErrorStderrHttp(w, fmt.Errorf("Content-Type==application/sdp required on /sub when not ?channel=..."))
			return
		}
	}

	// offer from browser
	offersdpbytes, err := ioutil.ReadAll(httpreq.Body)
	if err != nil {
		teeErrorStderrHttp(w, err)
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
	// XXX is this switch case necessary?, will the pc eventually reach Closed after Failed or Disconnected
	peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		log.Printf("subscriber 0x%p newstate: %s", peerConnection, cs.String())
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

	err = logSdpReport("publisher", offer)
	checkFatal(err)

	err = peerConnection.SetRemoteDescription(offer)
	checkFatal(err)

	logTransceivers("offer-added", peerConnection)

	// sdsdp, err := offer.Unmarshal()
	// checkFatal(err)
	// videoTrackCount := numVideoMediaDesc(sdsdp)
	// log.Println("videoTrackCount", videoTrackCount)

	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	checkFatal(err)
	rtpSender, err := peerConnection.AddTrack(track)
	checkFatal(err)
	go processRTCP(rtpSender)

	subAddTrackCh <- MsgSubscriberAddTrack{
		txtrack: &TxTrack{
			track:   track,
			splicer: &RtpSplicer{},
			txid:    Audio,
		},
	}

	track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video", mediaStreamId)
	checkFatal(err)
	rtpSender2, err := peerConnection.AddTrack(track)
	checkFatal(err)
	go processRTCP(rtpSender2)

	subAddTrackCh <- MsgSubscriberAddTrack{
		txtrack: &TxTrack{
			track:   track,
			splicer: &RtpSplicer{},
			txid:    Video,
		},
	}

	logTransceivers("subHandler-tracksadded", peerConnection)

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	checkFatal(err)

	// Create channel that is blocked until ICE Gathering is complete
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

	// Sets the LocalDescription, and starts our UDP listeners
	err = peerConnection.SetLocalDescription(sessdesc)
	checkFatal(err)

	t0 := time.Now()
	// Block until ICE Gathering is complete, disabling trickle ICE
	// we do this because we only can exchange one signaling message
	// in a production application you should exchange ICE Candidates via OnICECandidate
	<-gatherComplete

	log.Println("ICE gather time is ", time.Since(t0).String())

	// Get the LocalDescription and take it to base64 so we can paste in browser
	ansrtcsd := peerConnection.LocalDescription()

	err = logSdpReport("sub-answer", *ansrtcsd)
	checkFatal(err)

	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write([]byte(ansrtcsd.SDP))
	if err != nil {
		elog.Println(fmt.Errorf("sub sdp write failed:%w", err))
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

func logSdpReport(wherefrom string, rtcsd webrtc.SessionDescription) error {
	good := strings.HasPrefix(rtcsd.SDP, "v=")
	if !good {
		len := len(rtcsd.SDP)
		if len > 20 {
			len = 20
		}
		return fmt.Errorf("Invalid sdp, no v=0 startline:%s", rtcsd.SDP[:len])
	}
	nlines := len(strings.Split(strings.Replace(rtcsd.SDP, "\r\n", "\n", -1), "\n"))
	log.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	log.Println("fullsdp", wherefrom, rtcsd.SDP)

	sd, err := rtcsd.Unmarshal()
	if err != nil {
		return fmt.Errorf("sdp failed to unmarshal")
	}
	log.Printf(" n/%d media descriptions present", len(sd.MediaDescriptions))
	return nil
}

func idleLoopPlayer() {

	var pkts []rtp.Packet

	if *idleClipZipfile == "" && *idleClipServerInput == "" {
		if len(idleClipZipBytes) == 0 {
			checkFatal(fmt.Errorf("embedded idle-clip.zip is zero-length!"))
		}
		pkts = readRTPFromZip(idleClipZipBytes)
	} else if *idleClipServerInput != "" {

		inp, err := ioutil.ReadFile(*idleClipServerInput)
		checkFatal(err)

		rdr := bytes.NewReader(inp)

		req, err := http.NewRequest("POST", *idleClipServerURL, rdr)
		checkFatal(err)

		req.Header.Set("Content-Type", "application/octet-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		checkFatal(err)
		defer resp.Body.Close()

		fmt.Println("response Status:", resp.Status)
		body, err := ioutil.ReadAll(resp.Body)
		checkFatal(err)
		pkts = readRTPFromZip(body)
		elog.Println(len(pkts), "encoded rtp packets retrieved from", *idleClipServerURL)

	} else if *idleClipZipfile != "" {
		buf, err := ioutil.ReadFile(*idleClipZipfile)
		checkFatal(err)
		pkts = readRTPFromZip(buf)

	} else {
		panic("badlogic")
	}

	if len(pkts) == 0 {
		if len(pkts) == 0 {
			checkFatal(fmt.Errorf("embedded idle-clip.zip is zero-length!"))
		}
	}

	pkts = removeH264AccessDelimiterAndSEI(pkts)

	fps := 5
	seqno := uint16(0)
	tstotal := uint32(0)

	basetime := time.Now()

	framedur90 := uint32(90000 / fps)

	pktsDur90 := pkts[len(pkts)-1].Timestamp - pkts[0].Timestamp

	totalDur90 := pktsDur90/framedur90*framedur90 + framedur90

	for {

		// sps.SequenceNumber = seqno
		// seqno++
		// sps.Timestamp = tstotal
		// rxMediaCh <- MsgRxPacket{rxid: IdleVideo, packet: &sps, rxClockRate: 90000}

		// pps.SequenceNumber = seqno
		// seqno++
		// pps.Timestamp = tstotal
		// rxMediaCh <- MsgRxPacket{rxid: IdleVideo, packet: &pps, rxClockRate: 90000}

		//send sps pps every 20
		for i := 0; i < 20; i++ {

			for _, pkt := range pkts {

				// rollover should be okay for uint32: https://play.golang.org/p/VeIBZgorleL
				tsdelta := pkt.Timestamp - pkts[0].Timestamp

				tsdeltaDur := time.Duration(tsdelta) * time.Second / 90000

				when := basetime.Add(tsdeltaDur)

				time.Sleep(time.Until(when)) //time.when() should be zero if when < time.now()

				pkt.SequenceNumber = seqno
				seqno++
				pkt.Timestamp = tsdelta + tstotal

				copy := pkt // critical!, we must make a copy!
				rxMediaCh <- MsgRxPacket{rxid: IdleVideo, packet: &copy, rxClockRate: 90000}

			}

			tstotal += totalDur90
			basetime = basetime.Add(time.Duration(totalDur90) * time.Second / 90000)

			time.Sleep(time.Until(basetime))

		}
	}
}

func removeH264AccessDelimiterAndSEI(pkts []rtp.Packet) []rtp.Packet {
	// var sps rtp.Packet
	// var pps rtp.Packet

	// if p.Payload[0]&0x1f == 7 {
	// 	sps = p
	// } else if p.Payload[0]&0x1f == 8 {
	// 	pps = p
	// } else {
	// remove SEI and access-delimeter
	//}

	newseqno := uint16(0)
	p2 := make([]rtp.Packet, 0)
	for _, p := range pkts {

		if p.Payload[0] != 6 && p.Payload[0] != 9 {
			p.SequenceNumber = newseqno
			newseqno++
			p2 = append(p2, p)
			if mediaDebug {
				medialog.Printf("idle pkt %d %#v", p.Payload[0], p.Header)
			}
		}

	}
	return p2
}

func dialUpstream(dialurl string) {

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
	checkFatal(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkFatal(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkFatal(err)
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	checkFatal(err)

	// Create an offer to send to the other process
	offer, err := peerConnection.CreateOffer(nil)
	checkFatal(err)

	err = logSdpReport("dialupstream-offer", offer)
	checkFatal(err)

	// Sets the LocalDescription, and starts our UDP listeners
	// Note: this will start the gathering of ICE candidates
	err = peerConnection.SetLocalDescription(offer)
	checkFatal(err)

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
	checkFatal(err)
	defer resp.Body.Close()

	log.Println("dial connected")

	answerraw, err := ioutil.ReadAll(resp.Body)
	checkFatal(err) //cam

	anssd := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	err = logSdpReport("dial-answer", anssd)
	checkFatal(err)

	err = peerConnection.SetRemoteDescription(anssd)
	checkFatal(err)

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

// logPacket writes text2pcap compatible lines
// func logPacket(log *log.Logger, packet *rtp.Packet) {
// 	text2pcapLog(log, packet.)
// }

// logPacketNewSSRCValue writes text2pcap compatible lines
// but, this packet will NOT contain RTP,
// // but rather: ether/ip/udp/special_token
// func logPacketNewSSRCValue(log *log.Logger, ssrc webrtc.SSRC, src rtpsplice.RtpSource) {
// 	text2pcapSentinel := []byte{0, 31, 0xde, 0xad, 0xbe, 0xef}
// 	buf := new(bytes.Buffer)
// 	buf.Write(text2pcapSentinel)

// 	source := []uint64{1, uint64(ssrc), uint64(src)}
// 	err := binary.Write(buf, binary.LittleEndian, source)
// 	checkFatal(err)

// 	text2pcapLog(log, buf.Bytes())
// }

func ingressOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	_ = receiver //silence warnings

	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		inboundTrackReader(track, Audio, track.Codec().ClockRate)
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

	go func() {
		var err error

		for {
			err = sendPLI(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			}
			checkFatal(err)

			err = sendREMB(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			}
			checkFatal(err)

			time.Sleep(3 * time.Second)
		}
	}()

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, Video, track.Codec().ClockRate)
	//here on error
	log.Printf("video reader %p exited", track)

}

func inboundTrackReader(rxTrack *webrtc.TrackRemote, rxid TrackId, clockrate uint32) {

	for {
		p, _, err := rxTrack.ReadRTP()
		if err == io.EOF {
			return
		}
		checkFatal(err)

		rxMediaCh <- MsgRxPacket{rxid: rxid, packet: p, rxClockRate: clockrate}
	}
}

func (x TrackId) String() string {

	switch x {
	case Video:
		return "Video"
	case Audio:
		return "Audio"
	case Data:
		return "Data"
	case IdleVideo:
		return "IdleVid"
	}

	panic("<bad TrackId>:" + strconv.Itoa((int(x))))
}

func msgLoop() {
	for {
		msgOnce()
	}
}

var inputSplicers = make([]RtpSplicer, NumTrackId)

func msgOnce() {

	select {

	case m := <-rxMediaCh:

		idlePkt := m.rxid == IdleVideo

		mainVidPkt := m.rxid == Video

		if idlePkt {
			rxActive := time.Since(lastVideoRxTime) <= time.Second

			if !rxActive && !sendingIdleVid {
				iskeyframe := isH264Keyframe(m.packet.Payload)
				if iskeyframe {
					sendingIdleVid = true
					elog.Println("SWITCHING TO IDLE, NO INPUT VIDEO PRESENT")
				}
			}

		} else if mainVidPkt {

			lastVideoRxTime = time.Now()

			if sendingIdleVid {
				iskeyframe := isH264Keyframe(m.packet.Payload)
				if iskeyframe {
					sendingIdleVid = false
					elog.Println("SWITCHING TO INPUT, AS INPUT CAME UP")
				}
			}
		}

		if sendingIdleVid && mainVidPkt {
			return
		}
		if !sendingIdleVid && idlePkt {
			return
		}

		var txtype TrackId

		//keep in mind pion ignores both payloadtype, ssrc when you use write()
		switch m.rxid {
		case Audio:
			txtype = Audio
			m.packet.PayloadType = 80 // ignored by Pion
		case Video:
			fallthrough
		case IdleVideo:
			txtype = Video
			m.packet.PayloadType = 100 // ignored by Pion
		}

		pkt := *m.packet // make copy
		SpliceRTP(txtype, &inputSplicers[txtype], &pkt, time.Now().UnixNano(), int64(m.rxClockRate))

		if txtype == Audio && rtpoutConn != nil {
			//ptmp := pkt //copy
			rtpbuf, err := pkt.Marshal()
			checkFatal(err)
			_, _ = rtpoutConn.Write(rtpbuf)
		}

		for i, tr := range txtracks {

			ismatch := txtype == tr.txid
			//println(i,ismatch,txtype)
			if !ismatch {
				continue
			}
			//pline()

			err := tr.track.WriteRTP(&pkt)
			//println(pkt.SequenceNumber,pkt.Timestamp)
			if err == io.ErrClosedPipe {
				log.Printf("track io.ErrClosedPipe, removing track %s", tr.txid)

				// slice tricks non-order preserving delete
				txtracks[i] = txtracks[len(txtracks)-1]
				txtracks[len(txtracks)-1] = nil
				txtracks = txtracks[:len(txtracks)-1]

			}

		}

	case m := <-subAddTrackCh:

		txtracks = append(txtracks, m.txtrack)

	case <-mediaDebugTickerChan:

		medialog.Println("sendingIdleVid", sendingIdleVid)

		for i, v := range txtracks {
			medialog.Println("tx#", i, "ssrc", v.splicer.lastSSRC)
		}
		medialog.Println()

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
	//	checkFatal(err)

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
	err = logSdpReport("publisher", offer)
	checkFatal(err)

	err = peerConnection.SetRemoteDescription(offer)
	checkFatal(err)

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	checkFatal(err)

	// Create channel that is blocked until ICE Gathering is complete
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

	// Sets the LocalDescription, and starts our UDP listeners
	err = peerConnection.SetLocalDescription(sessdesc)
	checkFatal(err)

	// Block until ICE Gathering is complete, disabling trickle ICE
	// we do this because we only can exchange one signaling message
	// in a production application you should exchange ICE Candidates via OnICECandidate
	<-gatherComplete

	err = logSdpReport("listen-ingress-answer", *peerConnection.LocalDescription())
	checkFatal(err)

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

// SpliceRTP
// this is carefully handcrafted, be careful
// The packet you provide WILL get modified
//
// we may want to investigate adding seqno deltas onto a master counter
// as a way of making seqno most consistent in the face of lots of switching,
// and also more robust to seqno bug/jumps on input
//
// This grabs mutex after doing a fast, non-mutexed check for applicability

// p gets modified
func SpliceRTP(txid TrackId, s *RtpSplicer, p *rtp.Packet, unixnano int64, rtphz int64) {

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	if p.SSRC != s.lastSSRC {

		td1 := unixnano - s.lastUnixnanosNow // nanos
		if td1 < 0 {
			td1 = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		//td2 := td1 * rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		td2 := td1 / (int64(time.Second) / rtphz) //convert nanos -> 90khz or similar clockrate. speed not important
		if td2 == 0 {
			td2 = 1
		}
		s.tsOffset = p.Timestamp - (s.lastTS + uint32(td2))
		s.snOffset = p.SequenceNumber - s.lastSN - 1

		log.Printf("** ssrc change %v rtphz/%v td1/%v td2/%v tsdelta/%v sndelta/%v", txid.String(), rtphz, td1, td2, (p.Timestamp-s.tsOffset)-s.lastTS, (p.SequenceNumber-s.snOffset)-s.lastSN)
	}

	p.Timestamp -= s.tsOffset
	p.SequenceNumber -= s.snOffset

	s.lastUnixnanosNow = unixnano
	s.lastTS = p.Timestamp
	s.lastSN = p.SequenceNumber
	s.lastSSRC = p.SSRC
}

// isH264Keyframe detects when an RFC6184 payload contains an H264 SPS (8)
// most encoders will follow this with an PPS (7), and maybe SEI
// this code has evolved from:
// from https://github.com/jech/galene/blob/codecs/rtpconn/rtpreader.go#L45
// the original IDR detector was written by Juliusz Chroboczek @jech from the awesome Galene SFU
// Types sps=7 pps=8 IDR-slice=5
// no writes expects immutable []byte, so
// no mutex is taken
func isH264Keyframe(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}
	nalu := payload[0] & 0x1F
	if nalu == 0 {
		// reserved
		return false
	} else if nalu <= 23 {
		// simple NALU
		return nalu == 7
	} else if nalu == 24 || nalu == 25 || nalu == 26 || nalu == 27 {
		// STAP-A, STAP-B, MTAP16 or MTAP24
		i := 1
		if nalu == 25 || nalu == 26 || nalu == 27 {
			// skip DON
			i += 2
		}
		for i < len(payload) {
			if i+2 > len(payload) {
				return false
			}
			length := uint16(payload[i])<<8 |
				uint16(payload[i+1])
			i += 2
			if i+int(length) > len(payload) {
				return false
			}
			offset := 0
			if nalu == 26 {
				offset = 3
			} else if nalu == 27 {
				offset = 4
			}
			if offset >= int(length) {
				return false
			}
			n := payload[i+offset] & 0x1F
			if n == 7 {
				return true
			} else if n >= 24 {
				// is this legal?
				println("Non-simple NALU within a STAP")
			}
			i += int(length)
		}
		if i == len(payload) {
			return false
		}
		return false
	} else if nalu == 28 || nalu == 29 {
		// FU-A or FU-B
		if len(payload) < 2 {
			return false
		}
		if (payload[1] & 0x80) == 0 {
			// not a starting fragment
			return false
		}
		return payload[1]&0x1F == 7
	}
	return false
}

func readRTPFromZip(buf []byte) []rtp.Packet {
	// Open a zip archive for reading.

	if len(buf) == 0 {
		checkFatal(fmt.Errorf("zero-length rtp-zip file not gunna work"))
	}

	bufrdr := bytes.NewReader(buf)

	r, err := zip.NewReader(bufrdr, int64(len(buf)))
	checkFatal(err)

	pkts := make([]rtp.Packet, 0)

	seqbase := int(0)
	for i, f := range r.File {

		var p rtp.Packet

		rc, err := f.Open()
		checkFatal(err)

		buf, err := ioutil.ReadAll(rc)
		checkFatal(err)

		err = p.Unmarshal(buf)
		checkFatal(err)

		if i == 0 {
			seqbase = int(p.SequenceNumber)
		} else {
			want := i + seqbase
			got := int(p.SequenceNumber)
			if want != got {
				checkFatal(fmt.Errorf("idle-clip bad: bad rtp sequence number file/want/got %d %d", want, got))
			}
		}

		pkts = append(pkts, p)

		rc.Close()

	}

	if mediaDebug {
		medialog.Printf("Read %d idle-clip packets", len(pkts))
	}

	return pkts

}

func getDefRouteIntfAddrIPv6() (net.IP, error) {
	const googleDNSIPv6 = "[2001:4860:4860::8888]:8080" // not important, does not hit the wire
	cc, err := net.Dial("udp6", googleDNSIPv6)          // doesnt send packets
	if err != nil {
		return nil, err
	}

	cc.Close()
	return cc.LocalAddr().(*net.UDPAddr).IP, nil
}

func getDefRouteIntfAddrIPv4() (net.IP, error) {
	const googleDNSIPv4 = "8.8.8.8:8080"       // not important, does not hit the wire
	cc, err := net.Dial("udp4", googleDNSIPv4) // doesnt send packets
	if err != nil {
		return nil, err
	}

	cc.Close()
	return cc.LocalAddr().(*net.UDPAddr).IP, nil

}

func parseFtlKey() (uint32, string, string, error) {
	ftlsplit := strings.Split(*ftlKey, "-")
	if len(ftlsplit) != 2 {
		return 0, "", "", fmt.Errorf("fatal: bad stream key in --ftl-key")
	}
	chanidStr := ftlsplit[0]
	hmackey := ftlsplit[1]
	chanid64, err := strconv.ParseInt(chanidStr, 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("fatal: bad stream key in --ftl-key")
	}

	return uint32(chanid64), chanidStr, hmackey, nil
}

// do two things:
// create udp socket, and receive rtp on it
// create tcp socket, and dial and register with proxy on it
func clusterFtlReceive(ctx context.Context, udpconn net.PacketConn) {
	var err error

	chanid, _, _, err := parseFtlKey()
	checkFatal(err)

	// don't use 8084, so we can test everything on the same box

	elog.Println("rtp rx addr", udpconn.LocalAddr())

	lastudp := time.Now()
	buf := make([]byte, 2000)

	// OBS always sends the same ssrc, I think
	// but we want to change the ssrc we OBS reconnects so the splicer works.
	audiossrc := uint32(rand.Int63())
	videossrc := uint32(rand.Int63())
	badssrc := 0
	//connected := false
	active := false
	for {
		select {
		case <-ctx.Done():
			return // returning not to leak the goroutine
		default:
		}

		err = udpconn.SetReadDeadline(time.Now().Add(time.Second))
		checkFatal(err)
		n, _, err := udpconn.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {

			if active && time.Since(lastudp) > time.Second*3/2 { // 1.5 second
				elog.Println("FTL RTPRX: UDP PKTS *NOT* FLOWING")
				active = false
			}

			continue
		} else if err != nil {
			checkFatal(fmt.Errorf("FTL RTPRX: UDP FAIL, EXITING: %w", err))
		}

		lastudp = time.Now()

		if !active {
			active = true
			elog.Println("FTL RTPRX: UDP PKTS ARE FLOWING")
		}

		// There may benefits to issuing linux connect() call
		// but we are not doing it right now
		// udpconn, err = net.DialUDP("udp", laddr, readaddr)

		if n < 12 {
			continue
		}

		var p rtp.Packet

		b := make([]byte, n)
		copy(b, buf[:n])

		err = p.Unmarshal(b)
		checkFatal(err)

		switch p.Header.PayloadType {
		case 200:
			log.Println("got ftl sender report")
		case 96:
			if p.SSRC != chanid+1 {
				badssrc++
				continue
			}
			p.SSRC = videossrc // each FTL session should have different SSRC for downstream splicer
			rxMediaCh <- MsgRxPacket{rxid: Video, packet: &p, rxClockRate: 90000}
		case 97:
			// check for the starter packets that confuse chrome, and toss them: len(pkt)==1404
			if ok := isMysteryOBSFTL(p); !ok {
				break
			}

			if p.SSRC != chanid {
				badssrc++
				continue
			}
			p.SSRC = audiossrc // each FTL session should have different SSRC for downstream splicer
			rxMediaCh <- MsgRxPacket{rxid: Audio, packet: &p, rxClockRate: 48000}
		}
		if badssrc > 0 && badssrc%100 == 10 {
			elog.Println("Bad SSRC media received :(  count:", badssrc)
		}
	}
	//unreachable
	//return
}

func startFtlListener(inf *log.Logger, dbg *log.Logger) {

	config := &net.ListenConfig{}
	ln, err := config.Listen(context.Background(), "tcp", ":8084")
	if err != nil {
		inf.Fatalln(err)
	}
	defer ln.Close()

	for {
		inf.Println("ftl/waiting for accept")

		netconn, err := ln.Accept()
		if err != nil {
			inf.Fatalln(err)
		}

		inf.Println("ftl/socket accepted")

		tcpconn := netconn.(*net.TCPConn)
		ftlserver.NewTcpSession(inf, dbg, tcpconn, findserver)
		netconn.Close()
	}
	// unreachable
	//return
}

func findserver(inf *log.Logger, dbg *log.Logger, requestChanid string) (ftlserver.FtlServer, string) {
	want := requestChanid + "-"
	match := strings.HasPrefix(*ftlKey, want)
	dbg.Println("ftl/findserver/channelid match:", match)

	if match {
		arr := strings.Split(*ftlKey, "-")
		if len(arr) != 2 {
			inf.Fatalln("fatal: bad stream key in --ftl-key")
		}

		tmp64, err := strconv.ParseInt(arr[0], 10, 64)
		checkFatal(err)

		a := &myFtlServer{}
		a.audiossrc = uint32(rand.Int63())
		a.videossrc = uint32(rand.Int63())
		a.channelid = uint32(tmp64)
		return a, arr[1]
	}

	return nil, ""
}

type myFtlServer struct {
	badrtp    int
	badssrc   int
	audiossrc uint32
	videossrc uint32
	channelid uint32
}

func (x *myFtlServer) TakePacket(inf *log.Logger, dbg *log.Logger, pkt []byte) bool {
	var err error

	var p rtp.Packet

	err = p.Unmarshal(pkt)
	if err != nil {
		x.badrtp++
		if x.badrtp < 10 {
			return true
		} else {
			log.Println("ftl/obs: too many RTP decode failures, closing")
			return false
		}
	}

	switch p.Header.PayloadType {
	case 200:
		//log.Println("got ftl sender report")
	case 96:
		if p.SSRC != x.channelid+1 {
			x.badssrc++
			break
		}
		p.SSRC = x.videossrc // each FTL session should have different SSRC for downstream splicer
		rxMediaCh <- MsgRxPacket{rxid: Video, packet: &p, rxClockRate: 90000}

	case 97:

		// check for the starter packets that confuse chrome, and toss them: len(pkt)==1404
		if ok := isMysteryOBSFTL(p); !ok {
			break
		}

		if p.SSRC != x.channelid {
			x.badssrc++
			break
		}
		p.SSRC = x.audiossrc // each FTL session should have different SSRC for downstream splicer
		rxMediaCh <- MsgRxPacket{rxid: Audio, packet: &p, rxClockRate: 48000}
	}
	if x.badssrc > 0 && x.badssrc%100 == 10 {
		elog.Println("Bad SSRC media received :(  count:", x.badssrc)
	}

	return true //okay
}

func isMysteryOBSFTL(p rtp.Packet) (ok bool) {
	if len(p.Payload) > 600 {
		//opustoc := p.Payload[0] //typically 0xfc from https://www.rfc-editor.org/rfc/rfc6716.html#section-3.1

		nzero := 0
		const nzeroCount = 10
		for i := 0; i < nzeroCount; i++ {
			if p.Payload[i] == 0 {
				nzero++
			}
		}
		if nzero == nzeroCount {
			// bogus, non opus packet
			return false
		}
	}
	return true
}

func clusterHttpsRedisRegister(ctx context.Context, domain string, myip net.IP, port int) {

	const lockdur = time.Duration(2 * time.Second)

	px := strconv.Itoa(int(lockdur / time.Millisecond))

	/*
		there is a race here, but it is okay.
		if the sfu diseappears, but the proxy still finds it in redis,
		the https request will fail.
	*/

	key1 := "domain:" + domain + ":lock"
	key2 := "domain:" + domain + ":addrport"
	addrport := fmt.Sprintf("%s:%d", myip, port)

	rconn := redisPool.Get()
	defer rconn.Close()

	lock, err := redisLocker.Obtain(key1, lockdur, nil)
	defer func() { _ = lock.Release() }()
	checkFatal(err)

	for {

		select {
		case <-ctx.Done():
			return // returning not to leak the goroutine
		case <-time.NewTimer(lockdur / 2).C:
		}
		err = lock.Refresh(lockdur, nil)
		checkFatal(err)

		rr, err := rconn.Do("set", key2, addrport, "px", px)
		checkFatal(err)
		checkRedisOk(rr)
	}

}
func checkRedisOk(rr interface{}) {
	if rr != "OK" {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Fatalf("FATAL %s:%d redis not ok: %#v", filepath.Base(fileName), fileLine, rr)
	}
}

func clusterFtlRedisRegister(ctx context.Context, privateip net.IP, port int) {

	const lockdur = time.Duration(2 * time.Second)
	px := strconv.Itoa(int(lockdur / time.Millisecond))

	/*
		there is a race here, but it is okay.
		the ftl-proxy might see an SFU in redis, after the SFU disappears
		but, the packets comming from the the proxy should get Icmp bounced
		causing unix.ECONNREFUSED error back to the proxy.
		The proxy will see these and give up eventually.
		look for unix.ECONNREFUSED in the proxy.
	*/

	_, chanidstr, hmackey, err := parseFtlKey()
	checkFatal(err)
	key1 := "ftl:" + chanidstr + ":lock"
	key2 := "ftl:" + chanidstr + ":addrport"
	key3 := "ftl:" + chanidstr + ":hmackey"
	addrport := fmt.Sprintf("%s:%d", privateip, port)

	rconn := redisPool.Get()
	defer rconn.Close()

	lock, err := redisLocker.Obtain(key1, lockdur, nil)
	defer func() { _ = lock.Release() }()
	checkFatal(err)

	for {

		select {
		case <-ctx.Done():
			return // returning not to leak the goroutine
		case <-time.NewTimer(lockdur / 2).C:
		}
		err = lock.Refresh(lockdur, nil)
		checkFatal(err)

		rr, err := rconn.Do("set", key2, addrport, "px", px)
		checkFatal(err)
		checkRedisOk(rr)

		rr, err = rconn.Do("set", key3, hmackey, "px", px)
		checkFatal(err)
		checkRedisOk(rr)

	}

}

func getMyIPFromRedis(ctx context.Context) net.IP {
	rconn, err := redisPool.GetContext(ctx)
	checkFatal(err)
	defer rconn.Close()

	line, err := redigo.String(rconn.Do("client", "info"))
	checkFatal(err)

	hostport := ""
	redisid := int64(0)

	n, err := fmt.Sscanf(line, "id=%d addr=%s ", &redisid, &hostport)
	checkFatal(err)

	if n != 2 {
		checkFatal(fmt.Errorf("unable to get IP from redis clientline:%v", line))
	}

	host, _, err := net.SplitHostPort(hostport)
	checkFatal(err)

	ipaddr := net.ParseIP(host)
	if ipaddr == nil {
		checkFatal(fmt.Errorf("unable to get ip address from redis: %s", line))
	}
	return ipaddr
}
