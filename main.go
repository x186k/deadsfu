package main

//force new build

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"

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
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/pflag"

	"github.com/pkg/profile"
	"golang.org/x/sync/semaphore"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	_ "embed"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"

	"github.com/x186k/deadsfu/rtpstuff"
)

//go:embed html/*
var htmlContent embed.FS

//go:embed deadsfu-binaries/idle.screen.h264.pcapng
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

var ticker100ms = time.NewTicker(100 * time.Millisecond)
var mediaDebugTickerChan = make(<-chan time.Time)
var mediaDebug = false

type Subid uint64

type MsgRxPacket struct {
	rxidpair    RxidPair
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

type MsgFillRxidPair struct {
	rxid TrackId
	ch   chan RxidPair
}

var rxMediaCh chan MsgRxPacket = make(chan MsgRxPacket, 10)
var rxidPairCh chan MsgFillRxidPair = make(chan MsgFillRxidPair)
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
	track   *webrtc.TrackLocalStaticRTP
	splicer *RtpSplicer
	subid   Subid   // 64bit subscriber key
	txid    TrackId // track number from subscriber's perspective

	mainRxid TrackId // main rxid, NEVER set to idle idle
	currRxid TrackId // live rxid, can be idle
	pendRxid TrackId // pending rxid, can be idle
}

// subid to txid to txtrack index
var sub2txid2track map[Subid]map[TrackId]*Track = make(map[Subid]map[TrackId]*Track)

type TrackType int16

const (
	Invalid   TrackType = 0
	Video     TrackType = iota
	Audio     TrackType = iota
	Data      TrackType = iota
	IdleVideo TrackType = iota
)

type TrackId struct {
	id  int16
	typ TrackType
}

//this is an optimization (premature for sure)
//rather than just pass around a TrackId, we also pass around a ptr to it's state
type RxidPair struct {
	rxid  TrackId
	state *RxidState
}

// this (rxid2state) could be an array.
// but, it is <much> easier to think about as a map, as opposed to a sparse array.
// AND, this map is not indexed in any hot-spots or media-paths
// so, there is NO good reason to make it an array
// sooo... we keep it a map.

//we must mutex or constrain access to single goroutine. I choose #2
var rxid2state map[TrackId]*RxidState = make(map[TrackId]*RxidState)

type RxidState struct {
	lastReceipt time.Time //unixnanos
	active      bool
}

var txtracks []*Track

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

func logNotFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Printf("NON-FATAL ERROR %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
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
var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)
var medialog = log.New(os.Stdout, "M ", log.Lmicroseconds|log.LUTC)

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
	// checkFatal(err)
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

		//we do this to eliminate double error message on -z
		//hack city
		//pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
		pflag.Usage = Usage // my own usage handle
		//this will print unknown flags errors twice, but just deal with it
		pflag.Parse()
		if *help {
			Usage()
			os.Exit(0)
		}

		log.SetFlags(log.Lmicroseconds | log.LUTC)
		log.SetPrefix("D ")
		log.SetOutput(os.Stdout)

		mainlog := false

		for _, v := range *debug {
			switch v {
			case "":
				// do nothing
			case "tracks":
				mediaDebugTickerChan = time.NewTicker(4 * time.Second).C
				mediaDebug = true
			case "main":
				mainlog = true
			case "help":
				fallthrough
			default:
				elog.Fatal("--z-debug sub-flags are: main, help, tracks")
			}
		}
		if mainlog {
			log.Printf("'main' debug enabled")
		} else {
			silenceLogger(log.Default())
		}

	}

	go logGoroutineCountToDebugLog()

	log.Printf("idleScreenH264Pcapng len=%d md5=%x", len(idleScreenH264Pcapng), md5.Sum(idleScreenH264Pcapng))
	p, _, err := rtpstuff.ReadPcap2RTP(bytes.NewReader(idleScreenH264Pcapng))
	checkFatal(err)

	rxid2state[TrackId{id: 0, typ: IdleVideo}] = &RxidState{}
	rxid2state[TrackId{id: 0, typ: Video}] = &RxidState{}
	rxid2state[TrackId{id: 0, typ: Audio}] = &RxidState{}

	idlepair := RxidPair{
		rxid:  TrackId{id: 0, typ: IdleVideo},
		state: rxid2state[TrackId{id: 0, typ: IdleVideo}],
	}
	go idleLoopPlayer(p, idlepair)

	// XXX msgLoop touches rxid2state, so we have 2 GR touching a map
	// but, let's be honest, it's the only toucher of rxid2state after this point
	// so, probably okay
	go msgLoop()
}

func silenceLogger(l *log.Logger) {
	l.SetOutput(ioutil.Discard)
	l.SetPrefix("")
	l.SetFlags(0)
}

func main() {
	var err error
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

	}
	mux.HandleFunc(subPath, SubHandler)

	dialingout := *dialIngressURL != ""

	if !dialingout {
		mux.HandleFunc(pubPath, pubHandler)
	}

	//ftl if choosen
	if *obsKey != "" {
		audio := RxidPair{
			rxid:  TrackId{id: 0, typ: Audio},
			state: rxid2state[TrackId{id: 0, typ: Audio}],
		}
		video := RxidPair{
			rxid:  TrackId{id: 0, typ: Video},
			state: rxid2state[TrackId{id: 0, typ: Video}],
		}
		if video.state == nil {
			panic("fatal1")
		}
		if audio.state == nil {
			panic("fatal2")
		}

		go func() {
			for {
				attemptSingleFtlSession(audio, video)
			}
		}()
	}

	go func() {
		// httpLn, err := net.Listen("tcp", laddr)
		err := http.ListenAndServe(*httpListenAddr, mux)
		panic(err)
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

func attemptSingleFtlSession(audio, video RxidPair) {

	elog.Println("OBS/FTL: WAITING FOR CONNECTION")

	udpconn, tcpconn, kv, scanner, err := ftlServer("", "8084", *obsKey)
	if err != nil {
		logNotFatal(err)
		return
	}
	defer udpconn.Close()
	defer tcpconn.Close()

	elog.Println("OBS/FTL: GOT GOOD CONNECTION")

	if kv["VideoCodec"] != "H264" {
		checkFatal(fmt.Errorf("ftl: unsupported video codec: %v", kv["VideoCodec"]))
	}
	if kv["AudioCodec"] != "OPUS" {
		checkFatal(fmt.Errorf("ftl: unsupported audio codec: %v", kv["AudioCodec"]))
	}

	pingchan := make(chan bool)
	disconnectCh := make(chan bool)

	// PING goroutine
	// this will silently go away when the socket gets closed
	go func() {
		log.Println("ftl: ping responder running")
		for scanner.Scan() {
			l := scanner.Text()

			// XXX PING is sometimes followed by streamkey-id
			// but we don't validate it.
			// it is checked for Connect message
			if strings.HasPrefix(l, "PING ") {
				log.Println("ftl: ping!")
				fmt.Fprintf(tcpconn, "201\n")

				pingchan <- true
			} else if l == "" {
				//ignore blank
			} else if l == "DISCONNECT" {
				disconnectCh <- true
			} else {
				// unexpected
				elog.Println("ftl: unexpected msg:", l)
			}
		}
		//silently finish goroutine on scanner error or socket close
	}()

	//XXX consider use of rtp.Packet pool
	//println(999,buf[1],p.Header.PayloadType)
	// default:
	// 	checkFatal(fmt.Errorf("bad RTP payload from FTL: %d", p.Header.PayloadType))

	lastping := time.Now()
	lastudp := time.Now()
	buf := make([]byte, 2000)
	for {

		select {
		case m, more := <-pingchan:
			if m && more {
				lastping = time.Now()
			}
		case <-disconnectCh:
			elog.Println("OBS/FTL: SERVER DISCONNECTED")
			return
		default:
		}
		if time.Since(lastping) > time.Second*11 {
			elog.Println("OBS/FTL: PINGING TIMEOUT, CLOSING")
			return
		}
		if time.Since(lastudp) > time.Second*3/2 { // 1.5 second
			elog.Println("OBS/FTL: UDP/RX TIMEOUT, CLOSING")
			return
		}

		err = udpconn.SetReadDeadline(time.Now().Add(time.Second))
		checkFatal(err)
		n, err := udpconn.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		} else if err != nil {
			elog.Println(fmt.Errorf("OBS/FTL: UDP FAIL, CLOSING: %w", err))
			return
		}

		lastudp = time.Now()

		if n < 12 {
			continue
		}

		var p rtp.Packet

		b := make([]byte, n)
		copy(b, buf[:n])

		err = p.Unmarshal(b)
		checkFatal(err)

		switch p.Header.PayloadType {
		case 96:
			rxMediaCh <- MsgRxPacket{rxidpair: video, packet: &p, rxClockRate: 90000}
		case 97:
			rxMediaCh <- MsgRxPacket{rxidpair: audio, packet: &p, rxClockRate: 48000}
		}
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
// 041521 Decided checkFatal() is the correct way to handle errors in this func.
func SubHandler(w http.ResponseWriter, httpreq *http.Request) {
	defer httpreq.Body.Close()
	var err error

	log.Println("subHandler request", httpreq.URL.String())

	if handlePreflight(httpreq, w) {
		return
	}

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

	rid := httpreq.URL.Query().Get("channel")
	//issfu := httpreq.URL.Query().Get("issfu") != ""

	//change channel
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

		//check to see if this is a valid rxid/TrackId
		// we cannot access the map directly, so we use a chan

		_, ok := getRxidPair(trackid)

		if !ok {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. rid=%v not found", rid))
			return
		}

		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: Subid(txid),
			txid: TrackId{
				id:  0,
				typ: Video,
			}, //can only switch output track 0
			rxid: trackid, // XXX change to rxidpair?
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

	err = logSdpReport("publisher", offer)
	checkFatal(err)

	err = peerConnection.SetRemoteDescription(offer)
	checkFatal(err)

	logTransceivers("offer-added", peerConnection)

	sdsdp, err := offer.Unmarshal()
	checkFatal(err)

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
	checkFatal(err)
	rtpSender, err := peerConnection.AddTrack(track)
	checkFatal(err)
	go processRTCP(rtpSender)

	subAddTrackCh <- MsgSubscriberAddTrack{
		txtrack: &Track{
			track:    track,
			splicer:  &RtpSplicer{},
			subid:    Subid(txid),
			txid:     TrackId{id: 0, typ: Audio},
			mainRxid: TrackId{id: 0, typ: Audio},
			currRxid: TrackId{id: 0, typ: Audio},
			pendRxid: TrackId{id: 0, typ: Audio},
		},
	}

	for i := 0; i < videoTrackCount; i++ {
		name := fmt.Sprintf("video%d", i)
		track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, name, mediaStreamId)
		checkFatal(err)
		rtpSender, err := peerConnection.AddTrack(track)
		checkFatal(err)
		go processRTCP(rtpSender)

		subAddTrackCh <- MsgSubscriberAddTrack{
			txtrack: &Track{
				track:    track,
				splicer:  &RtpSplicer{},
				subid:    Subid(txid),
				txid:     TrackId{id: 0, typ: Video},
				mainRxid: TrackId{id: 0, typ: Video},
				currRxid: TrackId{id: 0, typ: Video},
				pendRxid: TrackId{id: 0, typ: Video},
			},
		}
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

func getRxidPair(rxid TrackId) (rxidpair RxidPair, found bool) {
	ch := make(chan RxidPair)

	rxidPairCh <- MsgFillRxidPair{
		rxid: rxid,
		ch:   ch,
	}

	select {
	case rxidpair = <-ch:
	case <-time.NewTimer(time.Second).C:
		panic("stall1")
	}

	found = rxidpair.state != nil

	return
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

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	checkFatal(err)
	return hex.EncodeToString(bytes)
}

func idleLoopPlayer(p []rtp.Packet, idlepair RxidPair) {

	n := len(p)
	delta1 := time.Second / time.Duration(n)
	delta2 := uint32(90000 / n)
	mrand.Seed(time.Now().UnixNano())
	seq := uint16(mrand.Uint32())
	ts := mrand.Uint32()

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

			rxMediaCh <- MsgRxPacket{rxidpair: idlepair, packet: &v, rxClockRate: 90000}

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
// 	checkFatal(err)

// 	text2pcapLog(log, buf.Bytes())
// }

func ingressOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	_ = receiver //silence warnings

	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		rxidpair, ok := getRxidPair(TrackId{id: 0, typ: Audio})

		if !ok {
			panic("cannot find audio0")
		}

		inboundTrackReader(track, rxidpair, track.Codec().ClockRate)
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
			checkFatal(err)

			err = sendREMB(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			}
			checkFatal(err)

			time.Sleep(3 * time.Second)
		}
	}()

	rxid, err := parseTrackid(trackname)
	checkFatal(err)

	rxidpair, ok := getRxidPair(rxid)

	if !ok {
		panic("cannot find track for trackname:" + trackname)
	}

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, rxidpair, track.Codec().ClockRate)
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

		t.id = int16(i)
		t.typ = Video
		return
	}

	if strings.HasPrefix(trackname, "audio") {
		i, xerr := strconv.Atoi(strings.TrimPrefix(trackname, "audio"))
		if xerr != nil {
			err = fmt.Errorf("fail to parse trackid: %v", trackname)
			return
		}

		t.id = int16(i)
		t.typ = Audio
		return
	}

	err = fmt.Errorf("need video<N> or audio<N> for track num, got:[%s]", trackname)
	return
}

func inboundTrackReader(rxTrack *webrtc.TrackRemote, rxidpair RxidPair, clockrate uint32) {

	for {
		p, _, err := rxTrack.ReadRTP()
		if err == io.EOF {
			return
		}
		checkFatal(err)

		rxMediaCh <- MsgRxPacket{rxidpair: rxidpair, packet: p, rxClockRate: clockrate}
	}
}

func (x TrackType) String() string {

	switch x {
	case Video:
		return "XVideo"
	case Audio:
		return "XAudio"
	case Data:
		return "XData"
	case IdleVideo:
		return "XIdleVideo"
	case Invalid:
		return "XInvalid"
	}

	return "<bad TrackId>"
}

func (x TrackId) String() string {
	return x.typ.String() + "/" + strconv.Itoa(int(x.id))
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
	//access rxid2state without requiring mutex
	case m := <-rxidPairCh:
		st := rxid2state[m.rxid]

		m.ch <- RxidPair{
			rxid:  m.rxid,
			state: st,
		}

	case m := <-rxMediaCh:
		//fmt.Printf(" xtx %x\n",m.packet.Payload[0:10])
		//println(6666,m.rxidstate.rxid)

		m.rxidpair.state.lastReceipt = time.Now()

		rxid := m.rxidpair.rxid

		if rxid.typ == Invalid {
			panic(111)
		}
		if rxid.typ == Audio {
			break
		}
		if rxid.typ == IdleVideo {
			break
		}

		isaudio := m.rxidpair.rxid.typ == Audio
		if !isaudio {
			if !rtpstuff.IsH264Keyframe(m.packet.Payload) {
				goto not_keyframe
			}
		}

		//this is a keyframe
		for i, tr := range txtracks {

			mainMatch := tr.mainRxid == rxid

			if mainMatch && (tr.pendRxid != TrackId{0, Invalid} || tr.currRxid != rxid) {

				if mediaDebug {
					medialog.Printf("keyframe tx/%d  switched 2 main, from:%s to:%s  \n", i, tr.currRxid, rxid)
				}

				tr.pendRxid = TrackId{0, Invalid} //clear pending
				tr.currRxid = rxid
			}

			pendMatch := tr.pendRxid == rxid

			if pendMatch && (tr.currRxid != rxid) {

				if mediaDebug {
					medialog.Printf("keyframe tx/%d  switched 2 pend, from:%s to:%s  \n", i, tr.currRxid, rxid)
				}

				tr.pendRxid = TrackId{0, Invalid} //clear pending
				tr.currRxid = rxid
			}

		}

	not_keyframe:

		for i, tr := range txtracks {

			send := tr.currRxid == rxid
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
					log.Printf("track io.ErrClosedPipe, removing track %v %v %v", tr.subid, tr.txid, tr.currRxid)

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

		if tr.currRxid.typ == Video {
			tr.mainRxid = TrackId{0, Video}
			tr.currRxid = TrackId{0, Video}
			tr.pendRxid = TrackId{0, Invalid}

			if !rxid2state[tr.currRxid].active {
				tr.currRxid = TrackId{0, IdleVideo}
			}
		} else if tr.currRxid.typ == Audio {
			tr.mainRxid = TrackId{0, Audio}
			tr.currRxid = TrackId{0, Audio}
			tr.pendRxid = TrackId{0, Invalid}
		}

		sub2txid2track[tr.subid][tr.txid] = tr

	case m := <-subSwitchTrackCh:

		if a, ok := sub2txid2track[m.subid]; ok {
			if tr, ok := a[m.txid]; ok {
				if m.rxid.typ == Invalid {
					panic("bad msg 99")
				}
				tr.mainRxid = m.rxid
				tr.pendRxid = m.rxid
			} else {
				elog.Println("invalid txid", m.txid)
			}
		} else {
			elog.Println("invalid subid", m.subid)
		}

	case <-mediaDebugTickerChan:

		// for rxid, v := range rxid2state {
		// 	medialog.Println("rx", rxid.String(), "active=", v.active)
		// }
		// for i, v := range txtracks {
		// 	medialog.Println("tx i:", i, "ssrc", v.splicer.lastSSRC, "main/curr/pend", v.mainRxid.String(), v.currRxid.String(), v.pendRxid.String())
		// }
		// medialog.Println()

	case now := <-ticker100ms.C:

		//fmt.Println("Tick at", tk)

		for txid, v := range rxid2state {

			isvideo := txid.typ == Video

			if !isvideo {
				continue // we only do idle switching on video right now
			}

			active := now.Sub(v.lastReceipt) <= time.Second

			transition2idle := v.active && !active
			v.active = active

			if !transition2idle {
				continue
			}

			if mediaDebug {
				medialog.Printf("100ms tick/transition2idle on %v\n", txid.String())
			}

			// went idle.
			for i, tr := range txtracks {
				if tr.currRxid == txid {
					if mediaDebug {
						medialog.Printf("100ms video%d  set to idle\n", i)
					}
					tr.pendRxid = TrackId{0, IdleVideo}
				}
			}

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
func SpliceRTP(s *RtpSplicer, in *rtp.Packet, unixnano int64, rtphz int64) {

	forceKeyFrame := false

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	if in.SSRC != s.lastSSRC || forceKeyFrame {
		log.Printf("SpliceRTP: %p: ssrc changed new=%v cur=%v", s, in.SSRC, s.lastSSRC)

		td := unixnano - s.lastUnixnanosNow // nanos
		if td < 0 {
			td = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		td *= rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		if td == 0 {
			td = 1
		}
		s.tsOffset = in.Timestamp - (s.lastTS + uint32(td))
		s.snOffset = in.SequenceNumber - s.lastSN - 1

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

	s.lastUnixnanosNow = unixnano
	s.lastTS = in.Timestamp
	s.lastSN = in.SequenceNumber
	s.lastSSRC = in.SSRC

	in.Timestamp -= s.tsOffset
	in.SequenceNumber -= s.snOffset

}
