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
	"strconv"

	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"path/filepath"
	"runtime"
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

	"github.com/pion/webrtc/v3"

	"github.com/x186k/deadsfu/rtpstuff"
)

var lastVideoRxTime time.Time
var receivingVideo bool
var sendingIdleVid bool

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
var ticker100ms = time.NewTicker(100 * time.Millisecond)
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
	IdleVideo TrackId = 0
	Video     TrackId = iota
	Audio     TrackId = iota
	Data      TrackId = iota
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

func logNotFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		elog.Printf("NON-FATAL ERROR %s:%d %v", filepath.Base(fileName), fileLine, err)
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
		panic("You have NOT built the binaries correctly. idle data is missing")
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
			case "media":
				mediaDebugTickerChan = time.NewTicker(4 * time.Second).C
				mediaDebug = true
			case "main":
				mainlog = true
			case "help":
				fallthrough
			default:
				elog.Fatal("--z-debug sub-flags are: main, help, media")
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

	go idleLoopPlayer(p)

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

		go func() {
			for {
				attemptSingleFtlSession()
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

func attemptSingleFtlSession() {

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
			rxMediaCh <- MsgRxPacket{rxid: Video, packet: &p, rxClockRate: 90000}
		case 97:
			rxMediaCh <- MsgRxPacket{rxid: Audio, packet: &p, rxClockRate: 48000}
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

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	checkFatal(err)
	return hex.EncodeToString(bytes)
}

func idleLoopPlayer(p []rtp.Packet) {

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

			rxMediaCh <- MsgRxPacket{rxid: IdleVideo, packet: &v, rxClockRate: 90000}

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

	panic("<bad TrackId>")
}

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

		// send vid on video track, etc
		//pline()
		//make a copy
		// var ipacket interface{}
		// ipacket = rtpPacketPool.Get()
		// packet = ipacket.(*rtp.Packet)
		// tr.splicer.snOffset, tr.splicer.tsOffset)
		//fmt.Printf("write send=%v ix=%d mediarxid=%d txtracks[i].rxid=%d  %x %x %x\n",
		//	send, i, rxid, tr.rxid, packet.SequenceNumber, packet.Timestamp, packet.SSRC)
		// slice tricks non-order preserving delete
		// *packet = rtp.Packet{}
		// rtpPacketPool.Put(ipacket)
		handlePacket(m)

	case m := <-subAddTrackCh:

		txtracks = append(txtracks, m.txtrack)

	case <-mediaDebugTickerChan:

		medialog.Println("receivingVideo", receivingVideo)
		medialog.Println("sendingIdleVid", sendingIdleVid)

		for i, v := range txtracks {
			medialog.Println("tx", TrackId(i).String(), i, "ssrc", v.splicer.lastSSRC)
		}
		medialog.Println()

	case now := <-ticker100ms.C:

		receivingVideo = now.Sub(lastVideoRxTime) <= time.Second

	}
}

func handlePacket(m MsgRxPacket) {
	iskeyframe := false

	if m.rxid == Audio {
		return
	}

	if m.rxid == IdleVideo {
		if !receivingVideo && !sendingIdleVid {
			iskeyframe = rtpstuff.IsH264Keyframe(m.packet.Payload)
			if iskeyframe {
				sendingIdleVid = true
			}
		}
		if !sendingIdleVid {
			return
		}
	} else if m.rxid == Video {
		lastVideoRxTime = time.Now()

		if receivingVideo && sendingIdleVid {
			iskeyframe = rtpstuff.IsH264Keyframe(m.packet.Payload)
			if iskeyframe {
				sendingIdleVid = false
			}
		}
		if sendingIdleVid {
			return
		}
	}

	for i, tr := range txtracks {

		if m.rxid != tr.txid {
			sendanyway := m.rxid == IdleVideo && tr.txid == Video
			if sendanyway {
				goto sendit
			}
			continue
		}

	sendit:

		o := *m.packet

		pkt := SpliceRTP(tr.splicer, &o, time.Now().UnixNano(), int64(m.rxClockRate))

		key := ""
		if (m.rxid == IdleVideo || m.rxid == Video) && rtpstuff.IsH264Keyframe(m.packet.Payload) {
			key = "##"
		}

		if tr.txid == Video {
			println(333, "0x"+strconv.FormatInt(int64(pkt.SSRC), 16),
				pkt.SequenceNumber, pkt.Timestamp, len(pkt.Payload),
				key)

		}

		err := tr.track.WriteRTP(pkt)
		if err == io.ErrClosedPipe {
			log.Printf("track io.ErrClosedPipe, removing track %s", tr.txid)

			txtracks[i] = txtracks[len(txtracks)-1]
			txtracks[len(txtracks)-1] = nil
			txtracks = txtracks[:len(txtracks)-1]

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
var _ = SpliceRTPInPlace

func SpliceRTPInPlace(state *RtpSplicer, pkt *rtp.Packet, unixnano int64, rtphz int64) {

	forceKeyFrame := false

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	if pkt.SSRC != state.lastSSRC || forceKeyFrame {
		if mediaDebug {
			medialog.Printf("### SpliceRTP: %p: ssrc changed new=%v cur=%v", state, pkt.SSRC, state.lastSSRC)
		}

		td := unixnano - state.lastUnixnanosNow // nanos
		if td < 0 {
			td = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		td *= rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		if td == 0 {
			td = 1
		}
		state.tsOffset = pkt.Timestamp - (state.lastTS + uint32(td))
		state.snOffset = pkt.SequenceNumber - state.lastSN - 1
	}

	state.lastUnixnanosNow = unixnano
	state.lastTS = pkt.Timestamp
	state.lastSN = pkt.SequenceNumber
	state.lastSSRC = pkt.SSRC

	pkt.Timestamp -= state.tsOffset
	pkt.SequenceNumber -= state.snOffset

}

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
