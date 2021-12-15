package main

//force new build

import (
	"archive/zip"
	"bytes"
	"context"
	"embed"
	"math/rand"
	"net"
	"path"
	"strconv"
	"sync"
	"unsafe"

	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"path/filepath"
	"runtime"

	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/pflag"
	"golang.org/x/sync/semaphore"

	"github.com/pkg/profile"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"

	"github.com/x186k/ftlserver"

	//redigo "github.com/gomodule/redigo/redis"

	"net/http/httputil"
	_ "net/http/pprof"
)

// https://tools.ietf.org/id/draft-ietf-mmusic-msid-05.html
// msid:streamid trackid/appdata
// per RFC appdata is "application-specific data", we use a/b/c for simulcast
const (
	mediaStreamId = "x186k"
	videoMimeType = "video/h264"
	audioMimeType = "audio/opus"
	whipPath      = "/whip"
	whapPath      = "/whap" // 2nd slash important
)

const (
	IdleVideo  TrackId = 0
	Video      TrackId = iota
	Audio      TrackId = iota
	Data       TrackId = iota
	NumTrackId         = iota
)

type MsgRxPacket struct {
	rxid        TrackId
	rxClockRate uint32
	packet      *rtp.Packet
}
type MsgSubscriberAddTrack struct {
	txtrack *TxTrack
}

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

// size optimized, not readability
type TxTrack struct {
	track   *webrtc.TrackLocalStaticRTP
	splicer *RtpSplicer
	txid    TrackId
}

type myFtlServer struct {
	badrtp    int
	badssrc   int
	audiossrc uint32
	videossrc uint32
	channelid uint32
	rxMediaCh chan MsgRxPacket
}

//the link between publishers and subscribers
// mostly the channel on which a /pub puts media for a /sub to send out
// this struct, is currently IMMUTABLE, ideally, it stays that way
type roomState struct {
	roomname    string
	ingressSema *semaphore.Weighted // is a publisher already using '/foobar' ??
	mediaCh     chan MsgRxPacket    // where publisher sends media for '/foobar'
	newTrackCh  chan MsgSubscriberAddTrack
	done        chan bool
}

var roomMap = make(map[string]*roomState)
var roomMapMutex sync.Mutex

var dialUpstreamUrl *url.URL

var Version = "version-unset"

//go:embed html
var htmlContent embed.FS

//go:embed deadsfu-binaries/idle-clip.zip
var idleClipZipBytes []byte

//go:embed deadsfu-binaries/favicon_io/favicon.ico
var favicon_ico []byte

//go:embed deadsfu-binaries/deadsfu-camera-not-available.mp4
var deadsfuCameraNotAvailableMp4 []byte

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:" + *stunServer},
		},
	},
}

var rtpoutConn *net.UDPConn

var idleMediaPackets []rtp.Packet

// logging notes
// use:
// log.Println(...)  for info messages that should be seen without enabling any debugging
const logFlags = log.Lmicroseconds | log.LUTC | log.Lshortfile | log.Lmsgprefix

var dbg = struct {
	url, media, https, ice, main, ftl, ddns, peerConn FastLogger
}{}
var dbgMap = map[string]*FastLogger{
	"url":            &dbg.url,
	"media":          &dbg.media,
	"https":          &dbg.https,
	"ice-candidates": &dbg.ice,
	"main":           &dbg.main,
	"ftl":            &dbg.ftl,
	"ddns":           &dbg.ddns,
	"peer-conn":      &dbg.peerConn,
}

var errlog = log.New(os.Stderr, "errlog", logFlags)

// note: log.Logger contains a mutex, which means log.Logger should not be copied around
// so use a pointer to log.logger
// https://eli.thegreenplace.net/2018/beware-of-copying-mutexes-in-go/

//Fast logger allows using if dbg.main.enabled in code hotspots
type FastLogger struct {
	*log.Logger
	enabled bool // this is the WHOLE point of this struct, it allows fast logging checks
}

func (x *FastLogger) Print(args ...interface{}) {
	if x.enabled {
		x.Logger.Print(args...)
	}
}

func (x *FastLogger) Printf(format string, args ...interface{}) {
	if x.enabled {
		x.Logger.Println(args...)
	}
}

func (x *FastLogger) Println(args ...interface{}) {
	if x.enabled {
		x.Logger.Println(args...)
	}
}

func logGoroutineCountToDebugLog() {
	n := -1
	for {
		nn := runtime.NumGoroutine()
		if nn != n {
			dbg.main.Println("NumGoroutine", nn)
			n = nn
		}
		time.Sleep(2 * time.Second)
	}
}

var checkFatalProhibited bool

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
	if checkFatalProhibited {
		panic("cannot call checkfatal so late in code! file issue!")
	}
}

var _ = pline

func pline() {
	_, fileName, fileLine, _ := runtime.Caller(1)
	fmt.Println("pline:", filepath.Base(fileName), fileLine)
}

var _ = fileline

func fileline() string {
	_, fileName, fileLine, _ := runtime.Caller(1)
	return filepath.Base(fileName) + ":" + strconv.Itoa(fileLine)
}

func validateEmbedFiles() {
	if _, err := htmlContent.ReadFile("html/index.html"); err != nil {
		panic("index.html failed to embed correctly")
	}
}

func init() {
	validateEmbedFiles()
}

func rtpReceiver(pconn net.PacketConn, rxMediaCh chan MsgRxPacket) {

	log.Printf("RTP/UDP WAITING ON %s", pconn.LocalAddr().String())

	c := pconn.(*net.UDPConn)

	buf := make([]byte, 2000)

	for {

		var p rtp.Packet

		n, err := c.Read(buf)
		if err != nil {
			continue // silent ignore
		}

		if len(buf) < 12 {
			continue //silent ignore
		}

		b := make([]byte, n)
		// this is necessary! pkt.raw/[]byte we chan-send gets modified
		// and next iteration of this loop will overwrite 'buf'
		copy(b, buf[:n])

		err = p.Unmarshal(b)
		if err != nil {
			continue //silent ignore
		}

		switch p.Header.PayloadType {
		case 96:
			// blocking is okay
			rxMediaCh <- MsgRxPacket{rxid: Video, packet: &p, rxClockRate: 90000}
		case 97:
			// blocking is okay
			rxMediaCh <- MsgRxPacket{rxid: Audio, packet: &p, rxClockRate: 48000}
		}

	}
}

func main() {
	var err error

	log.SetFlags(logFlags)
	log.SetPrefix("[log] ")
	log.SetOutput(os.Stdout)

	println("deadsfu Version " + Version)

	parseFlags()
	oneTimeFlagsActions() //if !strings.HasSuffix(os.Args[0], ".test") {

	verifyEmbedFiles()
	idleMediaLoader()

	go logGoroutineCountToDebugLog()

	if *dialUpstreamUrlFlag != "" {
		dialUpstreamUrl, err = url.Parse(*dialUpstreamUrlFlag)

		checkFatal(err) //okay
		if dialUpstreamUrl.Path == "/" {
			dialUpstreamUrl.Path = ""
		}
		if dialUpstreamUrl.Path != "" || len(dialUpstreamUrl.Query()) > 0 {
			checkFatal(fmt.Errorf("--dial-upstream must not have any path or query params"))
		}
	}

	if *httpFlag == "" && *httpsDomainFlag == "" {
		pflag.Usage()
		os.Exit(-1)
	}
	if *htmlSource == "" {
		pflag.Usage()
		os.Exit(-1)
	}

	mux, err := setupMux()
	checkFatal(err) //okay

	if *httpFlag != "" {
		ln, err := net.Listen("tcp", *httpFlag)
		checkFatal(err) //okay
		var mux2 http.Handler = mux
		if *httpsDomainFlag != "" {
			mux2 = certmagic.DefaultACME.HTTPChallengeHandler(mux)
		}
		server := &http.Server{Handler: mux2}
		log.Println("SFU HTTP IS READY ON", ln.Addr())

		go func() {
			checkFatal(server.Serve(ln)) //okay
		}()
	}

	ctx := context.Background() // not really used well

	if *httpsDomainFlag != "" {
		go startHttpsListener(ctx, *httpsDomainFlag, mux)
	}

	if len(*rtprx) > 0 {

		//if (*rtprx)[0]=="help" {

		link := getRoomState("") //default room

		for _, v := range *rtprx {

			var err error

			pconn, err := net.ListenPacket("udp", v)
			checkFatal(err)
			defer pconn.Close()

			go func() {
				rtpReceiver(pconn, link.mediaCh)
			}()

		}

	}

	if *ftlKey != "" {

		go func() {
			config := &net.ListenConfig{}
			ln, err := config.Listen(context.Background(), "tcp", ":8084")
			if err != nil {
				log.Fatalln(err)
			}
			defer ln.Close()
			err = startFtlListener(ln)
			if err != nil {
				errlog.Print("ftl listener shutting down:", err.Error())
			}
		}()

	}

	// okay. sigh. both

	//the user can specify zero for port, and Linux/etc will choose a port

	checkFatalProhibited = true // make sure we are not called checkFatal after main init

	// block here
	if *cpuprofile == 0 {
		select {}
	}

	println("profiling enabled, runtime seconds:", *cpuprofile)

	defer profile.Start(profile.CPUProfile).Stop()

	time.Sleep(time.Duration(*cpuprofile) * time.Second)

	println("profiling done, exit")
}

func handleSetCookieStatsShipper(next http.Handler, url string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// will be "" to delete
		value := url

		cookie1 := &http.Cookie{Name: "getstats-shipper-url", Value: value, HttpOnly: false}
		http.SetCookie(w, cookie1)

		next.ServeHTTP(w, r)
	})
}

// if a user accidentially sends an SDP to something other than /pub or /sub
// tell them! we are supposed to be the dead-simple sfu. lol
func handleSDPWarning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "POST" {
			next.ServeHTTP(w, r)
			return
		}

		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// https://stackoverflow.com/a/23077519/86375
		r.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

		str := string(buf)

		sdpSignature := strings.HasPrefix(str, "v=0")
		if sdpSignature {
			err := fmt.Errorf("WebRTC SDPs should only be sent to /pub, or /sub, not: %s", r.URL.EscapedPath())
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)

	})
}

func setupMux() (*http.ServeMux, error) {

	mux := http.NewServeMux()

	// handle: /whap
	mux.Handle(whapPath, commonPubSubHandler(subHandler))

	// handle: /whip if configured to do so
	if len(*dialUpstreamUrlFlag) == 0 {
		mux.Handle(whipPath, commonPubSubHandler(pubHandler))
	}

	httpPrefix := strings.HasPrefix(*htmlSource, "http://")
	httpsPrefix := strings.HasPrefix(*htmlSource, "https://")

	var rootmux http.Handler

	if *htmlSource == "none" {
		return mux, nil
	} else if *htmlSource == "internal" {
		f, err := fs.Sub(htmlContent, "html")
		checkFatal(err) //okay

		fsys := dotFileHidingFileSystemPlus{http.FS(f)}

		rootmux = handleSDPWarning(http.FileServer(fsys))

	} else if httpPrefix || httpsPrefix {

		u, err := url.Parse(*htmlSource)
		checkFatal(err) //okay
		rootmux = httputil.NewSingleHostReverseProxy(u)

	} else {

		s, err := os.Stat(*htmlSource)
		checkFatal(err) //okay
		if !s.IsDir() {
			checkFatal(fmt.Errorf("--html <path>, must refer to a directory when using filepath: %s", *htmlSource))
		}

		if _, err := os.Stat(path.Join(*htmlSource, "index.html")); os.IsNotExist(err) {
			checkFatal(fmt.Errorf("--html <path>, must point to dir containing index.html: %s", *htmlSource))
		}

		f := os.DirFS(*htmlSource)

		fsys := dotFileHidingFileSystemPlus{http.FS(f)}

		rootmux = handleSDPWarning(http.FileServer(fsys))

	}

	rootmux = handleSetCookieStatsShipper(rootmux, *getStatsLogging)

	mux.Handle("/", rootmux)

	mux.HandleFunc("/favicon.ico", func(rw http.ResponseWriter, r *http.Request) {
		readseek := bytes.NewReader(favicon_ico)
		http.ServeContent(rw, r, "favicon.ico", time.Time{}, readseek)
	})

	mux.HandleFunc("/no-camera.mp4", func(rw http.ResponseWriter, r *http.Request) {
		readseek := bytes.NewReader(deadsfuCameraNotAvailableMp4)
		http.ServeContent(rw, r, "/no-camera.mp4", time.Time{}, readseek)
	})

	if false {
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

	return mux, nil
}

func newPeerConnection() (*webrtc.PeerConnection, error) {

	// Do NOT share MediaEngine between PC!  BUG of 020321
	// with Sean & Orlando. They are so nice.
	m := &webrtc.MediaEngine{}

	i := &interceptor.Registry{}
	_ = i
	err := webrtc.RegisterDefaultInterceptors(m, i)
	if err != nil {
		return nil, err
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

	err = RegisterH264AndOpusCodecs(m)
	if err != nil {
		return nil, err
	}

	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	if err != nil {
		return nil, err
	}

	return peerConnection, nil
}

func commonPubSubHandler(hfunc http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		dbg.main.Println("commonPubSubHandler request", r.URL.String(), r.Header.Get("Content-Type"))

		//could be OPTIONS
		if handlePreflight(r, w) {
			return
		}

		if r.Method != "POST" {
			err := fmt.Errorf("only POST allowed")
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if r.Header.Get("Content-Type") != "application/sdp" {
			err := fmt.Errorf("Content-Type application/sdp required")
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if *bearerToken != "" {
			tok := ""
			tok = r.URL.Query().Get("access_token")
			if tok != "" {
				if tok == *bearerToken {
					goto goodToken
				}
				m := "access_token query param found, with invalid bearer token."
				log.Println(m)
				http.Error(w, m, 401)
				return
			}

			tok = r.Header.Get("Authorization")
			if strings.HasPrefix(tok, "Bearer ") {
				tok = strings.TrimPrefix(tok, "Bearer ")
				if tok == *bearerToken {
					goto goodToken
				}
				m := "Authorization: header found, with invalid bearer token."
				log.Println(m)
				http.Error(w, m, 401)
				return
			}

			m := "bearer token required, but not provided."
			log.Println(m)
			http.Error(w, m, 401)
			return
		}
	goodToken:

		hfunc(w, r)

	})
}

// sfu ingress setup
//NOTE, Do NOT ever use http.error to return SDPs
func pubHandler(rw http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	offer, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(string(offer), "v=") {
		err := fmt.Errorf("invalid SDP message")
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	roomname := r.URL.Query().Get("room") // "" is permitted, most common room name!
	link := getRoomState(roomname)

	dbg.url.Println("pubHandler", link.roomname, unsafe.Pointer(link), r.URL.String())

	sdpCh := make(chan *webrtc.SessionDescription)
	errCh := make(chan error)

	if *dialUpstreamUrlFlag != "" {
		panic("internal-err-120")
	}

	if !link.ingressSema.TryAcquire(1) {
		err := fmt.Errorf("Rejected: The URL path [%s] already has a publisher", roomname)
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	go func() {
		defer link.ingressSema.Release(1)

		err := pubHandlerCreatePeerconn(string(offer), link, sdpCh)
		if err != nil {
			errlog.Println(err.Error())
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	select {
	case <-time.NewTimer(time.Second * 10).C:
		err := fmt.Errorf("timeout setting up pub Peerconn for room %s", roomname)
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)

	case answersd := <-sdpCh:
		rw.Header().Set("Content-Type", "application/sdp")
		rw.WriteHeader(201)
		_, err = rw.Write([]byte(answersd.SDP))
		if err != nil {
			log.Println(err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

	case err := <-errCh:
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		//case <-time.NewTicker(24*time.Hour).C:
	}

}

func getRoomState(roomname string) *roomState {

	if roomname == "" {
		roomname = "mainroom"
	}

	roomMapMutex.Lock()
	link, found := roomMap[roomname]
	if !found {
		link = &roomState{
			roomname:    roomname,
			ingressSema: semaphore.NewWeighted(int64(1)),
			mediaCh:     make(chan MsgRxPacket, 100),
			newTrackCh:  make(chan MsgSubscriberAddTrack, 10),
			done:        make(chan bool),
		}
		roomMap[roomname] = link

		go idleMediaSenderGr(link)
		go mediaFanOutGr(link)
	}
	roomMapMutex.Unlock()
	return link
}

func handlePreflight(req *http.Request, w http.ResponseWriter) bool {
	if req.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(200) //200 from https://stackoverflow.com/a/46028619/86375

		return true
	}

	//put this on every request
	w.Header().Set("Access-Control-Allow-Origin", "*")

	return false
}

func subHandlerGR(offersdp string, link *roomState, sdpCh chan *webrtc.SessionDescription) error {
	peerConnection, err := newPeerConnection()
	if err != nil {
		return err
	}
	defer peerConnection.Close()

	logTransceivers("new-pc", peerConnection)

	// NO!
	// peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {...}
	// Pion says:
	// "OnTrack sets an event handler which is called when remote track arrives from a remote peer."
	// the 'sub' side of our SFU just Pushes tracks, it can't receive them,
	// so there is no OnTrack handler

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offersdp}

	// if !ValidateSDP(offer) {
	// 	return fmt.Errorf("invalid offer SDP received")
	// }

	logSdpReport("sub-offer", offer)
	if err != nil {
		return err
	}

	err = peerConnection.SetRemoteDescription(offer)
	if err != nil {
		return err
	}

	logTransceivers("offer-added", peerConnection)

	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	if err != nil {
		return err
	}
	rtpSender, err := peerConnection.AddTrack(track)
	if err != nil {
		return err
	}
	go processRTCP(rtpSender)

	// blocking is okay
	link.newTrackCh <- MsgSubscriberAddTrack{
		txtrack: &TxTrack{
			track:   track,
			splicer: &RtpSplicer{},
			txid:    Audio,
		},
	}

	track, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video", mediaStreamId)
	if err != nil {
		return err
	}
	rtpSender2, err := peerConnection.AddTrack(track)
	if err != nil {
		return err
	}
	go processRTCP(rtpSender2)

	// blocking is okay
	link.newTrackCh <- MsgSubscriberAddTrack{
		txtrack: &TxTrack{
			track:   track,
			splicer: &RtpSplicer{},
			txid:    Video,
		},
	}

	logTransceivers("subHandler-tracksadded", peerConnection)

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return err
	}

	// Sets the LocalDescription, and starts our UDP listeners, starts ICE
	err = peerConnection.SetLocalDescription(sessdesc)
	if err != nil {
		return err
	}

	// without this, there will be zero! a=candidates in sdp
	<-webrtc.GatheringCompletePromise(peerConnection)

	// Get the LocalDescription and take it to base64 so we can paste in browser
	ansrtcsd := peerConnection.LocalDescription()

	logSdpReport("sub-answer", *ansrtcsd)

	select {
	case sdpCh <- peerConnection.LocalDescription():
	default:
		errlog.Println("send fail: sdp to publisher")
		return nil
	}

	waitPeerconnClosed("sub", link, peerConnection)

	return nil
}

// Blocks until PC is Closed
func subHandler(rw http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var err error

	dbg.main.Println("subHandler request", r.URL.String())

	// rx offer, tx answer
	// offer from browser
	offersdpbytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	roomname := r.URL.Query().Get("room") // "" is permitted, most common room name!
	link := getRoomState(roomname)

	dbg.url.Println("subHandler", link.roomname, unsafe.Pointer(link), r.URL.String())

	sdpCh := make(chan *webrtc.SessionDescription)
	errCh := make(chan error)

	go func() {

		err := subHandlerGR(string(offersdpbytes), link, sdpCh)
		if err != nil {
			errlog.Println(err.Error())
			select {
			case errCh <- err:
			default:
			}
		}

	}()

	select {
	case <-time.NewTimer(time.Second * 10).C:
		err := fmt.Errorf("timeout setting up sub Peerconn for room %s", roomname)
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)

	case sd := <-sdpCh:
		rw.Header().Set("Content-Type", "application/sdp")
		rw.WriteHeader(201)
		_, err = rw.Write([]byte(sd.SDP))
		if err != nil {
			log.Println(err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

	case err := <-errCh:
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		//case <-time.NewTicker(24*time.Hour).C:
	}

}

func logTransceivers(tag string, pc *webrtc.PeerConnection) {
	if len(pc.GetTransceivers()) == 0 {
		dbg.main.Printf("%v transceivers is empty", tag)
	}
	for i, v := range pc.GetTransceivers() {
		rx := v.Receiver()
		tx := v.Sender()
		dbg.main.Printf("%v transceiver %v,%v,%v,%v nilrx:%v niltx:%v", tag, i, v.Direction(), v.Kind(), v.Mid(), rx == nil, tx == nil)

		if rx != nil && len(rx.GetParameters().Codecs) > 0 {
			dbg.main.Println(" rtprx ", rx.GetParameters().Codecs[0].MimeType)
		}
		if tx != nil && len(tx.GetParameters().Codecs) > 0 {
			dbg.main.Println(" rtptx ", tx.GetParameters().Codecs[0].MimeType)
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
	if !good {
		len := len(rtcsd.SDP)
		if len > 20 {
			len = 20
		}
		errlog.Println(fmt.Errorf("Invalid sdp, no v=0 startline:%s", rtcsd.SDP[:len]))
		return
	}
	nlines := len(strings.Split(strings.Replace(rtcsd.SDP, "\r\n", "\n", -1), "\n"))
	dbg.main.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	dbg.main.Println("fullsdp", wherefrom, rtcsd.SDP)

	sd, err := rtcsd.Unmarshal()
	if err != nil {
		errlog.Println(fmt.Errorf("rtcsd.Unmarshal() fail:%w", err))
		return
	}
	dbg.main.Printf(" n/%d media descriptions present", len(sd.MediaDescriptions))

	ncandidates := 0
	for _, v := range strings.Split(strings.ReplaceAll(rtcsd.SDP, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(v, "a=candidate") {
			dbg.ice.Println(wherefrom, v)
			ncandidates++
		}
	}
	dbg.ice.Println(wherefrom, "ice candidates found/printed", ncandidates)

}

func verifyEmbedFiles() {
	if len(idleClipZipBytes) == 0 {
		checkFatal(fmt.Errorf("embed idleClipZipBytes is zero-length!"))
	}

	if len(deadsfuCameraNotAvailableMp4) == 0 {
		checkFatal(fmt.Errorf("embed deadsfuCameraNotAvailableMp4 is zero-length!"))
	}

	if len(favicon_ico) == 0 {
		checkFatal(fmt.Errorf("embed deadsfuCameraNotAvailableMp4 is zero-length!"))
	}

}

func idleMediaLoader() {
	if *idleClipZipfile == "" && *idleClipServerInput == "" {

		idleMediaPackets = readRTPFromZip(idleClipZipBytes)
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
		idleMediaPackets = readRTPFromZip(body)
		log.Println(len(idleMediaPackets), "encoded rtp packets retrieved from", *idleClipServerURL)

	} else if *idleClipZipfile != "" {
		buf, err := ioutil.ReadFile(*idleClipZipfile)
		checkFatal(err)
		idleMediaPackets = readRTPFromZip(buf)

	} else {
		panic("badlogic")
	}

	if len(idleMediaPackets) == 0 {
		if len(idleMediaPackets) == 0 {
			checkFatal(fmt.Errorf("embedded idle-clip.zip is zero-length!"))
		}
	}

	idleMediaPackets = removeH264AccessDelimiterAndSEI(idleMediaPackets)

}

func idleMediaSenderGr(link *roomState) {

	fps := 5
	seqno := uint16(0)
	tstotal := uint32(0)

	basetime := time.Now()

	framedur90 := uint32(90000 / fps)

	pktsDur90 := idleMediaPackets[len(idleMediaPackets)-1].Timestamp - idleMediaPackets[0].Timestamp

	totalDur90 := pktsDur90/framedur90*framedur90 + framedur90

	for {

		for _, pkt := range idleMediaPackets {

			// rollover should be okay for uint32: https://play.golang.org/p/VeIBZgorleL
			tsdelta := pkt.Timestamp - idleMediaPackets[0].Timestamp

			tsdeltaDur := time.Duration(tsdelta) * time.Second / 90000

			when := basetime.Add(tsdeltaDur)

			time.Sleep(time.Until(when)) //time.when() should be zero if when < time.now()

			pkt.SequenceNumber = seqno
			seqno++
			pkt.Timestamp = tsdelta + tstotal

			copy := pkt // critical!, we must make a copy!
			//blocking is okay
			link.mediaCh <- MsgRxPacket{rxid: IdleVideo, packet: &copy, rxClockRate: 90000}

		}

		tstotal += totalDur90
		basetime = basetime.Add(time.Duration(totalDur90) * time.Second / 90000)

		time.Sleep(time.Until(basetime))

		select {
		case <-link.done:
			return
		default:
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
		}

	}
	return p2
}

func dialUpstream(link *roomState) error {

	var u url.URL

	u.Scheme = dialUpstreamUrl.Scheme
	u.Host = dialUpstreamUrl.Host
	u.Path = "/whap"

	q := u.Query()
	q.Set("room", link.roomname)
	u.RawQuery = q.Encode()

	peerConnection, err := newPeerConnection()
	if err != nil {
		return err
	}
	defer peerConnection.Close()

	dbg.url.Println("dialing upstream", link.roomname, unsafe.Pointer(link), u.String())

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingressOnTrack(peerConnection, track, receiver, link.mediaCh)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		dbg.main.Println("dial ICE Connection State has changed", icecs.String())
	})

	recvonly := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}
	// create transceivers for 1x audio, 3x video
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, recvonly)
	if err != nil {
		return err
	}
	_, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, recvonly)
	if err != nil {
		return err
	}
	// Create an offer to send to the other process
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		return err
	}

	logSdpReport("dialupstream-offer", offer)

	// Sets the LocalDescription, and starts our UDP listeners
	// Note: this will start the gathering of ICE candidates
	err = peerConnection.SetLocalDescription(offer)
	if err != nil {
		return err
	}

	// without this, there will be zero! a=candidates in sdp
	<-webrtc.GatheringCompletePromise(peerConnection)

	// send offer, get answer

	dbg.main.Println("sending post", u.String())

	req, err := http.NewRequest("POST", u.String(), strings.NewReader(offer.SDP))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/sdp")
	if *bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+*bearerToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dbg.main.Println("dial connected")

	answerraw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	anssd := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	logSdpReport("dial-answer", anssd)

	err = peerConnection.SetRemoteDescription(anssd)
	if err != nil {
		return err
	}

	waitPeerconnClosed("dial", link, peerConnection)

	return nil

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

	dbg.main.Print(b.String())
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

func ingressOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver, rxMediaCh chan MsgRxPacket) {
	_ = receiver //silence warnings

	mimetype := track.Codec().MimeType
	dbg.main.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		dbg.main.Println("OnTrack audio", mimetype)

		inboundTrackReader(track, Audio, track.Codec().ClockRate, rxMediaCh)
		//here on error
		dbg.main.Printf("audio reader %p exited", track)
		return
	}

	// audio callbacks never get here
	// video will proceed here

	if strings.ToLower(mimetype) != videoMimeType {
		panic("unexpected kind or mimetype:" + track.Kind().String() + ":" + mimetype)
	}

	dbg.main.Println("OnTrack RID():", track.RID())
	dbg.main.Println("OnTrack MediaStream.id [msid ident]:", track.StreamID())
	dbg.main.Println("OnTrack MediaStreamTrack.id [msid appdata]:", track.ID())

	go func() {
		var err error

		for {
			err = sendPLI(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			} else if err != nil {
				errlog.Println(err.Error())
				return
			}

			err = sendREMB(peerConnection, track)
			if err == io.ErrClosedPipe {
				return
			} else if err != nil {
				errlog.Println(err.Error())
				return
			}

			time.Sleep(3 * time.Second)
		}
	}()

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, Video, track.Codec().ClockRate, rxMediaCh)
	//here on error
	dbg.main.Printf("video reader %p exited", track)

}

func inboundTrackReader(rxTrack *webrtc.TrackRemote, rxid TrackId, clockrate uint32, rxMediaCh chan MsgRxPacket) {

	for {
		p, _, err := rxTrack.ReadRTP()
		if err == io.EOF {
			return
		} else if err != nil {
			errlog.Println(err.Error())
			return
		}

		// blocking is okay
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

func mediaFanOutGr(link *roomState) {
	var lastVideoRxTime time.Time = time.Now()
	var sendingIdleVid bool
	var inputSplicers = make([]RtpSplicer, NumTrackId)
	var txtracks []*TxTrack

	for {

		// should block, no default case
		select {

		case <-link.done: // this room is done? not currently closed/sent
			return

		case m := <-link.mediaCh:

			idlePkt := m.rxid == IdleVideo

			mainVidPkt := m.rxid == Video

			if idlePkt {
				rxActive := time.Since(lastVideoRxTime) <= time.Second

				if !rxActive && !sendingIdleVid {
					iskeyframe := isH264Keyframe(m.packet.Payload)
					if iskeyframe {
						sendingIdleVid = true
						log.Println("SWITCHING TO IDLE, NO INPUT VIDEO PRESENT")
					}
				}

			} else if mainVidPkt {

				lastVideoRxTime = time.Now()

				if sendingIdleVid {
					iskeyframe := isH264Keyframe(m.packet.Payload)
					if iskeyframe {
						sendingIdleVid = false
						log.Println("SWITCHING TO INPUT, AS INPUT CAME UP")
					}
				}
			}

			if sendingIdleVid && mainVidPkt {
				continue
			}
			if !sendingIdleVid && idlePkt {
				continue
			}

			//break dial upstream
			// if idlePkt && *dialUpstreamUrlFlag != "" {
			// 	// if this room is receiving the idle video, not 'real' ingress
			// 	// and we have dialUpstream urls
			// 	// we will see if we can connect to the upstream, by dialing it

			// 	if link.ingressSema.TryAcquire(1) {
			// 		go func() {
			// 			defer link.ingressSema.Release(1)

			// 			err := dialUpstream(link) // blocks until closed
			// 			if err != nil {
			// 				errlog.Println(err.Error())
			// 				time.Sleep(time.Second)
			// 			}

			// 		}()
			// 	}
			// }

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
			SpliceRTP(&inputSplicers[txtype], &pkt, time.Now().UnixNano(), int64(m.rxClockRate))

			if txtype == Audio && rtpoutConn != nil {
				//ptmp := pkt //copy
				rtpbuf, err := pkt.Marshal()
				if err != nil {
					errlog.Print(err.Error())
				}
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
					dbg.main.Printf("track io.ErrClosedPipe, removing track %s", tr.txid)

					// slice tricks non-order preserving delete
					txtracks[i] = txtracks[len(txtracks)-1]
					txtracks[len(txtracks)-1] = nil
					txtracks = txtracks[:len(txtracks)-1]

				}

			}

		case m := <-link.newTrackCh:

			txtracks = append(txtracks, m.txtrack)

		}
	}
}

func sendREMB(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.ReceiverEstimatedMaximumBitrate{Bitrate: 10000000, SenderSSRC: uint32(track.SSRC())}})
}

func sendPLI(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}})
}

// Blocks until PC is Closed
func pubHandlerCreatePeerconn(offersdp string, link *roomState, sdpCh chan *webrtc.SessionDescription) error {

	dbg.main.Println("createIngressPeerConnection")

	peerConnection, err := newPeerConnection()
	if err != nil {
		return err
	}
	defer peerConnection.Close()

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingressOnTrack(peerConnection, track, receiver, link.mediaCh)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		dbg.main.Println("ingress ICE Connection State has changed", icecs.String())
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
	//debugLog.Println("num senders", len(peerConnection.GetSenders()))
	// for _, rtpSender := range peerConnection.GetSenders() {
	// 	go processRTCP(rtpSender)
	// }

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdp)}
	logSdpReport("publisher", offer)

	err = peerConnection.SetRemoteDescription(offer)
	if err != nil {
		return fmt.Errorf("pc.SetRemoteDescription() fail %w", err)
	}

	// Create answer
	sessdesc, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("pc.CreateAnswer() fail %w", err)
	}

	// Sets the LocalDescription, and starts our UDP listeners
	err = peerConnection.SetLocalDescription(sessdesc)
	if err != nil {
		return fmt.Errorf("pc.SetLocalDescription() fail %w", err)
	}

	// without this, there will be zero! a=candidates in sdp
	<-webrtc.GatheringCompletePromise(peerConnection)

	logSdpReport("listen-ingress-answer", *peerConnection.LocalDescription())

	select {
	case sdpCh <- peerConnection.LocalDescription():
	default:
		errlog.Println("send fail: sdp to publisher")
		return nil
	}

	// Get the LocalDescription and take it to base64 so we can paste in browser
	waitPeerconnClosed("pub", link, peerConnection)

	return nil
}

func waitPeerconnClosed(debug string, link *roomState, pc *webrtc.PeerConnection) {

	done := make(chan struct{})

	pc.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		dbg.peerConn.Println(debug, link.roomname, unsafe.Pointer(link), "ConnectionState", cs.String())
		switch cs {
		case webrtc.PeerConnectionStateClosed:
			fallthrough
		case webrtc.PeerConnectionStateFailed:
			fallthrough
		case webrtc.PeerConnectionStateDisconnected:
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})

	<-done // get nil value when closed
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
func SpliceRTP(s *RtpSplicer, p *rtp.Packet, unixnano int64, rtphz int64) {

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

		dbg.main.Printf("** ssrc change [txid] rtphz/%v td1/%v td2/%v tsdelta/%v sndelta/%v", rtphz, td1, td2, (p.Timestamp-s.tsOffset)-s.lastTS, (p.SequenceNumber-s.snOffset)-s.lastSN)
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
		checkFatal(fmt.Errorf("zero-length rtp-zip file not gunna work")) //okay
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

func startFtlListener(ln net.Listener) error {

	for {
		dbg.ftl.Println("ftl/waiting for accept on:", ln.Addr())

		netconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("ftl: Accept() err %w", err)
		}

		dbg.ftl.Println("ftl/socket accepted")

		tcpconn := netconn.(*net.TCPConn)
		ftlserver.NewTcpSession(log.Default(), dbg.ftl.Logger, tcpconn, findserver, *ftlUdpPort)
		netconn.Close()
	}
	// unreachable
	//return
}

// XXX need to remove fatals eventually
// called during ftl connection
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
		if err != nil {
			errlog.Print(err.Error())
			return nil, ""
		}

		a := &myFtlServer{}
		a.audiossrc = uint32(rand.Int63())
		a.videossrc = uint32(rand.Int63())
		a.channelid = uint32(tmp64)
		return a, arr[1]
	}

	return nil, ""
}

// TakePacket
// if this returns false, it will tell server pkg to close connection
func (x *myFtlServer) TakePacket(inf *log.Logger, dbg *log.Logger, pkt []byte) bool {
	var err error

	var p rtp.Packet

	if len(pkt) < 12 {
		x.badrtp++
		return true //ignore and keep connection open
	}

	err = p.Unmarshal(pkt)
	if err != nil {
		x.badrtp++
		return true //ignore and keep connection open
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
		// blocking is okay
		x.rxMediaCh <- MsgRxPacket{rxid: Video, packet: &p, rxClockRate: 90000}

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
		// blocking is okay
		x.rxMediaCh <- MsgRxPacket{rxid: Audio, packet: &p, rxClockRate: 48000}
	}
	if x.badssrc > 0 && x.badssrc%100 == 10 {
		log.Println("Bad SSRC media received :(  count:", x.badssrc)
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

// containsDotFile reports whether name contains a path element starting with a period.
// The name is assumed to be a delimited by forward slashes, as guaranteed
// by the http.FileSystem interface.
func containsDotFile(name string) bool {
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// dotFileHidingFile is the http.File use in dotFileHidingFileSystem.
// It is used to wrap the Readdir method of http.File so that we can
// remove files and directories that start with a period from its output.
type dotFileHidingFile struct {
	http.File
}

// Readdir is a wrapper around the Readdir method of the embedded File
// that filters out all files that start with a period in their name.
func (f dotFileHidingFile) Readdir(n int) (fis []fs.FileInfo, err error) {
	files, err := f.File.Readdir(n)
	for _, file := range files { // Filters out the dot files
		if !strings.HasPrefix(file.Name(), ".") {
			fis = append(fis, file)
		}
	}
	return
}

// dotFileHidingFileSystemPlus is an http.FileSystem that hides
// hidden "dot files" from being served.
type dotFileHidingFileSystemPlus struct {
	http.FileSystem
}

// Open is a wrapper around the Open method of the embedded FileSystem
// that serves a 403 permission error when name has a file or directory
// with whose name starts with a period in its path.
func (fsys dotFileHidingFileSystemPlus) Open(name string) (http.File, error) {
	if containsDotFile(name) { // If dot file, return 403 response
		return nil, fs.ErrPermission
	}

	file, err := fsys.FileSystem.Open(name)
	// next three lines turn /foo/bar into /index.html
	// 12 9 21, these 3 lines can be part of a system where
	// room names are derived from the path. it means every path returns /index.html
	// if errors.Is(err, fs.ErrNotExist) {
	// 	file, err = fsys.FileSystem.Open("/index.html")
	// }
	if err != nil {
		return nil, err
	}
	return dotFileHidingFile{file}, err
}
