package sfu

//force new build

import (
	"archive/zip"
	"bytes"
	"context"
	crand "crypto/rand"

	"encoding/json"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"path"
	"strconv"
	"sync"

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

	"github.com/pkg/profile"

	//"net/http/httputil"

	//"github.com/davecgh/go-spew/spew"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"

	//redigo "github.com/gomodule/redigo/redis"

	"net/http/httputil"
	_ "net/http/pprof"

	"github.com/x186k/deadsfu"
	"github.com/x186k/deadsfu/ftlserver"

	"github.com/x186k/deadsfu/internal/newpeerconn"

	"github.com/google/uuid"

	"unsafe"
)

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64

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
type TxTrack struct {
	track     WriteRtpIntf
	splicer   RtpSplicer
	clockrate int
}

// There is no mutex for this, the parent must be mutexed!

type TxTrackPair struct {
	aud TxTrack
	vid TxTrack
}

type myFtlServer struct {
	badrtp    int
	badssrc   int
	audiossrc uint32
	videossrc uint32
	channelid uint32
	rxMediaCh chan rtp.Packet
}

//the link between publishers and subscribers
// mostly the channel on which a /pub puts media for a /sub to send out
// this struct, is currently IMMUTABLE, ideally, it stays that way
type Room struct {
	mu          sync.Mutex
	roomname    string
	ingressBusy bool
	xBroker     *XBroker
	tracks      *TxTracks
}

func (r *Room) PublisherTryLock() bool {

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ingressBusy {
		dbg.Roomcleaner.Printf("PublisherTryLock() room:%s already busy", r.roomname)
		return false // room ingres is busy!
	}
	r.ingressBusy = true
	//r.lastInUse = time.Now()

	dbg.Roomcleaner.Printf("PublisherTryLock() room:%s is now locked", r.roomname)

	return true

}
func (r *Room) PublisherUnlock() {
	r.mu.Lock()
	defer r.mu.Unlock()

	dbg.Roomcleaner.Printf("PublisherUnlock() room:%s is now unlocked", r.roomname)

	r.ingressBusy = false
	//r.lastInUse = time.Now()
}

func (r *Room) IsRoomBusy() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.tracks.IsEmpty() //double lock, maintain order
}

func (r *Room) IsDone() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	roomEmpty := !r.ingressBusy && r.tracks.IsEmpty()

	return roomEmpty
}

func (r *Room) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.xBroker.Stop()
	r.tracks = nil

}

type MsgGetSourcesList struct {
	serial int         // serial number from prior request
	jsonCh chan []byte // channel to return json over
}

var roomSetChangedCh = make(chan struct{}, 5) // we never want sender to 'default'
var getSourceListCh = make(chan MsgGetSourcesList, 1)

type RoomMap struct {
	mu      sync.Mutex
	roomMap map[string]*Room
}

func NewRoomMap() *RoomMap {
	return &RoomMap{
		roomMap: make(map[string]*Room),
	}
}

func (r *RoomMap) Get(name string) (*Room, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	room, ok := r.roomMap[name]
	return room, ok
}

func (r *RoomMap) GetList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	a := make([]string, 0, len(r.roomMap))

	for _, v := range r.roomMap {
		a = append(a, v.roomname)
	}

	return a
}

func (r *RoomMap) CloseDeadRooms() {
	r.mu.Lock()
	defer r.mu.Unlock()

	updated := false

	for name, room := range r.roomMap {

		if room.IsDone() {

			updated = true
			delete(r.roomMap, name)
			room.Close()

			dbg.Roomcleaner.Printf("CloseRoomIfNoPubNoSub() room:%s has no pubs, no subs, removing", name)

		}
	}

	if updated {
		select {
		case roomSetChangedCh <- struct{}{}:
		default:
			errlog.Println("cannot send on newRoomCh")
		}
	}

}

func RoomTerminator() {
	for {
		time.Sleep(2 * time.Second)
		rooms.CloseDeadRooms()
	}
}

var rooms = NewRoomMap()

var subMap = make(map[uuid.UUID]chan string)
var subMapMutex sync.Mutex

var dialUpstreamUrl *url.URL

var Version = "version-unset"

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:" + *stunServer},
		},
	},
}

//var rtpoutConn *net.UDPConn

var _ = idleMediaPackets
var idleMediaPackets []rtp.Packet

// logging notes
// use:
// log.Println(...)  for info messages that should be seen without enabling any debugging
const logFlags = log.Lmicroseconds | log.LUTC | log.Lshortfile | log.Lmsgprefix

var errlog = log.New(os.Stderr, "errlog", logFlags)

// note: log.Logger contains a mutex, which means log.Logger should not be copied around
// so use a pointer to log.logger
// https://eli.thegreenplace.net/2018/beware-of-copying-mutexes-in-go/

//Fast logger allows using if dbg.main.enabled in code hotspots
type FastLogger struct {
	help string
	*log.Logger
	enabled bool // this is the WHOLE point of this struct, it allows fast logging checks
}

func (x *FastLogger) Print(args ...interface{}) {
	if x.enabled {
		_ = log.Output(2, fmt.Sprint(args...))
	}
}

func (x *FastLogger) Printf(format string, args ...interface{}) {
	if x.enabled {
		_ = log.Output(2, fmt.Sprintf(format, args...))
	}
}

func (x *FastLogger) Println(args ...interface{}) {
	if x.enabled {
		_ = log.Output(2, fmt.Sprintln(args...))
	}
}

func PrintGoroutineCount() {
	n := -1
	for {
		nn := runtime.NumGoroutine()
		if nn != n {
			dbg.Numgoroutine.Println("NumGoroutine", nn)
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

var _ = pl

func pl(a ...interface{}) {
	b := fmt.Sprintln(a...)
	_ = log.Output(2, b)
}

var _ = wrap

func wrap(err error) error {
	_, fileName, fileLine, _ := runtime.Caller(1)
	return fmt.Errorf("at %s:%d %w", filepath.Base(fileName), fileLine, err)
}

func validateEmbedFiles() {
	if _, err := deadsfu.HtmlContent.ReadFile("html/index.html"); err != nil {
		panic("index.html failed to embed correctly")
	}
}

func Init() {
	pl(nanotime() / 1000000)
	bi, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	checkFatal(err)
	mrand.Seed(bi.Int64())
	validateEmbedFiles()
	idleMediaPackets = idleMediaLoader()
	pl(nanotime() / 1000000)
}

func Main() {
	var err error
	pl(nanotime() / 1000000)

	log.SetFlags(logFlags)
	log.SetPrefix("[log] ")
	log.SetOutput(os.Stdout)

	// gdbg := os.Getenv("GODEBUG")
	//  log.Printf("GODEBUG: %v", gdbg)

	println("deadsfu Version " + Version)

	parseFlags()
	oneTimeFlagsActions() //if !strings.HasSuffix(os.Args[0], ".test") {

	verifyEmbedFiles()

	go RoomListRequestHandler()
	if dbg.Numgoroutine.enabled {
		go PrintGoroutineCount()
	}
	go RoomTerminator()

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

		go HttpServer(server, ln)
	}

	ctx := context.Background() // not really used well

	if *httpsDomainFlag != "" {
		go startHttpsListener(ctx, *httpsDomainFlag, mux)
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
	if !*cpuprofile {
		select {}
	}

	println("press enter to START profiling")
	var input string
	fmt.Scanln(&input)
	println("profiling started")

	defer profile.Start(profile.CPUProfile).Stop()

	println("press enter to STOP profiling")
	fmt.Scanln(&input)

	println("profiling done, exiting")
}

func HttpServer(server *http.Server, ln net.Listener) {
	checkFatal(server.Serve(ln)) //okay
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

func switchHandler(rw http.ResponseWriter, r *http.Request) {

	a := getSubuuidFromRequest(r)
	if a == nil {
		dbg.Switching.Println("/switchRoom: invalid uuid passed into request")
		return
	}

	subMapMutex.Lock()
	subGrCh, ok := subMap[*a]
	subMapMutex.Unlock()

	if !ok { //that subscriber was not found
		dbg.Switching.Println(unsafe.Pointer(&subGrCh), "/switchRoom: subscriber not found for uuid:", a.String())
		return
	}

	name := r.URL.Query().Get("room")

	select {
	case subGrCh <- name:
		dbg.Switching.Println(unsafe.Pointer(&subGrCh), "/switchRoom: sent request to switch to room:", name)
	default:
		dbg.Switching.Println(unsafe.Pointer(&subGrCh), "/switchRoom: NOT! sent request to switch to room:", name)
	}
}

func setupMux() (*http.ServeMux, error) {

	mux := http.NewServeMux()

	// handle: /whap
	mux.Handle(whapPath, commonPubSubHandler(subHandler))

	// handle: /whip if configured to do so
	if len(*dialUpstreamUrlFlag) == 0 {
		mux.Handle(whipPath, commonPubSubHandler(pubHandler))
	}

	// room switching request
	mux.HandleFunc("/switchRoom", switchHandler)
	mux.HandleFunc("/getRoomList", getRoomListHandler)

	httpPrefix := strings.HasPrefix(*htmlSource, "http://")
	httpsPrefix := strings.HasPrefix(*htmlSource, "https://")

	var rootmux http.Handler

	if *htmlSource == "none" {
		return mux, nil
	} else if *htmlSource == "internal" {
		f, err := fs.Sub(deadsfu.HtmlContent, "html")
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
		readseek := bytes.NewReader(deadsfu.Favicon_ico)
		http.ServeContent(rw, r, "favicon.ico", time.Time{}, readseek)
	})

	mux.HandleFunc("/no-camera.mp4", func(rw http.ResponseWriter, r *http.Request) {
		readseek := bytes.NewReader(deadsfu.DeadsfuCameraNotAvailableMp4)
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
	//m := &webrtc.MediaEngine{}

	se := webrtc.SettingEngine{}

	if *iceCandidateHost != "" {
		se.SetNAT1To1IPs([]string{*iceCandidateHost}, webrtc.ICECandidateTypeHost)
	}
	if *iceCandidateSrflx != "" {
		se.SetNAT1To1IPs([]string{*iceCandidateSrflx}, webrtc.ICECandidateTypeSrflx)
		peerConnectionConfig.ICEServers = []webrtc.ICEServer{} // yuck
	}

	// with ion sfu
	// me, err := getPublisherMediaEngine()
	// if err != nil {
	// 	return nil, err
	// }

	//rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se))
	// good
	//XXXXXXXX
	// ion doesn't include :
	//webrtc.WithInterceptorRegistry(i))
	//rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se), webrtc.WithInterceptorRegistry(i))

	rtcapi, err := newpeerconn.NewWebRTCAPI()
	if err != nil {
		return nil, err
	}

	// bad, ~30kbps throughput on ingest
	//rtcapi := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithSettingEngine(se))

	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	if err != nil {
		return nil, err
	}

	return peerConnection, nil
}

func commonPubSubHandler(hfunc http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		dbg.Main.Println("commonPubSubHandler request", r.URL.String(), r.Header.Get("Content-Type"))

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
	link := rooms.GetOrMake(roomname)

	dbg.Url.Println("pubHandler", link.roomname, unsafe.Pointer(link), r.URL.String())

	sdpCh := make(chan *webrtc.SessionDescription)
	errCh := make(chan error)

	if *dialUpstreamUrlFlag != "" {
		panic("internal-err-120")
	}

	if !link.PublisherTryLock() {
		err := fmt.Errorf("Rejected: The URL path [%s] already has a publisher", roomname)
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		defer link.PublisherUnlock()

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

func fixRoomName(name string) string {
	//at this time, I have no other constraints of the valid chars
	//in a room name, we need unicode, yup
	// and any wacky json should get escaped by the marshaller
	// https://godocs.io/encoding/json#Marshal
	if name == "" {
		name = "mainroom"
	}
	return name
}

func getRoom(roomname string) (*Room, bool) {

	roomname = fixRoomName(roomname)

	link, ok := rooms.Get(roomname)
	return link, ok
}

func (rm *RoomMap) GetOrMake(roomname string) *Room {

	roomname = fixRoomName(roomname)

	//everything below here should be FAST
	rm.mu.Lock()
	defer rm.mu.Unlock()

	link, ok := rm.roomMap[roomname]

	if !ok {

		link = &Room{
			roomname: roomname,
			xBroker:  NewXBroker(),
			tracks:   NewTxTracks(),
		}

		go link.xBroker.Start()
		ch := link.xBroker.Subscribe() // can no longer block
		go Writer(ch, link.tracks, roomname)

		rm.roomMap[roomname] = link
	}

	// will never block, but new room notifications could get lost
	select {
	case roomSetChangedCh <- struct{}{}:
	default:
		errlog.Println("cannot send on newRoomCh")
	}

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

// subHandlerGr will block until the PC is done
func subHandlerGr(offersdp string,
	link *Room,
	sdpCh chan *webrtc.SessionDescription,
	subGrCh chan string) error {
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

	audioTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	if err != nil {
		return err
	}
	rtpSender, err := peerConnection.AddTrack(audioTrack)
	if err != nil {
		return err
	}
	go processRTCP(rtpSender)

	videoTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video", mediaStreamId)
	if err != nil {
		return err
	}

	if false {
		// I don't know what this would do exactly, if it would help, or wrongly add track twice
		sendonly := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly}
		_, err := peerConnection.AddTransceiverFromTrack(videoTrack, sendonly)
		if err != nil {
			return err
		}
	}
	rtpSender2, err := peerConnection.AddTrack(videoTrack)
	if err != nil {
		return err
	}
	go processRTCP(rtpSender2)

	// this will never fire, because the subscriber only receives.
	peerConnection.OnTrack(func(tr *webrtc.TrackRemote, r *webrtc.RTPReceiver) { panic("never") })

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

	pcDone, connected := waitPeerconnClosed("sub", link, peerConnection)

	vid := TxTrack{
		track:     videoTrack,
		splicer:   RtpSplicer{},
		clockrate: 90000,
	}
	aud := TxTrack{
		track:     audioTrack,
		splicer:   RtpSplicer{},
		clockrate: 48000,
	}

	txset := &TxTrackPair{aud, vid}

	go func() {
		conn, ok := <-connected

		if conn && ok {
			dbg.Goroutine.Println("sub/"+link.roomname, unsafe.Pointer(link), "connwait: launching writer")

			SubscriberGr(subGrCh, txset, link)

		} else {
			dbg.Goroutine.Println("sub/"+link.roomname, unsafe.Pointer(link), "connwait: connect fail")
		}

	}()

	dbg.Goroutine.Println("sub/"+link.roomname, unsafe.Pointer(link), "waiting for done")

	<-pcDone

	dbg.Goroutine.Println("sub/"+link.roomname, unsafe.Pointer(link), "finally done!")

	close(subGrCh)

	return nil
}

// Blocks until PC is Closed
func subHandler(rw http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var err error

	dbg.Main.Println("subHandler request", r.URL.String())

	// rx offer, tx answer
	// offer from browser
	offersdpbytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	roomname := r.URL.Query().Get("room") // "" is permitted, most common room name!
	link := rooms.GetOrMake(roomname)

	subuuid := getSubuuidFromRequest(r)

	subGrCh := make(chan string, 1)

	if subuuid != nil {
		//pl("Creating submap entry for ", subuuid.String())
		subMapMutex.Lock()
		subMap[*subuuid] = subGrCh
		subMapMutex.Unlock()
	}

	dbg.Url.Println("subHandler", link.roomname, unsafe.Pointer(link), r.URL.String())

	sdpCh := make(chan *webrtc.SessionDescription) //
	errCh := make(chan error)

	go func() {

		err := subHandlerGr(string(offersdpbytes), link, sdpCh, subGrCh)
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

func getSubuuidFromRequest(r *http.Request) (subuuid *uuid.UUID) {

	if x := r.URL.Query().Get("subuuid"); x != "" {
		if x, err := uuid.Parse(x); err == nil {
			subuuid = &x
		}
	}
	if x := r.Header.Get("X-deadsfu-subuuid"); x != "" {
		if x, err := uuid.Parse(x); err == nil {
			if subuuid != nil {
				log.Println("/whap request provided both subuuid param and header. Ignoring param")
			}
			subuuid = &x
		}
	}
	return subuuid
}

func logTransceivers(tag string, pc *webrtc.PeerConnection) {
	if len(pc.GetTransceivers()) == 0 {
		dbg.Main.Printf("%v transceivers is empty", tag)
	}
	for i, v := range pc.GetTransceivers() {
		rx := v.Receiver()
		tx := v.Sender()
		dbg.Main.Printf("%v transceiver %v,%v,%v,%v nilrx:%v niltx:%v", tag, i, v.Direction(), v.Kind(), v.Mid(), rx == nil, tx == nil)

		if rx != nil && len(rx.GetParameters().Codecs) > 0 {
			dbg.Main.Println(" rtprx ", rx.GetParameters().Codecs[0].MimeType)
		}
		if tx != nil && len(tx.GetParameters().Codecs) > 0 {
			dbg.Main.Println(" rtptx ", tx.GetParameters().Codecs[0].MimeType)
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
	dbg.Main.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	dbg.Main.Println("fullsdp", wherefrom, rtcsd.SDP)

	sd, err := rtcsd.Unmarshal()
	if err != nil {
		errlog.Println(fmt.Errorf("rtcsd.Unmarshal() fail:%w", err))
		return
	}
	dbg.Main.Printf(" n/%d media descriptions present", len(sd.MediaDescriptions))

	ncandidates := 0
	for _, v := range strings.Split(strings.ReplaceAll(rtcsd.SDP, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(v, "a=candidate") {
			dbg.Ice.Println(wherefrom, v)
			ncandidates++
		}
	}
	dbg.Ice.Println(wherefrom, "ice candidates found/printed", ncandidates)

}

func verifyEmbedFiles() {
	if len(deadsfu.IdleClipZipBytes) == 0 {
		checkFatal(fmt.Errorf("embed idleClipZipBytes is zero-length!"))
	}

	if len(deadsfu.DeadsfuCameraNotAvailableMp4) == 0 {
		checkFatal(fmt.Errorf("embed deadsfuCameraNotAvailableMp4 is zero-length!"))
	}

	if len(deadsfu.Favicon_ico) == 0 {
		checkFatal(fmt.Errorf("embed deadsfuCameraNotAvailableMp4 is zero-length!"))
	}

}

func idleMediaLoader() []rtp.Packet {

	var rtp []rtp.Packet

	if *idleClipZipfile == "" && *idleClipServerInput == "" {

		rtp = readRTPFromZip(deadsfu.IdleClipZipBytes)
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
		rtp = readRTPFromZip(body)
		log.Println(len(rtp), "encoded rtp packets retrieved from", *idleClipServerURL)

	} else if *idleClipZipfile != "" {
		buf, err := ioutil.ReadFile(*idleClipZipfile)
		checkFatal(err)
		rtp = readRTPFromZip(buf)

	} else {
		panic("badlogic")
	}

	if len(rtp) == 0 {
		checkFatal(fmt.Errorf("embedded idle-clip.zip is zero-length!"))
	}

	rtp = removeH264AccessDelimiterAndSEI(rtp)

	return rtp

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

var _ = dialUpstream

func dialUpstream(link *Room) error {

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

	dbg.Url.Println("dialing upstream", link.roomname, unsafe.Pointer(link), u.String())

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		OnTrack2(peerConnection, track, receiver, link)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		dbg.Main.Println("dial ICE Connection State has changed", icecs.String())
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

	dbg.Main.Println("sending post", u.String())

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

	dbg.Main.Println("dial connected")

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

	//simple version
	if false {
		for {
			_, _, rtcpErr := rtpSender.ReadRTCP()
			if rtcpErr != nil {
				return
			}
		}
	}

	for {
		packets, _, rtcpErr := rtpSender.ReadRTCP()
		if rtcpErr != nil {
			return
		}

		if dbg.ReceiverLostPackets.enabled {
			for _, pkt := range packets {
				switch t := pkt.(type) {
				case *rtcp.SenderReport:
					//fmt.Printf("rtpSender Sender Report %s \n", v.String())
				case *rtcp.ReceiverReport:
					for _, v := range t.Reports {
						log.Printf("rcvr report %d total lost %d", v.SSRC, v.TotalLost)
						//msgLoss.subpktslost++
					}
					//fmt.Printf("rtpSender Receiver Report %s \n", v.String())
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

var _ = text2pcapLog

func text2pcapLog(log *log.Logger, inbuf []byte) {
	var b bytes.Buffer
	b.Grow(20 + len(inbuf)*3)
	b.WriteString("000000 ")
	for _, v := range inbuf {
		b.WriteString(fmt.Sprintf("%02x ", v))
	}
	b.WriteString("!text2pcap")

	dbg.Main.Print(b.String())
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

func OnTrack2(
	peerConnection *webrtc.PeerConnection,
	track *webrtc.TrackRemote,
	receiver *webrtc.RTPReceiver,
	link *Room) {

	mimetype := track.Codec().MimeType
	dbg.Main.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		dbg.Main.Println("OnTrack audio", mimetype)

		inboundTrackReader(track, track.Codec().ClockRate, Audio, link.xBroker)
		//here on error
		dbg.Main.Printf("audio reader %p exited", track)
		return
	}

	// audio callbacks never get here
	// video will proceed here

	if strings.ToLower(mimetype) != videoMimeType {
		panic("unexpected kind or mimetype:" + track.Kind().String() + ":" + mimetype)
	}

	dbg.Main.Println("OnTrack RID():", track.RID())
	dbg.Main.Println("OnTrack MediaStream.id [msid ident]:", track.StreamID())
	dbg.Main.Println("OnTrack MediaStreamTrack.id [msid appdata]:", track.ID())

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

			// err = sendREMB(peerConnection, track)
			// if err == io.ErrClosedPipe {
			// 	return
			// } else if err != nil {
			// 	errlog.Println(err.Error())
			// 	return
			// }

			time.Sleep(3 * time.Second)
		}
	}()

	// if *logPackets {
	// 	logPacketNewSSRCValue(logPacketIn, track.SSRC(), rtpsource)
	// }

	//	var lastts uint32
	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	inboundTrackReader(track, track.Codec().ClockRate, Video, link.xBroker)
	//here on error
	dbg.Main.Printf("video reader %p exited", track)

}

// var xpacketPool = sync.Pool{
// 	New: func() interface{} {
// 		a := new(XPacket)
// 		a.buf = make([]byte, 1460)
// 		return a
// 	},
// }

func inboundTrackReader(rxTrack *webrtc.TrackRemote, clockrate uint32, typ XPacketType, xb *XBroker) {

	for {
		xp := new(XPacket)
		buf := make([]byte, 1460)

		i, _, err := rxTrack.Read(buf) // faster than .ReadRTP()
		if err == io.EOF {
			return
		} else if err != nil {
			errlog.Println(err.Error())
			return
		}

		//r := &rtp.Packet{}
		r := &xp.Pkt
		if err := r.Unmarshal(buf[:i]); err != nil {
			errlog.Print("unable to unmarshal on inbound")
			continue
		}

		isvid := typ == Video
		xp.Typ = typ
		xp.Arrival = nanotime()
		xp.Keyframe = isvid && isH264Keyframe(r.Payload)

		xb.Publish(xp)

	}
}

var _ = noSignalGeneratorGr

func noSignalGeneratorGr(doneSync <-chan struct{}, idlePkts []rtp.Packet, idleCh chan<- *XPacket) {

	iskf := make([]bool, len(idlePkts))

	for i, p := range idlePkts {
		iskf[i] = isH264Keyframe(p.Payload)
	}

	fps := 5
	seqno := uint16(0)
	tstotal := uint32(0)

	basetime := time.Now()

	framedur90 := uint32(90000 / fps)

	pktsDur90 := idlePkts[len(idlePkts)-1].Timestamp - idlePkts[0].Timestamp

	totalDur90 := pktsDur90/framedur90*framedur90 + framedur90

	for {

		for i, pkt := range idlePkts {

			xp := &XPacket{
				Arrival:  nanotime(),
				Pkt:      pkt, //this is a copy from array!
				Typ:      IdleVideo,
				Keyframe: iskf[i],
			}

			xp.Pkt.SSRC = 0xdeadbeef

			// rollover should be okay for uint32: https://play.golang.org/p/VeIBZgorleL
			tsdelta := pkt.Timestamp - idlePkts[0].Timestamp

			tsdeltaDur := time.Duration(tsdelta) * time.Second / 90000

			when := basetime.Add(tsdeltaDur)

			xp.Pkt.SequenceNumber = seqno
			seqno++
			xp.Pkt.Timestamp = tsdelta + tstotal

			time.Sleep(time.Until(when)) //time.when() should be zero if when < time.now()

			idleCh <- xp // downstreams shouldn't touch XPacket contents

			// put termination check after send to better detect races
			// (dont minimize race period, maximize it)
			// ~4 ns
			select {
			case _, ok := <-doneSync:
				if !ok {
					panic("closing not permitted")
				}
				return
			default:
			}

		}

		tstotal += totalDur90
		basetime = basetime.Add(time.Duration(totalDur90) * time.Second / 90000)

		time.Sleep(time.Until(basetime))

	}
}

var _ = noSignalSwitchGr

func noSignalSwitchGr(liveCh <-chan *XPacket, noSignalCh <-chan *XPacket, outCh chan<- *XPacket) {

	var lastVideoRxTime time.Time = time.Now()
	var sendingIdleVid bool = true

	for {

		select {
		case mm := <-liveCh:
			lastVideoRxTime = time.Now()

			if sendingIdleVid {

				if mm.Keyframe {
					sendingIdleVid = false
					log.Println("SWITCHING TO INPUT, NOW INPUT VIDEO PRESENT")
				}
			}

			if !sendingIdleVid {
				outCh <- mm
			}

		case idle := <-noSignalCh:

			rxActive := time.Since(lastVideoRxTime) <= time.Second

			if !rxActive && !sendingIdleVid {

				if idle.Keyframe {
					sendingIdleVid = true
					log.Println("SWITCHING TO IDLE, NO INPUT VIDEO PRESENT")
				}
			}

			if sendingIdleVid {
				outCh <- idle
			}
		}
	}
}

var _ = sendREMB

func sendREMB(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.ReceiverEstimatedMaximumBitrate{Bitrate: 10000000, SenderSSRC: uint32(track.SSRC())}})
}

func sendPLI(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) error {
	return peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}})
}

// Blocks until PC is Closed
func pubHandlerCreatePeerconn(offersdp string, link *Room, sdpCh chan *webrtc.SessionDescription) error {

	dbg.Main.Println("createIngressPeerConnection")

	peerConnection, err := newPeerConnection()
	if err != nil {
		return err
	}
	defer peerConnection.Close()

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		OnTrack2(peerConnection, track, receiver, link)
	})

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		dbg.Main.Println("ingress ICE Connection State has changed", icecs.String())
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

	pcdone, _ := waitPeerconnClosed("pub", link, peerConnection)
	<-pcdone

	return nil
}

// pcDone will get closed upon the failed, closed or disconnected state of the PC
// connected will get closed upon the connected state of the PC
// this does not block until the PC is finished, you can do that with pcDone
func waitPeerconnClosed(debug string, link *Room, pc *webrtc.PeerConnection) (
	pcDone chan struct{},
	connected chan bool) {

	pcDone = make(chan struct{})
	connected = make(chan bool)

	onceCloseDone := sync.Once{}
	onceCloseConnected := sync.Once{}
	onceClosePc := sync.Once{}

	fCloseDone := func() { close(pcDone) }
	fCloseConnected := func() {
		select {
		case connected <- true:
		default:
		}
		close(connected)
	}

	pc.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		dbg.PeerConn.Println(debug+"/"+link.roomname, unsafe.Pointer(link), "ConnectionState", cs.String())

		switch cs {
		case webrtc.PeerConnectionStateConnected:

			onceCloseConnected.Do(fCloseConnected)
		case webrtc.PeerConnectionStateClosed:
			fallthrough
		case webrtc.PeerConnectionStateFailed:
			fallthrough
		case webrtc.PeerConnectionStateDisconnected:
			onceCloseDone.Do(fCloseDone)
			// IMPORTANT
			// per 12/27/21 Conversation with Sean, the PC going to a closed
			// state is NOT the last step, we need to Close() the PC when we want it
			// to release resources, and have WriteRTP start failing
			//12/27/21 this doesn't seem to start io.ErrPipeClosed on WriteRTP,
			// but this is important none the less.
			// get nil value when closed

			onceClosePc.Do(func() {
				pc.Close()
			})

		}
	})

	return
}

// SpliceRTP
// *rtp.Packet gets modified/trashed
func (s *RtpSplicer) SpliceWriteRTP(trk WriteRtpIntf, p *rtp.Packet, unixnano int64, rtphz int64) {

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	// 12/30/21 maybe we should use something else other than SSRC transitions?
	if p.SSRC != s.lastSSRC {
		s.lastSSRC = p.SSRC

		if unixnano == 0 {
			panic("unixnano cannot be zero.")
		}

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

		dbg.Main.Printf("** ssrc change [txid] rtphz/%v td1/%v td2/%v tsdelta/%v sndelta/%v", rtphz, td1, td2, (p.Timestamp-s.tsOffset)-s.lastTS, (p.SequenceNumber-s.snOffset)-s.lastSN)
	}

	p.Timestamp -= s.tsOffset
	p.SequenceNumber -= s.snOffset

	// xdbg := true
	// if xdbg {
	// 	if p.SSRC != s.lastSSRC && rtphz == 90000 {
	// 		pl("last ts", s.lastTS, s.lastUnixnanosNow)
	// 		pl("new ts", p.Timestamp, unixnano)
	// 	}
	// }

	s.lastUnixnanosNow = unixnano
	s.lastTS = p.Timestamp
	s.lastSN = p.SequenceNumber

	//I had believed it was possible to see: io.ErrClosedPipe {
	// but I no longer believe this to be true
	// if it turns out I can see those, we will need to adjust
	err := trk.WriteRTP(p)
	if err != nil {
		panic(err)
	}
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
		dbg.Ftl.Println("ftl/waiting for accept on:", ln.Addr())

		netconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("ftl: Accept() err %w", err)
		}

		dbg.Ftl.Println("ftl/socket accepted")

		tcpconn := netconn.(*net.TCPConn)
		ftlserver.NewTcpSession(log.Default(), dbg.Ftl.Logger, tcpconn, findserver, *ftlUdpPort)
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
		a.audiossrc = uint32(mrand.Int63())
		a.videossrc = uint32(mrand.Int63())
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
		x.rxMediaCh <- p

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
		x.rxMediaCh <- p
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

type XPacketType int32

const (
	_         XPacketType = iota
	Video                 = iota
	Audio                 = iota
	Data                  = iota
	IdleVideo             = iota
)

var _ = Data

type XPacket struct {
	Arrival  int64
	Pkt      rtp.Packet
	Typ      XPacketType
	Keyframe bool
}

// Replay will replay a GOP to a subscribers tracks

func Replay(inCh chan *XPacket, t *TxTracks, txt *TxTrackPair) {
	dbg.Goroutine.Println(unsafe.Pointer(t), "Replay() started")
	defer dbg.Goroutine.Println(unsafe.Pointer(t), "Replay() ended")

	var delta int64
	var tmpAudSSRC uint32 = uint32(mrand.Int63())
	var tmpVidSSRC uint32 = uint32(mrand.Int63())

	var first *XPacket = nil

	for xp := range inCh {
		now := nanotime()

		if first == nil {
			first = xp
			delta = now - first.Arrival
			if delta < 0 {
				panic("bug")
			}
			if !xp.Keyframe {
				pl("Replay() didnt start with KF, returning")
				return
			}
		}

		playtime := xp.Arrival + delta
		sleep := playtime - now
		if sleep < 0 {
			sleep = 0
		}

		time.Sleep(time.Duration(sleep))

		copy := xp.Pkt

		switch xp.Typ {
		case Audio:
			copy.SSRC = tmpAudSSRC
		case Video:
			copy.SSRC = tmpVidSSRC
		}
		// you cannot use m.now for the nano timestamp
		// these packets have been delayed,
		// and those old timestamps won't play well
		// when we switch to 'live'
		// (this would cause a big jump in the timestamps to the splicer)

		t.mu.Lock()
		if _, ok := t.replay[txt]; !ok {
			//finish when tracks have been switched away
			t.mu.Unlock()
			return
		}
		switch xp.Typ {
		case Audio:
			txt.aud.splicer.SpliceWriteRTP(txt.aud.track, &copy, now, int64(txt.aud.clockrate))
		case Video:
			txt.vid.splicer.SpliceWriteRTP(txt.vid.track, &copy, now, int64(txt.vid.clockrate))
		default:
			log.Fatalln("bad p.typ:", xp.Typ)
		}
		t.mu.Unlock()

	}
}

func SubscriberGr(subGrCh <-chan string, txt *TxTrackPair, room *Room) {
	dbg.Goroutine.Println(unsafe.Pointer(&subGrCh), "subGr() started")
	defer dbg.Goroutine.Println(unsafe.Pointer(&subGrCh), "subGr() ended")

	for {
		room.tracks.Add(txt)

		xpCh := room.xBroker.SubscribeReplay()
		go func() {
			defer room.xBroker.Unsubscribe(xpCh)
			Replay(xpCh, room.tracks, txt)
		}()

		req, open := <-subGrCh

		room.tracks.Remove(txt)        // remove from current room
		if !open {
			return
		}

		tmptxt := *txt // See note below: this is necessary to trigger Replay to return
		txt = &tmptxt

		if newroom, ok := getRoom(req); ok {
			room = newroom
			dbg.Goroutine.Println(unsafe.Pointer(&subGrCh), "subGr() switched to different room")
		} else {
			dbg.Goroutine.Println(unsafe.Pointer(&subGrCh), "subGr() not switched to different room")
		}

	}

}

//Important note:
// why we change the address of 'txt' *TxTrackPair:
// shutdown Replay() using method #2
// freaking magic!
// this re-addressing of 'txt' *TxTrackPair
// forces Replay() to finish up,
// since Replay() returns when it discovers
// the *TxTrackPair we have passed it is no longer
// on the 'replay' map of *TxTracks (room.tracks)
// ---
// if we don't do this, we can start multiple concurrent overlapping
// Replay() for the same *TxTrackPair.
// doing this causes them to finish up and exit.
// because this code in this func, basically does a Remove() then Add()

func makeRoomListJson(serial int) []byte {

	type RoomJson struct {
		Serial int      `json:"serial"`
		Rooms  []string `json:"rooms"`
	}

	a := RoomJson{Serial: serial, Rooms: make([]string, 0, 10)}

	a.Rooms = rooms.GetList()

	xx, err := json.Marshal(a)
	if err != nil {
		errlog.Println(err.Error())
		return []byte{} // not great, but what else to do?
	}

	return xx
}

func RoomListRequestHandler() {

	sendback := func(j []byte, jsnCh chan<- []byte) {
		select {
		//the HTTP receiver may be gone, but thats okay
		case jsnCh <- j:
			//happy path

		default:
			//the HTTP receiver may be gone, but thats okay also
			//we just ignore that it's gone, let the GC do its magic
		}
	}

	serial := 100

	x := make([]MsgGetSourcesList, 0)

	for {
		select {

		// this is a request from http for the roomlist
		case m, ok := <-getSourceListCh:

			if !ok {
				panic("bad")
			}
			if m.serial == serial {
				dbg.Switching.Println("/getSourceList same serial, saving")
				x = append(x, m)
			} else {
				dbg.Switching.Println("/getSourceList not same serial, responding")
				j := makeRoomListJson(serial)
				sendback(j, m.jsonCh)
			}

		// this is a notice from internally, the room list has changed
		case _, ok := <-roomSetChangedCh:
			if !ok {
				panic("bad")
			}

			serial++
			j := makeRoomListJson(serial)

			for _, v := range x {
				sendback(j, v.jsonCh)
			}
		}
	}
}

func getRoomListHandler(rw http.ResponseWriter, r *http.Request) {

	dbg.Switching.Println("getSourceListHandler() enter")
	defer dbg.Switching.Println("getSourceListHandler() exit")

	serial := r.URL.Query().Get("serial")

	sno, _ := strconv.Atoi(serial)
	// we ignore the error, it's okay

	a := make(chan []byte, 1) //we are not the writer, we do not close this

	// we could pass r.Context().Done(), but there is little point
	b := MsgGetSourcesList{
		serial: sno,
		jsonCh: a,
	}

	getSourceListCh <- b

	select {
	//is the http request is closed?
	case <-r.Context().Done():
		return // okay, see you next time!

	case jsn, ok := <-a:
		if !ok {
			errlog.Println("unexpected closed response chan")
		}
		_, _ = rw.Write(jsn) //an error here might mean the remote is gone, but we want to ignore that
	}

}

func Writer(ch chan *XPacket, t *TxTracks, name string) {
	dbg.Goroutine.Println("Writer() started")
	defer dbg.Goroutine.Println("Writer() ended")

	var rtpPktCopy rtp.Packet

	for p := range ch {

		now := nanotime()

		switch p.Typ {
		case Audio:
			t.mu.Lock()
			for k := range t.live {
				rtpPktCopy = p.Pkt
				k.aud.splicer.SpliceWriteRTP(k.aud.track, &rtpPktCopy, now, int64(k.aud.clockrate))
			}
			t.mu.Unlock()

		case Video:

			t.mu.Lock()

			// if keyframe, move all from pending to live
			if p.Keyframe {

				for pair := range t.replay {
					delete(t.replay, pair)
					t.live[pair] = struct{}{}
				}
			}

			//pl(5,len(t.live),len(t.replay))

			// forward to all 'live' tracks
			for k := range t.live {

				rtpPktCopy = p.Pkt
				//this is a candidate for heavy optimzation
				// or hand-assembly, or inlining, etc, if the
				// per-write WriteRTP() performance ever gets low enough
				// this is currently at 20ns/loop
				k.vid.splicer.SpliceWriteRTP(k.vid.track, &rtpPktCopy, now, int64(k.vid.clockrate))
			}

			t.mu.Unlock()
		}
		//	pl("reading")
	}
}

type TxTracks struct {
	mu     sync.Mutex
	live   map[*TxTrackPair]struct{}
	replay map[*TxTrackPair]struct{}
}

func NewTxTracks() *TxTracks {
	a := &TxTracks{
		live:   make(map[*TxTrackPair]struct{}),
		replay: make(map[*TxTrackPair]struct{}),
	}
	return a
}

func (t *TxTracks) Add(p *TxTrackPair) {
	t.mu.Lock()
	t.replay[p] = struct{}{}
	t.mu.Unlock()
}

func (t *TxTracks) Remove(p *TxTrackPair) {
	t.mu.Lock()
	delete(t.live, p)
	delete(t.replay, p)
	t.mu.Unlock()
}

func (t *TxTracks) IsEmpty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.live) == 0 && len(t.replay) == 0
}

type WriteRtpIntf interface {
	WriteRTP(p *rtp.Packet) error
}

type PeriodLog struct {
	last  int64
	count int
}

func (x *PeriodLog) Println(args ...interface{}) {
	x.count++

	if nanotime()-int64(x.last) > int64(time.Second*2) {
		x.last = nanotime()
		args = append(args, x.count)
		_ = log.Output(2, fmt.Sprintln(args...))
	}
}
