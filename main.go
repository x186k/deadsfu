package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"

	//"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/caddyserver/certmagic"
	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"
	"github.com/libdns/cloudflare"
	"github.com/x186k/sfu-x186k/rtpsplice"

	"embed"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"
)

//go:generate go run scripts/gen.go

// content is our static web server content.
//go:embed html/index.html
var indexHtml []byte

//go:embed embed
var embedfs embed.FS

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
	},
}

var myMetrics struct {
	writeRTPError      uint64
	audioErrClosedPipe uint64
}

var (
	h264IdleRtpPackets []rtp.Packet
	videoMimeType      string = "video/H264"
	audioMimeType      string = "audio/opus"
	rtcapi             *webrtc.API
	pubStartCount      int32
	
	subMap             map[string]*Subscriber = make(map[string]*Subscriber)
	subMapMutex        sync.Mutex
	audioTrack, video1, video2, video3 *webrtc.TrackLocalStaticRTP
	ingressSemaphore         = semaphore.NewWeighted(int64(1))
)

//XXXXXXXX fixme add time & purge occasionally
type Subscriber struct {
	isBrowser bool                   // media forwarding is quite different between browser subscriber vs sfu subscriber
	conn      *webrtc.PeerConnection // peerconnection
	//myVideo   *webrtc.TrackLocalStaticRTP // will be nil for sfu, non-nil for browser, browser needs own seqno+ts for rtp, thus this
	myVideo *webrtc.TrackLocalStaticRTP // will be nil for sfu, non-nil for browser, browser needs own seqno+ts for rtp, thus this
	myAudio *webrtc.TrackLocalStaticRTP // will be nil for sfu, non-nil for browser, browser needs own seqno+ts for rtp, thus this

	videoSplicer rtpsplice.RtpSplicer
}

func checkPanic(err error) {
	if err != nil {
		panic(err)
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
var debug = flag.Bool("debug", true, "enable debug output")
var logPackets = flag.Bool("log-packets", false, "log packets for later use with text2pcap")

// egrep '(RTP_PACKET|RTCP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
var nohtml = flag.Bool("no-html", false, "do not serve any html files, only do WHIP")
var dialRxURL = flag.String("dial-rx", "", "do not take http WHIP for ingress, dial for ingress")
var port = flag.Int("port", 8080, "default port to accept HTTPS on")
var videoCodec = flag.String("video-codec", "h264", "video codec to use/just h264 currently")
var httpsHostname = flag.String("https-hostname", "", "hostname for Let's Encrypt TLS certificate (https)")

var logPacketIn = log.New(os.Stdout, "I ", log.Lmicroseconds|log.LUTC)

//var logPacketOut = log.New(os.Stdout, "O ", log.Lmicroseconds|log.LUTC)
var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)

func init() {
	var err error

	// Create the API object with the MediaEngine
	m := webrtc.MediaEngine{}
	rtcapi = webrtc.NewAPI(webrtc.WithMediaEngine(&m))
	//rtcApi = webrtc.NewAPI()

	// Create a audio track
	audioTrack, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", "pion")
	checkPanic(err)
	video1, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video1", "pion")
	checkPanic(err)
	video2, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video2", "pion")
	checkPanic(err)
	video3, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video3", "pion")
	checkPanic(err)

	if *videoCodec == "h264" {
		err := RegisterH264AndOpusCodecs(&m)
		checkPanic(err)
	} else {
		log.Fatalln("only h.264 supported")
		// err := m.RegisterDefaultCodecs()
		// checkPanic(err)
	}

	pcapng := getEmbeddedOrFetch("idle.screen.h264.pcapng")

	h264IdleRtpPackets, _, err = rtpsplice.ReadPcap2RTP(bytes.NewReader(pcapng))
	checkPanic(err)

	go func() {
		rtpdumpLoopPlayer(h264IdleRtpPackets, video1)
	}()

}

const assetsBaseUrl = "https://github.com/x186k/x186k-sfu-assets/raw/main/"

func getEmbeddedOrFetch(filename string) []byte {

	x, err := embedfs.ReadFile("embed/" + filename)
	if err == nil && len(x) > 0 {
		return x
	}
	//checkPanic(err)

	url := assetsBaseUrl + filename
	rsp, err := http.Get(url)
	checkPanic(err)
	defer rsp.Body.Close()

	raw, err := ioutil.ReadAll(rsp.Body)
	checkPanic(err)

	return raw

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
		log.Println("debug output NOT enabled")
		log.SetOutput(ioutil.Discard)
		log.SetPrefix("")
		log.SetFlags(0)
	}

	mux := http.NewServeMux()

	pubPath := "/pub"
	subPath := "/sub" // 2nd slash important

	if !*nohtml {
		mux.HandleFunc("/", slashHandler)
	}
	mux.HandleFunc(subPath, subHandler)

	if *dialRxURL == "" {
		mux.HandleFunc(pubPath, pubHandler)
	} else {
		dialUpstream(*dialRxURL)
	}

	var ln net.Listener
	httpType := ""

	if *httpsHostname != "" {

		//certmagic.DefaultACME.Agreed = true
		//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA // XXXXXXXXXXX

		cftoken := os.Getenv("CLOUDFLARE_TOKEN")
		if cftoken != "" {
			log.Printf("CLOUDFLARE_TOKEN set, will use DNS challenge for Let's Encrypt\n")

			//xx:=digitalocean.Provider{APIToken: dotoken,
			//	Client: digitalocean.Client{XClient:  client}}
			dnsProvider := cloudflare.Provider{APIToken: cftoken}

			certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
				DNSProvider:        &dnsProvider,
				TTL:                0,
				PropagationTimeout: 0,
				Resolvers:          []string{},
			}
		}

		// We do NOT do port 80 redirection, as certmagic.HTTPS()
		tlsConfig, err := certmagic.TLS([]string{*httpsHostname})
		checkPanic(err)
		/// XXX ro work with OBS studio for now
		tlsConfig.MinVersion = 0

		ln, err = tls.Listen("tcp", ":"+strconv.Itoa(*port), tlsConfig)
		checkPanic(err)
		httpType = "https"
	} else {
		ln, err = net.Listen("tcp", ":"+strconv.Itoa(*port))
		checkPanic(err)
		httpType = "http"
	}

	log.Printf("WHIP input listener at: %s://%s%s", httpType, ln.Addr().String(), pubPath)
	log.Printf("WHIP output listener at: %s://%s%s", httpType, ln.Addr().String(), subPath)

	err = http.Serve(ln, mux)
	panic(err)

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

var pcnum int = 0

// sfu ingest setup
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

	if !ingressSemaphore.TryAcquire(1) {
		teeErrorStderrHttp(w, errors.New("ingress busy"))
		return
	}

	// inside here will panic if something prevents success
	// this is by design/ cam
	answersd, peerConnection := createIngestPeerConnection(string(offer))

	logSdpReport("listen-ingress-answer", *answersd)

	pcnum++

	connConnected := make(chan bool)
	connDone := make(chan bool)
	peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		log.Println("ingress Connection State has changed", cs.String(), pcnum)
		switch cs {
		case webrtc.PeerConnectionStateConnected:
			connConnected <- true
		case webrtc.PeerConnectionStateFailed:
		case webrtc.PeerConnectionStateClosed:
		case webrtc.PeerConnectionStateDisconnected:
			close(connDone)
		}
	})

	go func() {
		select {
		case <-connConnected:
		case <-time.After(15 * time.Second):
			log.Println("pubhandler: timeout waiting for connected", pcnum)
			peerConnection.Close()
		}
		<-connDone
		log.Println("ingress DONE! re-opening ingress", pcnum)

		ingressSemaphore.Release(1)
	}()

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

	if rid != "" {
		if rid != "a" && rid != "b" && rid != "c" {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. only a,b,c are valid"))
			return
		}

		subMapMutex.Lock()
		sub, ok := subMap[txid]
		subMapMutex.Unlock()
		if !ok {
			teeErrorStderrHttp(w, fmt.Errorf("no such sub"))
			return
		}

		sub.requestedRID = rid
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

		sub := &Subscriber{}

		// Create a new PeerConnection
		log.Println("created PC")
		peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
		checkPanic(err)

		sub.conn = peerConnection

		offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdpbytes)}
		logSdpReport("publisher", offer)

		err = peerConnection.SetRemoteDescription(offer)
		checkPanic(err)

		sdsdp, err := offer.Unmarshal()
		checkPanic(err)

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
			log.Println("sub Connection State has changed", cs.String())
		})

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

		// audio first
		rtpSender, err := sub.conn.AddTrack(audioTrack)
		checkPanic(err)
		go processRTCP(rtpSender)
		sub.rtpSenders[0] = rtpSender

		rtpSender, err = sub.conn.AddTrack(video1)
		checkPanic(err)
		go processRTCP(rtpSender)
		sub.rtpSenders[1] = rtpSender

		if numvideo >= 2 { // is browser!
			rtpSender, err = sub.conn.AddTrack(video2)
			checkPanic(err)
			go processRTCP(rtpSender)
			sub.rtpSenders[2] = rtpSender
		}
		if numvideo >= 3 {

			rtpSender, err = sub.conn.AddTrack(video3)
			checkPanic(err)
			go processRTCP(rtpSender)
			sub.rtpSenders[3] = rtpSender
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

	}
}

func logSdpReport(wherefrom string, rtcsd webrtc.SessionDescription) {
	good := strings.HasPrefix(rtcsd.SDP, "v=")
	nlines := len(strings.Split(strings.Replace(rtcsd.SDP, "\r\n", "\n", -1), "\n"))
	log.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	// if debugsdp {
	// 	_ = ioutil.WriteFile("/tmp/"+wherefrom, []byte(rtcsd.SDP), 0777)
	// }

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

func rtpdumpLoopPlayer(p []rtp.Packet, track *webrtc.TrackLocalStaticRTP) {
	n := len(p)
	delta1 := time.Second / time.Duration(n)
	delta2 := uint32(90000 / n)
	seq := uint16(mrand.Uint32())
	ts := mrand.Uint32()

	for {
		for _, v := range p {
			time.Sleep(delta1)
			v.SequenceNumber = seq
			seq++
			v.Timestamp = ts
			err := track.WriteRTP(v)
			checkPanic(err)
		}
		ts += delta2
	}

}

func dialUpstream(baseurl string) {

	txid, err := randomHex(10)
	checkPanic(err)
	url := baseurl + "?txid=" + txid

	log.Println("dialUpstream url:", url)

	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	checkPanic(err)

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
	connConnected := make(chan bool)
	connDone := make(chan bool)
	peerConnection.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		log.Println("ingress Connection State has changed", cs.String())
		switch cs {
		case webrtc.PeerConnectionStateConnected:
			connConnected <- true
		case webrtc.PeerConnectionStateFailed:
		case webrtc.PeerConnectionStateClosed:
		case webrtc.PeerConnectionStateDisconnected:
			close(connDone)
		}
	})
	go func() {
		select {
		case <-connConnected:
		case <-time.After(15 * time.Second):
			log.Println("dial:timeout waiting for connected")
			peerConnection.Close()
		}
		<-connDone
		log.Println("dial ingress DONE! exiting")
		os.Exit(0)
	}()

	// send offer, get answer
	resp, err := http.Post(url, "application/sdp", strings.NewReader(offer.SDP))
	checkPanic(err)
	defer resp.Body.Close()
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

func logPacket(packet *rtp.Packet, msg string) string {
	var b bytes.Buffer
	b.Grow(20 + len(packet.Raw)*3)
	b.WriteString("000000 ")
	// tools for text2pcap
	for _, v := range packet.Raw {
		b.WriteString(fmt.Sprintf("%02x ", v))
	}
	b.WriteString(msg)
	return b.String()
}

func ingestOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {

	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		// forever loop
		for {
			p, _, err := track.ReadRTP()
			checkPanic(err) //cam, if there is no audio, better to destroy SFU and let new SFU sessions occur

			// os.Stdout.WriteString("a")
			// os.Stdout.Sync()
			// fmt.Println(time.Now().Clock())
			if err := audioTrack.WriteRTP(p); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					// I believe this occurs when there is no subscribers connected with audioTrack
					// thus it is non-fatal
					myMetrics.audioErrClosedPipe++
					continue
				}
				// not-ErrClosedPipe, fatal
				//cam, if there is no audio, better to destroy SFU and let new SFU sessions occur
				panic(err)
			}
		}
	}

	// audio callbacks never get here
	// video will proceed here

	if mimetype != videoMimeType {
		panic("unexpected kind or mimetype:" + track.Kind().String() + ":" + mimetype)
	}

	log.Println("OnTrack ID():", track.ID())
	log.Println("OnTrack RID():", track.RID())
	log.Println("OnTrack streamid():", track.StreamID())

	var trackname string // store trackname here, reduce locks
	if track.RID() == "" {
		log.Println("using StreamID for trackname:", track.StreamID())
		trackname = track.StreamID()
	} else {
		log.Println("using RID for trackname:", track.RID())
		trackname = track.RID()
	}

	if trackname != "a" && trackname != "b" && trackname != "c" {
		panic("only track names a,b,c supported")
	}

	go func() {
		sendPLI(peerConnection, track)
		sendREMB(peerConnection, track)
		ticker := time.NewTicker(3 * time.Second)
		for range ticker.C {
			sendPLI(peerConnection, track)
			sendREMB(peerConnection, track)
		}
	}()

	var rtpsource rtpsplice.RtpSource
	switch trackname {
	case "a":
		rtpsource = rtpsplice.Video1
	case "b":
		rtpsource = rtpsplice.Video2
	case "c":
		rtpsource = rtpsplice.Video3
	}

	var destrack *webrtc.TrackLocalStaticRTP
	switch trackname {
	case "a":
		destrack = video1
	case "b":
		destrack = video2
	case "c":
		destrack = video3
	}

	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	for {
		// Read RTP packets being sent to Pion
		//fmt.Println(99,rid)
		packet, _, readErr := track.ReadRTP()
		if readErr != nil {
			panic(readErr)
		}

		if *logPackets {
			logPacketIn.Print(logPacket(packet, "RTP_PACKET video ingress"))
		}

		if writeErr := destrack.WriteRTP(packet); writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
			panic(writeErr)
		}

		sendRTPToEachSubscriber(packet, rtpsource)

	}
}

func sendRTPToEachSubscriber(p *rtp.Packet, src rtpsplice.RtpSource) {

	/* pseudo code

	if ingest == simulcast {
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

		//	os.Stdout.WriteString("y")
		if sub.videoSplicer.IsActiveOrPending(src) {
			pprime := sub.videoSplicer.SpliceRTP(p, src, time.Now().UnixNano(), int64(90000))
			if pprime != nil {
				//os.Stdout.WriteString(string(rune(int('a') + int(src))))
				os.Stdout.Write([]byte{byte('a') + byte(src)})
				err := sub.myVideo.WriteRTP(p)
				if err != nil {
					myMetrics.writeRTPError++
				}
			}
		}

		subMapMutex.Lock()
	}
	subMapMutex.Unlock()

	// if subscriber is a browser
	// we decide which RID he should receive
	// if sub.unsharedTrack != nil { // we write to per-subscriber tracks when they are browser

	// 	// has subscriber requested to switch tracks?
	// 	if sub.requestedRID == trackname {
	// 		iskey := keyFrameHelper(packet.Payload, mimetype)
	// 		if iskey {

	// 			// 12 7 20 chrome seems more sensative to timestamp than seqnp

	// 			sub.seqnoOffset = packet.SequenceNumber - sub.lastSent.SequenceNumber - 1
	// 			// one could argue that X should be the inter-frame-TS-delta
	// 			// but if you use the inter-frame-TS-delta, you will make the timestamp change early
	// 			// which might mess with gstreamer type decoders
	// 			// if you use X=0, then the new frame probably starts on the same timestamp as the cut
	// 			// frame. But the math&housekeeping is easier! :)
	// 			x := uint32(2970)
	// 			sub.timestampOffset = packet.Timestamp - sub.lastSent.Timestamp - x

	// 			sub.currentRID = sub.requestedRID
	// 			sub.requestedRID = ""
	// 		}
	// 	}

	// 	ridMatch := sub.currentRID == trackname
	// 	useDefaultRid := sub.currentRID == "" && trackname == "a"

	// 	if ridMatch || useDefaultRid {
	// 		// if yes, forward packet

	// 		packet.SequenceNumber -= sub.seqnoOffset
	// 		packet.Timestamp -= sub.timestampOffset

	// 		sub.lastSent = packet

	// 		err = sub.unsharedTrack.WriteRTP(packet)
	// 		if err != nil {
	// 			myMetrics.writeRTPError++
	// 		}
	// 	}
	// }

}

func sendREMB(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) {
	if writeErr := peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.ReceiverEstimatedMaximumBitrate{Bitrate: 10000000, SenderSSRC: uint32(track.SSRC())}}); writeErr != nil {
		fmt.Println(writeErr)
	}
}

func sendPLI(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote) {
	if writeErr := peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}}); writeErr != nil {
		fmt.Println(writeErr)
	}
}

/*
	IMPORTANT
	read this like your life depends upon it.
	########################
	any error that prevents peerconnection setup this line MUST MUST MUST panic()
	why?
	1. pubStartCount is now set
	2. sublishers will be connected because pubStartCount>0
	3. if ingest cannot proceed, we must Panic to live upto the
	4. single-shot, fail-fast manifesto I envision
*/
// error design:
// this does not return an error
// if an error occurs, we panic
// single-shot / fail-fast approach
//
func createIngestPeerConnection(offersdp string) (*webrtc.SessionDescription, *webrtc.PeerConnection) {

	log.Println("createIngestPeerConnection")

	// Set the remote SessionDescription

	//	ofrsd, err := rtcsd.Unmarshal()
	//	checkPanic(err)

	// Create a new RTCPeerConnection
	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	checkPanic(err)

	peerConnection.OnICEConnectionStateChange(func(icecs webrtc.ICEConnectionState) {
		log.Println("ingress ICE Connection State has changed", icecs.String())
	})

	// XXX 1 5 20 cam
	// not sure reading rtcp helps, since we should not have any
	// senders on the ingest.
	// leave for now
	//
	// Read incoming RTCP packets
	// Before these packets are retuned they are processed by interceptors. For things
	// like NACK this needs to be called.

	// we dont have, wont have any senders for the ingest.
	// it is just a receiver
	// log.Println("num senders", len(peerConnection.GetSenders()))
	// for _, rtpSender := range peerConnection.GetSenders() {
	// 	go processRTCP(rtpSender)
	// }

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdp)}
	logSdpReport("publisher", offer)

	err = peerConnection.SetRemoteDescription(offer)
	checkPanic(err)

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingestOnTrack(peerConnection, track, receiver)
	})

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
	return peerConnection.LocalDescription(), peerConnection
}

