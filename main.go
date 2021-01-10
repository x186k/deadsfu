package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	_ "io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"

	//"net/http/httputil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"
	"github.com/libdns/cloudflare"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
)

const (
	debugsdp = true
)

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
	videoMimeType  string
	rtcapi         *webrtc.API
	ingestPresent  bool
	pubStartCount  uint32
	subMap         map[string]*Subscriber = make(map[string]*Subscriber)
	subMapMutex    sync.Mutex
	localVidTracks map[string]*webrtc.TrackLocalStaticRTP = make(map[string]*webrtc.TrackLocalStaticRTP)
	//localVidTracksMutex sync.Mutex  NOPE! ingestPresent is used with pubStartCount to prevent concurrent access
	audioTrack *webrtc.TrackLocalStaticRTP
)

//XXXXXXXX fixme add time & purge occasionally
type Subscriber struct {
	step            int                         // true indicates got
	unsharedTrack       *webrtc.TrackLocalStaticRTP // individual track for simulcast situations
	conn            *webrtc.PeerConnection      // peerconnection
	currentRID      string                      // simulcast level for playback
	requestedRID    string
	timestampOffset uint32
	seqnoOffset     uint16
	lastSent        *rtp.Packet
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

	buf, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		http.Error(res, "can't open index.html", http.StatusInternalServerError)
		return
	}
	_, _ = res.Write(buf)
}

//var silenceJanus = flag.Bool("silence-janus", false, "if true will throw away janus output")
var debug = flag.Bool("debug", true, "enable debug output")
var nohtml = flag.Bool("no-html", false, "do not serve any html files, only do WHIP")
var dialRxURL = flag.String("dial-rx", "", "do not take http WHIP for ingress, dial for ingress")
var port = flag.Int("port", 8080, "default port to accept HTTPS on")
var httpsHostname = flag.String("https-hostname", "", "hostname for Let's Encrypt TLS certificate (https)")
var info = log.New(os.Stderr, "I ", log.Lmicroseconds|log.LUTC)
var elog = log.New(os.Stderr, "E ", log.Lmicroseconds|log.LUTC)

func initPion() {
	m := webrtc.MediaEngine{}

	// Setup the codecs you want to use.
	// We'll use a VP8 and Opus but you can also define your own
	// if err := m.RegisterCodec(webrtc.RTPCodecParameters{
	// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/vp8", ClockRate: 90000, Channels: 0, SDPFmtpLine: "", RTCPFeedback: nil},
	// 	PayloadType:        96,
	// }, webrtc.RTPCodecTypeVideo); err != nil {
	// 	panic(err)
	// }

	h264 := false
	if h264 {
		err := RegisterH264Codecs(&m)
		checkPanic(err)
	} else {
		err := m.RegisterDefaultCodecs()
		checkPanic(err)
	}

	// Create the API object with the MediaEngine
	rtcapi = webrtc.NewAPI(webrtc.WithMediaEngine(&m))
	//rtcApi = webrtc.NewAPI()

}
func init() {

	initPion()
}

func main() {
	var err error
	flag.Parse()

	if *debug {
		log.SetFlags(log.Lmicroseconds | log.LUTC)
		log.SetPrefix("D ")
		info.Println("debug output IS enabled")
	} else {
		info.Println("debug output NOT enabled")
		log.SetOutput(ioutil.Discard)
		log.SetPrefix("")
		log.SetFlags(0)
	}

	//unclear if we need
	//var group *errgroup.Group

	// ln, err := net.Listen("tcp", ":8000")
	// checkPanic(err)

	mux := http.NewServeMux()

	pubPath := "/pub"
	//subPath := "/sub/" // pre-query string version
	subPath := "/sub" // 2nd slash important

	if !*nohtml {
		mux.HandleFunc("/", slashHandler)
	}
	mux.HandleFunc(subPath, subHandler)

	if *dialRxURL == "" {
		mux.HandleFunc(pubPath, pubHandler)
	} else {
		err = dialUpstream(*dialRxURL)
		checkPanic(err)
	}

	//certmagic.DefaultACME.Email = ""

	//I find this function from certmagic more opaque than I like
	//err = HTTPS([]string{"x186k.duckdns.org"}, mux, ducktoken) // https automagic
	//panic(err)

	//client := godo.NewFromToken(dotoken)

	// if true {
	//     client.OnRequestCompleted(func(req *http.Request, resp *http.Response) {
	//         data, _ := httputil.DumpRequestOut(req, true)
	//         fmt.Printf("Req: %s\n", data)

	//         data, _ = httputil.DumpResponse(resp, true)
	//         fmt.Printf("Resp: %s\n\n", data)
	//     })
	// }

	var ln net.Listener
	httpType := ""

	if *httpsHostname != "" {

		certmagic.DefaultACME.Agreed = true
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

	if atomic.AddUint32(&pubStartCount, 1) > 1 {
		// handle this
		teeErrorStderrHttp(w, errors.New("cannot accept 2nd ingress connection, restart for new session"))
		return
	}
	// inside here will panic if something prevents success
	// this is by design/ cam
	answer, err := createIngestPeerConnection(string(offer))
	if err != nil {
		teeErrorStderrHttp(w, err)
		panic(err)
	}

	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write([]byte(answer))
	checkPanic(err) // cam/if this write fails, then fail hard!

	//NOTE, Do NOT ever use http.error to return SDPs
}

// sfu egress setup
func subHandler(w http.ResponseWriter, httpreq *http.Request) {
	defer httpreq.Body.Close()

	log.Println("subHandler request", httpreq.URL.String())

	if !ingestPresent {
		teeErrorStderrHttp(w, fmt.Errorf("no publisher, please connect publisher first"))
		return
	}

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

	// empty or answer
	raw, err := ioutil.ReadAll(httpreq.Body)
	if err != nil {
		teeErrorStderrHttp(w, err)
		return
	}
	emptyOrRecvOnlyAnswer := string(raw)

	subMapMutex.Lock()
	sub, ok := subMap[txid]
	if !ok {
		sub = &Subscriber{}
		subMap[txid] = sub
	}
	subMapMutex.Unlock()

	rid := httpreq.URL.Query().Get("rid")
	step := httpreq.URL.Query().Get("step")
	issfu := httpreq.URL.Query().Get("issfu") != ""

	if rid != "" {
		if rid != "a" && rid != "b" && rid != "c" {
			teeErrorStderrHttp(w, fmt.Errorf("invalid rid. only a,b,c are valid"))
			return
		}

		sub.requestedRID = rid
		w.WriteHeader(http.StatusAccepted)
		return
	} else if step == "1" { // asking for offer
		if httpreq.Method != "POST" {
			teeErrorStderrHttp(w, fmt.Errorf("only POST allowed for ?step="))
			return
		}

		if sub.step != 0 {
			teeErrorStderrHttp(w, fmt.Errorf("cannot repeat step=1"))
			return
		}
		sub.step = 1

		// part one of two part transaction

		// Create a new PeerConnection
		log.Println("created PC")
		peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
		if err != nil {
			panic(err)
		}
		peerConnection.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
			log.Println(pcs)
		})

		//audio
		log.Println("-- before audio", audioTrack)
		if audioTrack == nil {
			panic("no audio available, panic")
		}

		// pion can receiver either
		//single m=video with simulcast, which is 3x ssrcs
		// or three m=video non-simulcast, old style mediadesc

		// for egress, we can provide 1x output video
		// or we can provide 3x output video when we have
		// simulcast ingress or multi-track ingress

		if !issfu {
			// !issfu true, means this is a broswer connecting
			// and it can only take one track of input

			// we just give browsers a single track, but their own unique track
			log.Println("addtrack for browser subscriber")

			vidtrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video", "pion")
			checkPanic(err)

			sub.unsharedTrack = vidtrack

			rtpSender, err := peerConnection.AddTrack(vidtrack)
			checkPanic(err)
			go processRTCP(rtpSender)

		} else {
			// issfu true, means this is a SFU subscribing
			// and it can only take many tracks of input

			// another x186ksfu instance
			// we forward all tracks down
			for k, v := range localVidTracks {
				log.Println("addtrack for sfu subscriber:", k)
				rtpSender, err := peerConnection.AddTrack(v)
				checkPanic(err)
				go processRTCP(rtpSender)
			}
		}

		// audio
		rtpSenderAudio, err := peerConnection.AddTrack(audioTrack)
		checkPanic(err)
		go processRTCP(rtpSenderAudio)

		// Create an offer for the other PeerConnection
		offer, err := peerConnection.CreateOffer(nil)
		if err != nil {
			panic(err)
		}

		// Create channel that is blocked until ICE Gathering is complete
		gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

		// SetLocalDescription, needed before remote gets offer
		if err = peerConnection.SetLocalDescription(offer); err != nil {
			panic(err)
		}

		// Block until ICE Gathering is complete, disabling trickle ICE
		// we do this because we only can exchange one signaling message
		// in a production application you should exchange ICE Candidates via OnICECandidate
		log.Println("pre gatherComplete read")
		<-gatherComplete
		log.Println("post gatherComplete read")

		sub.conn = peerConnection
		// delete the map entry in one minute. should be plenty of time

		o := *peerConnection.LocalDescription()

		err = logSdpReport("pion-subscribe", o)
		checkPanic(err)

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(o.SDP))

		return
	} else if step == "2" {
		if httpreq.Method != "POST" {
			teeErrorStderrHttp(w, fmt.Errorf("only POST allowed for ?step="))
			return
		}

		if sub.step != 1 {
			teeErrorStderrHttp(w, fmt.Errorf("step=2 must follow step=1"))
			return
		}
		sub.step = 2
		// part two of two part transaction

		sdesc := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: emptyOrRecvOnlyAnswer}

		err = logSdpReport("subscriber-recd-answer", sdesc)
		checkPanic(err)

		subMapMutex.Lock()
		peerConnection := subMap[txid].conn
		subMapMutex.Unlock()

		err = peerConnection.SetRemoteDescription(sdesc)
		checkPanic(err)

		log.Println("setremote done")
	} else {
		teeErrorStderrHttp(w, fmt.Errorf("step=1 or step=2 or rid=<rid> must be supplied"))
		return
	}
}

func logSdpReport(wherefrom string, rtcsd webrtc.SessionDescription) error {
	good := strings.HasPrefix(rtcsd.SDP, "v=")
	nlines := len(strings.Split(strings.Replace(rtcsd.SDP, "\r\n", "\n", -1), "\n"))
	log.Printf("%s sdp from %v is %v lines long, and has v= %v", rtcsd.Type.String(), wherefrom, nlines, good)

	if debugsdp {
		_ = ioutil.WriteFile("/tmp/"+wherefrom, []byte(rtcsd.SDP), 0777)
	}

	sd, err := rtcsd.Unmarshal()
	if err != nil {
		return err
	}
	log.Printf(" n/%d media descriptions present", len(sd.MediaDescriptions))
	return nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func dialUpstream(baseurl string) error {

	txid, err := randomHex(10)
	checkPanic(err)
	url := baseurl + "?issfu=1&step=1&txid=" + txid

	log.Println("dialUpstream url:", url)

	// for pub ingest, we want to take offer, generate answer: double post
	empty := strings.NewReader("")
	resp, err := http.Post(url, "application/sdp", empty)
	checkPanic(err)
	defer resp.Body.Close()
	offerraw, err := ioutil.ReadAll(resp.Body)
	checkPanic(err) //cam
	offer := string(offerraw)

	if atomic.AddUint32(&pubStartCount, 1) > 1 {
		return errors.New("cannot accept 2nd ingress connection, please restart for new session")
	}
	// inside here will panic if something prevents success
	// this is by design/ cam
	answer, err := createIngestPeerConnection(offer)
	if err != nil {
		return err
	}

	ansreader := strings.NewReader(answer)
	url = baseurl + "?issfu=1&step=2&txid=" + txid
	resp2, err := http.Post(url, "application/sdp", ansreader)
	checkPanic(err)
	defer resp2.Body.Close()
	secondResponse, err := ioutil.ReadAll(resp.Body)
	checkPanic(err)

	if len(secondResponse) > 0 {
		elog.Println("got unexpected data back from 2nd fetch to upstream:", string(secondResponse))
		//we will ignore this
	}
	return nil
}

func processRTCP(rtpSender *webrtc.RTPSender) {
	rtcpBuf := make([]byte, 1500)
	for {
		if _, _, rtcpErr := rtpSender.Read(rtcpBuf); rtcpErr != nil {
			return
		}
	}
}

func ingestOnTrack(peerConnection *webrtc.PeerConnection, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	var err error
	mimetype := track.Codec().MimeType
	log.Println("OnTrack codec:", mimetype)

	if track.Kind() == webrtc.RTPCodecTypeAudio {
		log.Println("OnTrack audio", mimetype)

		audioTrack, err = webrtc.NewTrackLocalStaticRTP(track.Codec().RTPCodecCapability, "audio", "pion")
		checkPanic(err)

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

	if track.Kind() != webrtc.RTPCodecTypeVideo || !strings.HasPrefix(mimetype, "video") {
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
	if trackname == "" {
		panic("empty trackname")
	}

	if trackname != "a" && trackname != "b" && trackname != "c" {
		panic("only track names a,b,c supported")
	}

	// save the video mime type, and check that all video tracks are the same type

	if videoMimeType == "" {
		videoMimeType = mimetype
	} else {
		if mimetype != videoMimeType {
			panic("cannot support multiple video mime types")
		}
	}

	//change from pion to a,b,c
	localVidTracks[trackname], err = webrtc.NewTrackLocalStaticRTP(track.Codec().RTPCodecCapability, "video", trackname)
	checkPanic(err)

	go func() {
		sendPLI(peerConnection, track)
		sendREMB(peerConnection, track)
		ticker := time.NewTicker(3 * time.Second)
		for range ticker.C {
			sendPLI(peerConnection, track)
			sendREMB(peerConnection, track)
		}
	}()

	//this is the main rtp read/write loop
	// one per track (OnTrack above)
	for {
		// Read RTP packets being sent to Pion
		//fmt.Println(99,rid)
		packet, _, readErr := track.ReadRTP()
		if readErr != nil {
			panic(readErr)
		}

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

		subMapMutex.Lock()
		// for each subscriber
		for _, sub := range subMap {
			subMapMutex.Unlock()

			// if sub.simuTrack == nil {
			// 	panic("unfinished subscriber / never got audio??")
			// }

			// if subscriber is a browser
			// we decide which RID he should receive
			if sub.unsharedTrack != nil { // we write to per-subscriber tracks when they are browser

				// has subscriber requested to switch tracks?
				if sub.requestedRID == trackname {
					iskey := keyFrameHelper(packet.Payload, mimetype)
					if iskey {

						// 12 7 20 chrome seems more sensative to timestamp than seqnp

						sub.seqnoOffset = packet.SequenceNumber - sub.lastSent.SequenceNumber - 1
						// one could argue that X should be the inter-frame-TS-delta
						// but if you use the inter-frame-TS-delta, you will make the timestamp change early
						// which might mess with gstreamer type decoders
						// if you use X=0, then the new frame probably starts on the same timestamp as the cut
						// frame. But the math&housekeeping is easier! :)
						x := uint32(2970)
						sub.timestampOffset = packet.Timestamp - sub.lastSent.Timestamp - x

						sub.currentRID = sub.requestedRID
						sub.requestedRID = ""
					}
				}

				ridMatch := sub.currentRID == trackname
				useDefaultRid := sub.currentRID == "" && trackname == "a"

				if ridMatch || useDefaultRid {
					// if yes, forward packet

					packet.SequenceNumber -= sub.seqnoOffset
					packet.Timestamp -= sub.timestampOffset

					sub.lastSent = packet

					err = sub.unsharedTrack.WriteRTP(packet)
					if err != nil {
						myMetrics.writeRTPError++
					}
				}
			}
			subMapMutex.Lock()
		}
		subMapMutex.Unlock()

		if writeErr := localVidTracks[trackname].WriteRTP(packet); writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
			panic(writeErr)
		}
	}
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
func createIngestPeerConnection(offersdp string) (string, error) {

	log.Println("createIngestPeerConnection")

	// Set the remote SessionDescription

	//	ofrsd, err := rtcsd.Unmarshal()
	//	checkPanic(err)

	// Create a new RTCPeerConnection
	peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
	checkPanic(err)

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
	err = logSdpReport("publisher", offer)
	checkPanic(err)

	err = peerConnection.SetRemoteDescription(offer)
	checkPanic(err)

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		ingestOnTrack(peerConnection, track, receiver)
	})

	peerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		fmt.Printf("Connection State has changed %s \n", connectionState.String())
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

	// XXX
	// someday we should check pion for webrtc/connected status to set this bool
	//
	ingestPresent = true

	// Get the LocalDescription and take it to base64 so we can paste in browser
	ansrtcsd := peerConnection.LocalDescription()

	err = logSdpReport("pion-publisher", *ansrtcsd)
	checkPanic(err)

	return ansrtcsd.SDP, nil
}

func keyFrameHelper(payload []byte, mimetype string) bool {
	switch mimetype {

	case "video/VP8":
		vp8 := &VP8Helper{}
		err := vp8.Unmarshal(payload)
		if err != nil {
			elog.Println(err) //cam, malformed rtp is not fatal
		}
		return vp8.IsKeyFrame

	case "video/H264":
		return isH264Keyframe(payload)
	}
	panic("unhandled keyframe mimetype " + mimetype)
}
