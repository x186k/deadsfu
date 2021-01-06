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
	"net/http"
	"strconv"

	//"net/http/httputil"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	//"github.com/davecgh/go-spew/spew"

	//"github.com/digitalocean/godo"
	"github.com/libdns/cloudflare"

	"github.com/pion/rtcp"
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
    rtpWriteError	uint64
}


var (
	videoMimeType string
	rtcapi        *webrtc.API
	ingestPresent bool
	pubStartCount uint32
	// going to need more of these
	subMap       map[string]*Subscriber = make(map[string]*Subscriber)
	subMapMutex  sync.Mutex
	outputTracks map[string]*webrtc.TrackLocalStaticRTP = make(map[string]*webrtc.TrackLocalStaticRTP)
	//outputTracksMutex sync.Mutex  NOPE! ingestPresent is used with pubStartCount to prevent concurrent access
)

type Subscriber struct {
	simuTrackName string                      // which simulcast track is being watched
	simuTrack     *webrtc.TrackLocalStaticRTP // individual track for simulcast situations

	conn *webrtc.PeerConnection
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
var port = flag.Int("port", 8000, "default port to accept HTTPS on")

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

	// err := RegisterH264Codecs(&m)
	// checkPanic(err)

	err := m.RegisterDefaultCodecs()
	checkPanic(err)

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
	subPath := "/sub/" // 2nd slash important

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

	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA // XXXXXXXXXXX

	cftoken := os.Getenv("CLOUDFLARE_TOKEN")
	if cftoken == "" {
		fmt.Printf("CLOUDFLARE_TOKEN not set\n")
		return
	}
	//xx:=digitalocean.Provider{APIToken: dotoken,
	//	Client: digitalocean.Client{XClient:  client}}
	yy := cloudflare.Provider{APIToken: cftoken}

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider:        &yy,
		TTL:                0,
		PropagationTimeout: 0,
		Resolvers:          []string{},
	}

	// We do NOT do port 80 redirection, as
	tlsConfig, err := certmagic.TLS([]string{"foo.sfu1.com"})
	checkPanic(err)
	/// XXX ro work with OBS studio for now
	tlsConfig.MinVersion = 0

	ln, err := tls.Listen("tcp", ":"+strconv.Itoa(*port), tlsConfig)
	checkPanic(err)

	log.Println("WHIP input listener at:", ln.Addr().String(), pubPath)
	log.Println("WHIP output listener at:", ln.Addr().String(), subPath)

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
	answer := createIngestPeerConnection(string(offer))

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

	lastelement := path.Base(httpreq.URL.Path)
	if !strings.HasPrefix(lastelement, "txid=") || len(lastelement) < 15 {
		//can handle, do not panic
		teeErrorStderrHttp(w, fmt.Errorf("last element of sfuout url must start with txid= and be 15 chars or more"))
		return
	}
	txid := lastelement[5:]

	// empty or answer
	raw, err := ioutil.ReadAll(httpreq.Body)
	if err != nil {
		teeErrorStderrHttp(w, err)
		return
	}
	emptyOrRecvOnlyAnswer := string(raw)

	if len(emptyOrRecvOnlyAnswer) == 0 { // empty
		log.Println("empty body")
		// part one of two part transaction

		// Create a new PeerConnection
		peerConnection, err := rtcapi.NewPeerConnection(peerConnectionConfig)
		if err != nil {
			panic(err)
		}

		// pion can receiver either
		//single m=video with simulcast, which is 3x ssrcs
		// or three m=video non-simulcast, old style mediadesc

		subscriberIsBrowser := true

		sub := &Subscriber{conn: peerConnection}

		if subscriberIsBrowser {
			// we just give browsers a single track, but their own unique track
			log.Println("addtrack for browser subscriber")

			vidtrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: videoMimeType}, "video", "pion")
			checkPanic(err)

			sub.simuTrackName = "q"
			sub.simuTrack = vidtrack

			rtpSender, err := peerConnection.AddTrack(vidtrack)
			checkPanic(err)
			go rtcpReadLoop(rtpSender)

		} else {
			// another x186ksfu instance
			// we forward all tracks down
			for k, v := range outputTracks {
				log.Println("addtrack for sfu subscriber:", k)
				rtpSender, err := peerConnection.AddTrack(v)
				checkPanic(err)
				go rtcpReadLoop(rtpSender)
			}
		}

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
		<-gatherComplete

		subMapMutex.Lock()
		subMap[txid] = sub
		subMapMutex.Unlock()
		// delete the map entry in one minute. should be plenty of time

		o := *peerConnection.LocalDescription()

		err = logSdpReport("pion-subscribe", o)
		checkPanic(err)

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(o.SDP))

		return
	} else {
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

func dialUpstream(url string) error {

	txid, err := randomHex(10)
	checkPanic(err)
	url = url + "/txid=" + txid

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
	answer := createIngestPeerConnection(offer)

	ansreader := strings.NewReader(answer)
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

func rtcpReadLoop(rtpSender *webrtc.RTPSender) {
	rtcpBuf := make([]byte, 1500)
	for {
		if _, _, rtcpErr := rtpSender.Read(rtcpBuf); rtcpErr != nil {
			return
		}
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
func createIngestPeerConnection(offersdp string) (answer string) {

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
	// 	go rtcpReadLoop(rtpSender)
	// }

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offersdp)}
	err = logSdpReport("publisher", offer)
	checkPanic(err)

	err = peerConnection.SetRemoteDescription(offer)
	checkPanic(err)

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {

		log.Println("OnTrack ID():", track.ID())
		log.Println("OnTrack RID():", track.RID())
		trackname := track.ID()
		if track.RID() != "" {
			trackname = track.RID()
		}
		log.Println("OnTrack trackname:", trackname)
		log.Println("OnTrack codec:", track.Codec().MimeType)

		// save the video mime type, and check that all video tracks are the same type
		if strings.HasPrefix(track.Codec().MimeType, "video") {
			if videoMimeType == "" {
				videoMimeType = track.Codec().MimeType
			} else {
				if track.Codec().MimeType != videoMimeType {
					panic("cannot support multiple mime types")
				}
			}
		}

		localtrack, err := webrtc.NewTrackLocalStaticRTP(track.Codec().RTPCodecCapability, "video", "pion")
		checkPanic(err)
		outputTracks[trackname] = localtrack

		go func() {
			ticker := time.NewTicker(3 * time.Second)
			for range ticker.C {
				fmt.Printf("Sending pli for stream with rid: %q, ssrc: %d\n", track.RID(), track.SSRC())
				if writeErr := peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}}); writeErr != nil {
					fmt.Println(writeErr)
				}
				// Send a remb message with a very high bandwidth to trigger chrome to send also the high bitrate stream
				fmt.Printf("Sending remb for stream with rid: %q, ssrc: %d\n", track.RID(), track.SSRC())
				if writeErr := peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.ReceiverEstimatedMaximumBitrate{Bitrate: 10000000, SenderSSRC: uint32(track.SSRC())}}); writeErr != nil {
					fmt.Println(writeErr)
				}
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
			_ = packet

			subMapMutex.Lock()
			// for each subscriber
			for _, sub := range subMap {
				subMapMutex.Unlock()
				// is this subscriber watching this ingest incoming track???
				if sub.simuTrackName != "" && sub.simuTrackName == trackname && sub.simuTrack != nil {
					// if yes, forward packet
					err = sub.simuTrack.WriteRTP(packet)
					if err != nil {
						myMetrics.rtpWriteError++
					}
				}
				subMapMutex.Lock()
			}
			subMapMutex.Unlock()

			if writeErr := outputTracks[trackname].WriteRTP(packet); writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
				panic(writeErr)
			}
		}
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

	return ansrtcsd.SDP
}
