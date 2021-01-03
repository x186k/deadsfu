package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
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
	//"github.com/digitalocean/godo"
	"github.com/libdns/cloudflare"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v3"
)

const (
	rtcpPLIInterval = time.Second * 3
)

var peerConnectionConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
	},
}

var (
	ingestPresent bool
	pubStartCount uint32
	// going to need more of these
	subMap       map[string]*webrtc.PeerConnection = make(map[string]*webrtc.PeerConnection)
	subMapMutex  sync.Mutex
	outputTracks map[string]*webrtc.TrackLocalStaticRTP = make(map[string]*webrtc.TrackLocalStaticRTP)
	//outputTracksMutex sync.Mutex  NOPE! ingestPresent is used with pubStartCount to prevent concurrent access
)

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

	dotoken := os.Getenv("DIGITALOCEAN_ACCESS_TOKEN")
	if dotoken == "" {
		fmt.Printf("DIGITALOCEAN_ACCESS_TOKEN not set\n")
		return
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

	xxx := os.Getenv("CLOUDFLARE_TOKEN")
	//xx:=digitalocean.Provider{APIToken: dotoken,
	//	Client: digitalocean.Client{XClient:  client}}
	yy := cloudflare.Provider{APIToken: xxx}

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
		peerConnection, err := webrtc.NewPeerConnection(peerConnectionConfig)
		if err != nil {
			panic(err)
		}

		// AddTrack should be called before CreateOffer
		rtpSender, err := peerConnection.AddTrack(outputTracks["x"])
		if err != nil {
			panic(err)
		}

		// Read incoming RTCP packets
		// Before these packets are retuned they are processed by interceptors. For things
		// like NACK this needs to be called.
		go func() {
			rtcpBuf := make([]byte, 1500)
			for {
				if _, _, rtcpErr := rtpSender.Read(rtcpBuf); rtcpErr != nil {
					return
				}
			}
		}()

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
		subMap[txid] = peerConnection
		subMapMutex.Unlock()
		// delete the map entry in one minute. should be plenty of time
		go func() {
			time.Sleep(time.Minute)
			subMapMutex.Lock()
			delete(subMap, txid)
			subMapMutex.Unlock()
		}()

		o := *peerConnection.LocalDescription()

		logSdpReport("sub: sending offer: ", string(o.SDP))

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(o.SDP))

		return
	} else {
		// part two of two part transaction

		logSdpReport("sub: 2nd POST, answer: ", string(emptyOrRecvOnlyAnswer))

		subMapMutex.Lock()
		peerConnection := subMap[txid]
		subMapMutex.Unlock()

		sdesc := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: emptyOrRecvOnlyAnswer}

		err = peerConnection.SetRemoteDescription(sdesc)
		checkPanic(err)

		subMapMutex.Lock()
		delete(subMap, txid) //no error if missing
		subMapMutex.Unlock()

		log.Println("setremote done")
	}
}

func logSdpReport(prefix string, sdp string) {
	good := strings.HasPrefix(sdp, "v=")
	nlines := len(strings.Split(strings.Replace(sdp, "\r\n", "\n", -1), "\n"))
	log.Printf("%s: %v, and is %d lines long", prefix, good, nlines)
	if !good || nlines < 10 {
		log.Println(sdp)
		log.Println()
	}
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

	logSdpReport("dial: received offer: ", offer)

	if atomic.AddUint32(&pubStartCount, 1) > 1 {
		return errors.New("cannot accept 2nd ingress connection, please restart for new session")
	}
	// inside here will panic if something prevents success
	// this is by design/ cam
	answer := createIngestPeerConnection(offer)

	logSdpReport("dial: sending answer: ", answer)

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
func createIngestPeerConnection(offer string) (answer string) {

	logSdpReport("pub: received offer: ", string(offer))

	// Create a new RTCPeerConnection
	peerConnection, err := webrtc.NewPeerConnection(peerConnectionConfig)
	checkPanic(err)

	//  removed broadcast style track setup
	// oh oh oh, can add directions to this sendonly...
	// 	was 'broadcast' way:
	// XXX
	// the sfu appears ro work okay without this, using addtrack()
	//peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo)

	// Create Track that we send video back to browser on
	//just initializes a struct!
	outputTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: "video/vp8"}, "video_q", "pion_q")
	if err != nil {
		panic(err)
	}

	// replaces pc.AddTransceiverFromKind() from broadcast example
	// important concurrency note:
	// other subscribers can't read this until:
	// ingestPresent is true, which is set later in this function
	// other publishers can't get here, cause this function
	// is protected by atomic.inc32(&x)
	// so this map write IS safe. there. I told you. I broke it down.
	outputTracks["x"] = outputTrack
	if _, err = peerConnection.AddTrack(outputTracks["x"]); err != nil {
		panic(err)
	}

	// Set a handler for when a new remote track starts, this just distributes all our packets
	// to connected peers
	peerConnection.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		// Send a PLI on an interval so that the publisher is pushing a keyframe every rtcpPLIInterval
		// This can be less wasteful by processing incoming RTCP events, then we would emit a NACK/PLI when a viewer requests it
		go func() {
			ticker := time.NewTicker(rtcpPLIInterval)
			for range ticker.C {
				if rtcpSendErr := peerConnection.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(remoteTrack.SSRC())}}); rtcpSendErr != nil {
					println(rtcpSendErr) //cam
				}
			}
		}()

		// old 'broadcast' approach
		// l ocalTrack, err = webrtc.NewTrackLocalStaticRTP(remoteTrack.Codec().RTPCodecCapability, "video", "pion")
		// checkPanic(err)

		rtpBuf := make([]byte, 1400)
		for {
			i, _, err := remoteTrack.Read(rtpBuf)
			checkPanic(err)

			fmt.Print("d")

			// ErrClosedPipe means we don't have any subscribers, this is ok if no peers have connected yet
			if _, err = outputTracks["x"].Write(rtpBuf[:i]); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				panic(err)
			}
		}
	})

	// Set the remote SessionDescription
	desc := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offer)}
	err = peerConnection.SetRemoteDescription(desc)
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

	// XXX
	// someday we should check pion for webrtc/connected status to set this bool
	//
	ingestPresent = true

	// Get the LocalDescription and take it to base64 so we can paste in browser
	return peerConnection.LocalDescription().SDP
}
