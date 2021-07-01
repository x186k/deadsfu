package main

import (
	"bytes"
	"fmt"
	"hash/crc64"
	"io"
	"sync/atomic"

	"net/http/httptest"

	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/x186k/deadsfu/rtpstuff"
	//this is kinda weird, but works, so we use it.
	//main "github.com/x186k/deadsfu"
)

// func TestMain(m *testing.M) {

// 	// call flag.Parse() here if TestMain uses flags

// 	log.SetOutput(ioutil.Discard)
// 	log.SetFlags(0)

// 	// elog.SetOutput(ioutil.Discard)
// 	// elog.SetFlags(0)

// 	os.Exit(m.Run())
// }

var rtcconf = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{
			URLs: []string{"stun:stun.l.google.com:19302"},
		},
	},
}

var tab = crc64.MakeTable(crc64.ISO)

func calccrc(p []byte) uint64 {
	a := uint64(0)
	// a = crc64.Update(0, tab, p[0:1])
	// a = crc64.Update(a, tab, p[2:8])
	a = crc64.Update(a, tab, p[12:])
	return a
}

var pkthash map[uint64]int = make(map[uint64]int)

func TestPubSub(t *testing.T) {
	//log.SetOutput(ioutil.Discard)
	//log.SetFlags(0)

	fake := append(make([]byte, 12), spspps...)

	pkthash[calccrc(fake)] = 2

	p, _, err := rtpstuff.ReadPcap2RTP(bytes.NewReader(idleScreenH264Pcapng))
	checkPanic(err)
	for _, v := range p {
		crc := calccrc(v.Raw)
		//println(88,)

		pkthash[crc] = 1

	}

	//initStateAndGoroutines()

	pc, err := webrtc.NewPeerConnection(rtcconf)
	checkPanic(err)

	var numvid int32 = 0

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		_ = receiver
		//panic("--ontrack")

		mimetype := track.Codec().MimeType

		for {
			p, _, err := track.ReadRTP()
			if err == io.EOF {
				return
			}
			checkPanic(err)

			_ = fmt.Print
			_ = p
			found := pkthash[calccrc(p.Raw)]
			fmt.Printf(" rx test-pc %v %v %v\n", mimetype, len(p.Payload), found)
			if mimetype == "video/H264" {
				atomic.AddInt32(&numvid, 1)
			}
		}
	})

	ro := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}
	// create transceivers for 1x audio, 3x video
	_, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, ro)
	checkPanic(err)
	_, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, ro)
	checkPanic(err)

	//vt, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: "video/h264"}, "video", "pion")
	//checkPanic(err)

	// track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: audioMimeType}, "audio", mediaStreamId)
	// checkPanic(err)
	// rtpSender, err := pc.AddTrack(vt)
	// checkPanic(err)
	// go processRTCP(rtpSender)

	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) { println("ICEConnection", s.String()) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) { println("Connection", s.String()) })

	offer, err := pc.CreateOffer(nil)
	checkPanic(err)

	//logSdpReport("dialupstream-offer", offer)
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	err = pc.SetLocalDescription(offer) //start ICE
	checkPanic(err)
	<-gatherComplete

	req := httptest.NewRequest("POST", "http://ignored.com/sub", strings.NewReader(offer.SDP))
	w := httptest.NewRecorder()
	req.Header.Set("Content-Type", "application/sdp")
	SubHandler(w, req) // not super clean, but \_(ツ)_/¯
	resp := w.Result()
	answerraw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 202, resp.StatusCode)
	assert.Equal(t, "application/sdp", resp.Header.Get("Content-Type"))
	ans := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	assert.True(t, ValidateSDP(ans))
	err = pc.SetRemoteDescription(ans)
	checkPanic(err)

	//t.FailNow()
	time.Sleep(time.Second * 2)
	require.True(t, atomic.LoadInt32(&numvid) > 0)

	println("ok, got idle video okay")

	go startMultiTrackPublisher(t)

	for {
		time.Sleep(time.Second)
		err := video1.WriteSample(media.Sample{Data: spspps, Duration: time.Second})
		if err != nil && err != io.ErrClosedPipe {
			panic(err)
		}
	}
	//select {}
}

var spspps = []byte{
	0x78, 0x00, 0x10, 0x67, 0x42, 0xc0, 0x1f, 0x43,
	0x23, 0x50, 0x14, 0x05, 0xef, 0x2c, 0x03, 0xc2,
	0x21, 0x1a, 0x80, 0x00, 0x04, 0x68, 0x48, 0xe3,
	0xc8,
}

var video1 *webrtc.TrackLocalStaticSample

func startMultiTrackPublisher(t *testing.T) {

	pc, err := webrtc.NewPeerConnection(rtcconf)
	checkPanic(err)

	// so := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendrecv}
	// // create transceivers for 1x audio, 3x video
	// _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, so)
	// checkPanic(err)
	// _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, so)
	// checkPanic(err)

	video1, err = webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: "video/h264", SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"}, "1", "1")
	checkPanic(err)

	//println(88,)

	rtpSender, err := pc.AddTrack(video1)
	checkPanic(err)
	go processRTCP(rtpSender)

	go func() {

	}()

	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) { println("pub-ICEConnection", s.String()) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) { println("pub-Connection", s.String()) })

	offer, err := pc.CreateOffer(nil)
	checkPanic(err)

	//logSdpReport("dialupstream-offer", offer)
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	err = pc.SetLocalDescription(offer) //start ICE
	checkPanic(err)
	<-gatherComplete

	req := httptest.NewRequest("POST", "http://ignored.com/pub", strings.NewReader(offer.SDP))
	w := httptest.NewRecorder()
	req.Header.Set("Content-Type", "application/sdp")
	pubHandler(w, req) // not super clean, but \_(ツ)_/¯
	resp := w.Result()
	answerraw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 202, resp.StatusCode)
	assert.Equal(t, "application/sdp", resp.Header.Get("Content-Type"))
	ans := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	assert.True(t, ValidateSDP(ans))
	err = pc.SetRemoteDescription(ans)
	checkPanic(err)

	// go func() {
	// 	tk := time.NewTicker(time.Second / 2)

	// 	for range tk.C {
	// 		//RACEY
	// 		//println(98, txtracks[0].pending, txtracks[0].rxid)
	// 		//println(99, txtracks[1].pending, txtracks[1].rxid)
	// 	}
	// }()

}
