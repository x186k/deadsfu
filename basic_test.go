package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// call flag.Parse() here if TestMain uses flags

	log.SetOutput(ioutil.Discard)
	log.SetFlags(0)
	elog.SetOutput(ioutil.Discard)
	elog.SetFlags(0)

	os.Exit(m.Run())
}

func TestBasicSubscriber(t *testing.T) {

	initStateAndGoroutines()

	rtcconf := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	pc, err := webrtc.NewPeerConnection(rtcconf)
	checkPanic(err)

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
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
			fmt.Printf(" rx test-pc %v %x\n", mimetype, p.Payload[0:10])
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
	subHandler(w, req)
	resp := w.Result()
	answerraw, _ := io.ReadAll(resp.Body)

	assert.Equal(t, 202, resp.StatusCode)
	assert.Equal(t, resp.Header.Get("Content-Type"), "application/sdp")

	ans := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answerraw)}
	assert.True(t, validateSDP(ans))

	err = pc.SetRemoteDescription(ans)
	checkPanic(err)



	tk := time.NewTicker(time.Second)

	for range tk.C {
		println(98,txtracks[0].pending,txtracks[0].rxid)
		println(99,txtracks[1].pending,txtracks[1].rxid)
	}
}
