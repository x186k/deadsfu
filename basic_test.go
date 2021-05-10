// +build !disableWriteRTP

package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// call flag.Parse() here if TestMain uses flags

	log.SetOutput(ioutil.Discard)
	log.SetPrefix("")
	log.SetFlags(0)
	elog.SetOutput(ioutil.Discard)
	elog.SetPrefix("")
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

	ro := webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}
	// // create transceivers for 1x audio, 3x video
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

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		println("--ontrack")
	})

	err = pc.SetLocalDescription(offer) //start ICE
	checkPanic(err)

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



	select {}

}
