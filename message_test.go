// +build disableWriteRTP

package main

import (
	"testing"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

const subid = Subid(100)

func TestMsgAddingSwitchingAndRTP(t *testing.T) {
	assert.True(t, disableWriteRTP, "disableWriteRTP must be true for this test")
	if !disableWriteRTP {
		return
	}

	// state checklist, do not remove
	resetState(t)
	initMediaHandlerState(TrackCounts{
		numVideo:     6,
		numAudio:     1,
		numIdleVideo: 1,
		numIdleAudio: 0,
	})
	ticker.Stop()

	t0 := &Track{
		subid:   subid,
		txid:    XVideo + 0,
		rxid:    XVideo + 0,
		track:   &webrtc.TrackLocalStaticRTP{},
		splicer: &RtpSplicer{},
	}
	t1 := &Track{
		subid:   subid,
		txid:    XVideo + 1,
		rxid:    XVideo + 1,
		track:   &webrtc.TrackLocalStaticRTP{},
		splicer: &RtpSplicer{},
	}
	t2 := &Track{
		subid:   subid,
		txid:    XVideo + 2,
		rxid:    XVideo + 2,
		track:   &webrtc.TrackLocalStaticRTP{},
		splicer: &RtpSplicer{},
	}

	assert.NotEqual(t, t1, t0)
	assert.NotEqual(t, t2, t0)
	assert.NotEqual(t, t1, t2)

	{

		subAddTrackCh <- MsgSubscriberAddTrack{txtrack: t0}
		msgOnce()
		subAddTrackCh <- MsgSubscriberAddTrack{txtrack: t1}
		msgOnce()
		subAddTrackCh <- MsgSubscriberAddTrack{txtrack: t2}
		msgOnce()

		assert.Equal(t, XVideo, rxid2state[XVideo].rxid)

		assert.Equal(t, t0, sub2txid2track[subid][XVideo+0])
		assert.Equal(t, t1, sub2txid2track[subid][XVideo+1])
		assert.Equal(t, t2, sub2txid2track[subid][XVideo+2])

	}

	// SWITCH to rxid/1
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  XVideo + 0,
			rxid:  XVideo + 1, //was zero
		}
		msgOnce()

	}

	// SWITCH to rxid/2
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  XVideo + 0,
			rxid:  XVideo + 2,
		}
		msgOnce()

	}

	/*
		new media on rxid/0 (not pending)
		not a keyframe
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxidstate:   rxid2state[XVideo+0],
			rxClockRate: 0,
			packet:      &rtp.Packet{},
		}
		msgOnce()

	}

	/*
		new media on rxid/2
		not keyframe
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxidstate:   rxid2state[XVideo+2],
			rxClockRate: 0,
			packet:      &rtp.Packet{},
		}
		msgOnce()

	}

	/*
		new media on rxid/2
		IS Keyframe!
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxidstate:   rxid2state[XVideo+2],
			rxClockRate: 0,
			packet: &rtp.Packet{
				Header:  rtp.Header{},
				Raw:     []byte{},
				Payload: []byte{0x67, 0x42, 0x00, 0x0a, 0xf8, 0x41, 0xa2},
			},
		}
		msgOnce()

	}

	/*
	   Tracks are normally eliminated when WriteRTP returns io.Eof*
	   by calling removeTrack(tr)
	   We will emulate that for the three tracks
	*/

}

func resetState(t *testing.T) {

	// clear 4x maps

	m := sub2txid2track
	for k := range m {
		delete(m, k)
	}

}

func mustPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Errorf("The code did not panic")
	}
}

func TestMsgInvalidSwitchTrack(t *testing.T) {
	resetState(t)
	ticker.Stop()

	// The following is the code under test
	subSwitchTrackCh <- MsgSubscriberSwitchTrack{
		subid: Subid(subid), //invalid!
		txid:  XVideo + 999,
		rxid:  XVideo + 99,
	}

	msgOnce()

	assert.Equal(t, 0, len(sub2txid2track[Subid(subid)]))

}
