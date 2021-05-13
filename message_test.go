// +build disableWriteRTP

package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

const subid = Subid(100)

func TestMain(m *testing.M) {
	//flag.Parse() // call flag.Parse() here if TestMain uses flags

	log.SetOutput(ioutil.Discard)
	elog.SetOutput(ioutil.Discard)
	
	os.Exit(m.Run())
}

func TestMsgAddingSwitchingAndRTP(t *testing.T) {
	assert.True(t, disableWriteRTP, "disableWriteRTP must be true for this test")
	if !disableWriteRTP {
		return
	}
	var ok bool

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
		subid:           subid,
		txid:            XVideo + 0,
		rxid:            XVideo + 0,
		rxidLastPending: 0,
		track:           &webrtc.TrackLocalStaticRTP{},
		splicer:         &RtpSplicer{},
	}
	t1 := &Track{
		subid:           subid,
		txid:            XVideo + 1,
		rxid:            XVideo + 1,
		rxidLastPending: 0,
		track:           &webrtc.TrackLocalStaticRTP{},
		splicer:         &RtpSplicer{},
	}
	t2 := &Track{
		subid:           subid,
		txid:            XVideo + 2,
		rxid:            XVideo + 2,
		rxidLastPending: 0,
		track:           &webrtc.TrackLocalStaticRTP{},
		splicer:         &RtpSplicer{},
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

		// checklist
		_ = sub2txid2track                   //affected
		_ = rxid2state[XVideo].txtracks      // affected
		_ = rxid2state[XVideo].pendingSwitch // not affected
		assert.Equal(t, t0, sub2txid2track[subid][XVideo+0])
		assert.Equal(t, t1, sub2txid2track[subid][XVideo+1])
		assert.Equal(t, t2, sub2txid2track[subid][XVideo+2])

		//make sure setup is good
		_, ok = rxid2state[XVideo].txtracks[t0]
		assert.Equal(t, true, ok)
		_, ok = rxid2state[XVideo+1].txtracks[t1]
		assert.Equal(t, true, ok)
		_, ok = rxid2state[XVideo+2].txtracks[t2]
		assert.Equal(t, true, ok)

	}

	// SWITCH to rxid/1
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  XVideo + 0,
			rxid:  XVideo + 1, //was zero
		}
		msgOnce()

		//switch sent
		// checklist
		_ = sub2txid2track                   //not
		_ = rxid2state[XVideo].txtracks      // affected
		_ = rxid2state[XVideo].pendingSwitch //  affected

		//should not have moved
		_, ok = rxid2state[XVideo].txtracks[t0]
		assert.Equal(t, true, ok)

		//should be pending entry
		_, ok = rxid2state[XVideo+1].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, XVideo+1, t0.rxidLastPending)
	}

	// SWITCH to rxid/2
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  XVideo + 0,
			rxid:  XVideo + 2,
		}
		msgOnce()

		// switch sent:
		// checklist
		_ = sub2txid2track                   //not
		_ = rxid2state[XVideo].txtracks      // not
		_ = rxid2state[XVideo].pendingSwitch //  affected

		//should not have moved
		_, ok = rxid2state[XVideo+0].txtracks[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxid2state[XVideo+1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxid2state[XVideo+2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, XVideo+2, t0.rxidLastPending)

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

		//checklist
		_ = sub2txid2track                   //not
		_ = rxid2state[XVideo].txtracks      // not
		_ = rxid2state[XVideo].pendingSwitch //  no affect

		//should not have moved
		_, ok = rxid2state[XVideo+0].txtracks[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxid2state[XVideo+1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxid2state[XVideo+2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, XVideo+2, t0.rxidLastPending)
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

		//checklist
		_ = sub2txid2track                   //no
		_ = rxid2state[XVideo].txtracks      // no
		_ = rxid2state[XVideo].pendingSwitch //  no affect

		//should not have moved
		_, ok = rxid2state[XVideo+0].txtracks[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxid2state[XVideo+1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxid2state[XVideo+2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, XVideo+2, t0.rxidLastPending)
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

		//checklist
		_ = sub2txid2track              //no
		_ = rxid2state[XVideo].txtracks      //  old removed. and new entry
		_ = rxid2state[XVideo].pendingSwitch //  now empty

		//moved
		_, ok = rxid2state[XVideo+0].txtracks[t0]
		assert.Equal(t, false, ok)
		_, ok = rxid2state[XVideo+2].txtracks[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxid2state[XVideo+1].pendingSwitch[t0]
		assert.Equal(t, false, ok)
		// no longer pending on 2
		_, ok = rxid2state[XVideo+2].pendingSwitch[t0]
		assert.Equal(t, false, ok)

	}

	/*
	   Tracks are normally eliminated when WriteRTP returns io.Eof*
	   by calling removeTrack(tr)
	   We will emulate that for the three tracks
	*/
	{
		removeTrack(t0)
		removeTrack(t1)
		removeTrack(t2)

		//checklist
		_ = sub2txid2track              //no
		_ = rxid2state[XVideo].txtracks      //  old removed. and new entry
		_ = rxid2state[XVideo].pendingSwitch //  now empty

		for _, v := range sub2txid2track {
			assert.Zero(t, len(v))
		}
		for _, v := range rxid2state {
			assert.Zero(t, len(v.txtracks))
		}
		for _, v := range rxid2state {
			assert.Zero(t, len(v.pendingSwitch))
		}
	}

}

func resetState(t *testing.T) {

	// clear 4x maps
	{
		m := sub2txid2track
		for k := range m {
			delete(m, k)
		}
	}
	{
		for _, v := range rxid2state {
			v.txtracks = make(map[*Track]struct{})
			v.pendingSwitch = make(map[*Track]struct{})
		}
	}

	// checklist
	// _ = sub2txid2track
	// _ = rxidArray[0].rxid2track
	// _ = rxidArray[0].pendingSwitch

	assert.Equal(t, 0, len(sub2txid2track))
	{
		for _, v := range rxid2state {
			assert.Equal(t, 0, len(v.txtracks))
			assert.Equal(t, 0, len(v.pendingSwitch))
		}
	}
}

func mustPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Errorf("The code did not panic")
	}
}

func TestMsgBadAdd(t *testing.T) {
	resetState(t)
	ticker.Stop()

	defer mustPanic(t)

	time.Sleep(time.Millisecond * 20)

	subAddTrackCh <- MsgSubscriberAddTrack{
		txtrack: nil,
	}

	msgOnce()
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
