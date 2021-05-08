// +build disableWriteRTP

package main

import (
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

const subid = Subid(100)

// func TestMain(m *testing.M) {
// 	//flag.Parse() // call flag.Parse() here if TestMain uses flags

// 	os.Exit(m.Run())
// }

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
		txid:            0,
		rxid:            0,
		rxidLastPending: 0,
	}
	t1 := &Track{
		subid:           subid,
		txid:            1,
		rxid:            1,
		rxidLastPending: 0,
		track:           &webrtc.TrackLocalStaticRTP{},
		splicer:         &RtpSplicer{},
	}
	t2 := &Track{
		subid:           subid,
		txid:            2,
		rxid:            2,
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

		// checklist
		_ = sub2txid2track             //affected
		_ = rxidArray[0].rxid2track    // affected
		_ = rxidArray[0].pendingSwitch // not affected
		assert.Equal(t, t0, sub2txid2track[subid][0])
		assert.Equal(t, t1, sub2txid2track[subid][1])
		assert.Equal(t, t2, sub2txid2track[subid][2])

		//make sure setup is good
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, true, ok)
		_, ok = rxidArray[1].rxid2track[t1]
		assert.Equal(t, true, ok)
		_, ok = rxidArray[2].rxid2track[t2]
		assert.Equal(t, true, ok)

	}

	// SWITCH to rxid/1
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  0,
			rxid:  1, //was zero
		}
		msgOnce()

		//switch sent
		// checklist
		_ = sub2txid2track             //not affected
		_ = rxidArray[0].rxid2track    //affected
		_ = rxidArray[0].pendingSwitch //affected

		//should not have moved
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, true, ok)

		//should be pending entry
		_, ok = rxidArray[1].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, Rxid(1), t0.rxidLastPending)
	}

	// SWITCH to rxid/2
	{
		subSwitchTrackCh <- MsgSubscriberSwitchTrack{
			subid: subid,
			txid:  0,
			rxid:  2,
		}
		msgOnce()

		// switch sent:
		// checklist
		_ = sub2txid2track             //not affected
		_ = rxidArray[0].rxid2track    //no affect, since not keyframe
		_ = rxidArray[0].pendingSwitch // affected

		//should not have moved
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxidArray[1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxidArray[2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, Rxid(2), t0.rxidLastPending)

	}

	/*
		new media on rxid/0 (not pending)
		not a keyframe
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxid:        0,
			rxClockRate: 0,
			packet:      &rtp.Packet{},
		}
		msgOnce()

		//checklist
		_ = sub2txid2track             //no affect
		_ = rxidArray[0].rxid2track    // no affect
		_ = rxidArray[0].pendingSwitch // not keyframe, no affect

		//should not have moved
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxidArray[1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxidArray[2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, Rxid(2), t0.rxidLastPending)
	}

	/*
		new media on rxid/2
		not keyframe
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxid:        2,
			rxClockRate: 0,
			packet:      &rtp.Packet{},
		}
		msgOnce()

		//checklist
		_ = sub2txid2track
		_ = rxidArray[0].rxid2track    // no affect
		_ = rxidArray[0].pendingSwitch // not keyframe, no affect

		//should not have moved
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxidArray[1].pendingSwitch[t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = rxidArray[2].pendingSwitch[t0]
		assert.Equal(t, true, ok)
		assert.Equal(t, Rxid(2), t0.rxidLastPending)
	}

	/*
		new media on rxid/2
		IS Keyframe!
	*/
	{
		rxMediaCh <- MsgRxPacket{
			rxid:        2,
			rxClockRate: 0,
			packet: &rtp.Packet{
				Header:  rtp.Header{},
				Raw:     []byte{},
				Payload: []byte{0x67, 0x42, 0x00, 0x0a, 0xf8, 0x41, 0xa2},
			},
		}
		msgOnce()

		//checklist
		_ = sub2txid2track             //no change
		_ = rxidArray[0].rxid2track    // old removed. and new entry
		_ = rxidArray[0].pendingSwitch //now empty

		//moved
		_, ok = rxidArray[0].rxid2track[t0]
		assert.Equal(t, false, ok)
		_, ok = rxidArray[2].rxid2track[t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = rxidArray[1].pendingSwitch[t0]
		assert.Equal(t, false, ok)
		// no longer pending on 2
		_, ok = rxidArray[2].pendingSwitch[t0]
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
		_ = sub2txid2track             //no change
		_ = rxidArray[0].rxid2track    // old removed. and new entry
		_ = rxidArray[0].pendingSwitch //now empty

		for _, v := range sub2txid2track {
			assert.Zero(t, len(v))
		}
		for _, v := range rxidArray {
			assert.Zero(t, len(v.rxid2track))
		}
		for _, v := range rxidArray {
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
		for _, v := range rxidArray {
			v.rxid2track = make(map[*Track]struct{})
			v.pendingSwitch = make(map[*Track]struct{})
		}
	}

	// checklist
	// _ = sub2txid2track
	// _ = rxidArray[0].rxid2track
	// _ = rxidArray[0].pendingSwitch

	assert.Equal(t, 0, len(sub2txid2track))
	{
		for _, v := range rxidArray {
			assert.Equal(t, 0, len(v.rxid2track))
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
		txid:  999,
		rxid:  99,
	}

	msgOnce()

	assert.Equal(t, 0, len(sub2txid2track[Subid(subid)]))

}
