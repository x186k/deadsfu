// +build test

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
	var ok bool

	// state checklist, do not remove
	resetState(t)
	initMediaHandlerState(3,1)
	ticker.Stop()

	var t0, t1, t2 *Track

	t0 = &Track{
		subid:           subid,
		track:           &webrtc.TrackLocalStaticRTP{},
		splicer:         &RtpSplicer{},
		rxid:            0,
		rxidLastPending: 0,
	}

	{
		x := *t0
		x.rxid = 1
		t1 = &x
		y := *t0
		y.rxid = 2
		t2 = &y
	}

	assert.NotEqual(t, t1, t0)
	assert.NotEqual(t, t2, t0)
	assert.NotEqual(t, t1, t2)

	{

		subAddTrackCh <- MsgSubscriberAddTrack{txid: 0, txtrack: t0}
		msgOnce()
		subAddTrackCh <- MsgSubscriberAddTrack{txid: 1, txtrack: t1}
		msgOnce()
		subAddTrackCh <- MsgSubscriberAddTrack{txid: 2, txtrack: t2}
		msgOnce()

		//state checklist
		_ = sub2txid2track //affected
		_ = rxid2track     //affected
		_ = pendingSwitch  //no affect
		assert.Equal(t, t0, sub2txid2track[subid][0])
		assert.Equal(t, t1, sub2txid2track[subid][1])
		assert.Equal(t, t2, sub2txid2track[subid][2])

		//make sure setup is good
		_, ok = rxid2track[0][t0]
		assert.Equal(t, true, ok)
		_, ok = rxid2track[1][t1]
		assert.Equal(t, true, ok)
		_, ok = rxid2track[2][t2]
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

		// switch sent:
		// state checklist
		_ = sub2txid2track //no affect
		_ = rxid2track     //n/a
		_ = pendingSwitch  //affected

		//should not have moved
		_, ok = rxid2track[0][t0]
		assert.Equal(t, true, ok)

		//should be pending entry
		_, ok = pendingSwitch[1][t0]
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
		// state checklist
		//state checklist
		_ = sub2txid2track //affected
		_ = rxid2track     //no affect, since not keyframe
		_ = pendingSwitch  //no affect

		//should not have moved
		_, ok = rxid2track[0][t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = pendingSwitch[1][t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = pendingSwitch[2][t0]
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
		_ = sub2txid2track
		_ = rxid2track
		_ = pendingSwitch

		//should not have moved
		_, ok = rxid2track[0][t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = pendingSwitch[1][t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = pendingSwitch[2][t0]
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
		_ = rxid2track
		_ = pendingSwitch

		//should not have moved
		_, ok = rxid2track[0][t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = pendingSwitch[1][t0]
		assert.Equal(t, false, ok)

		// now  pending on 2
		_, ok = pendingSwitch[2][t0]
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
		_ = sub2txid2track //no change
		_ = rxid2track     // old removed. and new entry
		_ = pendingSwitch  //now empty

		//moved
		_, ok = rxid2track[0][t0]
		assert.Equal(t, false, ok)
		_, ok = rxid2track[2][t0]
		assert.Equal(t, true, ok)

		// not longer pending on 1
		_, ok = pendingSwitch[1][t0]
		assert.Equal(t, false, ok)
		// no longer pending on 2
		_, ok = pendingSwitch[2][t0]
		assert.Equal(t, false, ok)

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
		m := rxid2track
		for k := range m {
			delete(m, k)
		}
	}
	{
		m := pendingSwitch
		for k := range m {
			delete(m, k)
		}
	}

	// development helper checklist, do not remove
	_ = sub2txid2track
	_ = rxid2track
	_ = pendingSwitch
	assert.Equal(t, 0, len(sub2txid2track))
	assert.Equal(t, 0, len(rxid2track))
	assert.Equal(t, 0, len(pendingSwitch))
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
		txid:    0,
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
