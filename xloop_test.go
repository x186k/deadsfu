// +build test

package main

import (
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

var subid = Subid(100)

func TestMsgAddingSwitchingAndRTP(t *testing.T) {
	// state checklist, do not remove
	resetState(t)
	ticker.Stop()

	var txid1 Txid = 2
	var startRxid Rxid = 0
	var nextRxid Rxid = 7

	tr := &Track{
		subid:       subid,
		track:       &webrtc.TrackLocalStaticRTP{},
		splicer:     &RtpSplicer{},
		rxid:        startRxid,
		pendingRxid: 0,
	}

	assert.Equal(t, 0, len(rxid2track[0]), "must have empty rx0")

	subAddTrackCh <- MsgSubscriberAddTrack{
		txid:    txid1,
		txtrack: tr,
	}
	msgOnce()

	{
		//state checklist
		_ = sub2txid2track
		_ = rxid2track
		_ = pendingSwitch
		assert.Equal(t, 1, len(sub2txid2track))
		assert.Equal(t, 1, len(sub2txid2track[subid]))
		assert.Equal(t, tr, sub2txid2track[subid][txid1])
		assert.Equal(t, 1, len(rxid2track))
		assert.Equal(t, 1, len(rxid2track[startRxid]))
		assert.Equal(t, struct{}{}, rxid2track[startRxid][tr])
		assert.Equal(t, startRxid, tr.rxid)
		assert.Equal(t, 0, len(pendingSwitch))
	}

	subSwitchTrackCh <- MsgSubscriberSwitchTrack{
		subid: subid,
		txid:  txid1,
		rxid:  nextRxid,
	}
	msgOnce()

	// switch sent:
	// state checklist
	{
		_ = sub2txid2track
		_ = rxid2track
		_ = pendingSwitch
		assert.Equal(t, 1, len(sub2txid2track))
		assert.Equal(t, 1, len(sub2txid2track[subid]))
		assert.Equal(t, tr, sub2txid2track[subid][txid1])
		assert.Equal(t, 1, len(rxid2track))
		assert.Equal(t, 1, len(rxid2track[startRxid]))
		assert.Equal(t, struct{}{}, rxid2track[startRxid][tr])
		assert.Equal(t, startRxid, tr.rxid)
		assert.Equal(t, 1, len(pendingSwitch))
		assert.Equal(t, struct{}{}, pendingSwitch[nextRxid][tr])
	}

	/*
		send media on rxid WITHOUT pending switch
		BUT! this should not cause a switch, cause this rxid is not pending a switch
	*/
	rxMediaCh <- MsgRxPacket{
		rxid:        startRxid,
		rxClockRate: 0,
		packet:      &rtp.Packet{},
	}
	msgOnce()

	{
		//checklist
		_ = sub2txid2track
		_ = rxid2track
		_ = pendingSwitch
		assert.Equal(t, 1, len(sub2txid2track))
		assert.Equal(t, 1, len(sub2txid2track[subid]))
		assert.Equal(t, tr, sub2txid2track[subid][txid1])
		assert.Equal(t, 1, len(rxid2track))
		assert.Equal(t, 1, len(rxid2track[startRxid]))
		assert.Equal(t, struct{}{}, rxid2track[startRxid][tr])
		assert.Equal(t, startRxid, tr.rxid)
		assert.Equal(t, 1, len(pendingSwitch))
		assert.Equal(t, struct{}{}, pendingSwitch[nextRxid][tr])
	}

	/*
		send media on rxid with pending switch
		BUT! this should not cause a switch, because this is not a valid h.264 SPS!!!
	*/
	rxMediaCh <- MsgRxPacket{
		rxid:        nextRxid,
		rxClockRate: 0,
		packet:      &rtp.Packet{},
	}
	msgOnce()

	{
		//checklist
		_ = sub2txid2track
		_ = rxid2track
		_ = pendingSwitch
		assert.Equal(t, 1, len(sub2txid2track))
		assert.Equal(t, 1, len(sub2txid2track[subid]))
		assert.Equal(t, tr, sub2txid2track[subid][txid1])

		assert.Equal(t, 1, len(rxid2track))
		assert.Equal(t, 1, len(rxid2track[startRxid]))
		assert.Equal(t, struct{}{}, rxid2track[startRxid][tr])
		assert.Equal(t, startRxid, tr.rxid)
		assert.Equal(t, 1, len(pendingSwitch))
		assert.Equal(t, struct{}{}, pendingSwitch[nextRxid][tr])
	}

	/*
		send media on rxid with pending switch
		BUT! this SHOULD  cause a switch, because this is a valid h.264 SPS!!!
	*/
	rxMediaCh <- MsgRxPacket{
		rxid:        nextRxid,
		rxClockRate: 0,
		packet: &rtp.Packet{
			Header:  rtp.Header{},
			Raw:     []byte{},
			Payload: []byte{0x67, 0x42, 0x00, 0x0a, 0xf8, 0x41, 0xa2},
		},
	}
	msgOnce()

	{
		//checklist
		_ = sub2txid2track //no change
		_ = rxid2track     // old removed. and new entry
		_ = pendingSwitch  //now empty
		assert.Equal(t, 1, len(sub2txid2track))
		assert.Equal(t, 1, len(sub2txid2track[subid]))
		assert.Equal(t, tr, sub2txid2track[subid][txid1])

		assert.Equal(t, 0, len(rxid2track[startRxid]))
		assert.Equal(t, 1, len(rxid2track[nextRxid]))
		assert.Equal(t, struct{}{}, rxid2track[nextRxid][tr])

		assert.Equal(t, nextRxid, tr.rxid)

		for _, v := range pendingSwitch {
			assert.Equal(t, 0, len(v))
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
