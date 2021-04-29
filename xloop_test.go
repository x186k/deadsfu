// +build test

package main

import (
	"os"
	"testing"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/assert"
)

var subid = Subid(100)

func TestMain(m *testing.M) {

	// call flag.Parse() here if TestMain uses flags

	go xloop()

	os.Exit(m.Run())
}

func TestXloop1(t *testing.T) {

	subAddTrackCh <- MsgSubscriberAddTrack{
		subid:     subid,
		txtrackid: 0,
		txtrack: &TrackSplicer{
			track:   &webrtc.TrackLocalStaticRTP{},
			splicer: &RtpSplicer{},
		},
	}

	time.Sleep(time.Millisecond * 20)
	assert.Equal(t, 1, len(subid2Track[Subid(subid)]), "missing")

	subSwitchTrackCh <- MsgSubscriberSwitchTrack{
		subid:     subid,
		txtrackid: 0,
		rxtrackid: 1,
	}
}

func mustPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Errorf("The code did not panic")
	}
}

func TestXloopBadAdd(t *testing.T) {
	defer mustPanic(t)

	time.Sleep(time.Millisecond * 20)

	subAddTrackCh <- MsgSubscriberAddTrack{
		subid:     subid,
		txtrackid: 0,
		txtrack:   nil,
	}

	xloop()
}

func TestXloop2(t *testing.T) {

	// The following is the code under test
	subSwitchTrackCh <- MsgSubscriberSwitchTrack{
		subid:     Subid(subid), //invalid!
		txtrackid: 999,
		rxtrackid: 99,
	}

	time.Sleep(time.Millisecond * 20)
	assert.Equal(t, 0, len(subid2Track[Subid(subid)]), "subid2Track[x] must be nil")

}
