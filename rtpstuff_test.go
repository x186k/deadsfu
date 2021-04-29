package main

// This has questionable value.

import (
	"math"
	"sort"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

type XPacket struct {
	rtp.Packet
	t time.Time
}

var _ = MergeAB

func MergeAB(t *testing.T, a []XPacket, b []XPacket) []XPacket {

	for i, v := range a[1:] {
		assert.Equal(t, v.SSRC, a[i].SSRC, "ssrc must be same")
	}
	for i, v := range b[1:] {
		assert.Equal(t, v.SSRC, b[i].SSRC, "ssrc must be same")
	}
	assert.NotEqual(t, a[0].SSRC, b[0].SSRC, "ssrc must be diff")

	merged := make([]XPacket, 0)
	merged = append(merged, a...)
	merged = append(merged, b...)

	sort.Slice(merged, func(i, j int) bool { return merged[i].t.Before(merged[j].t) })

	return merged
}

// func checkKeyframeOnSSRCChange(t *testing.T, a []XPacket) {
// 	for i, v := range a {
// 		if i > 0 {
// 			if v.SSRC != a[i-1].SSRC && !v.isSplicable {
// 				t.Fatal("SPS is false, on SSRC transition, must be true for valid stream")
// 			}
// 		}
// 	}
// }

var _ = checkSeqno

func checkSeqno(t *testing.T, a []XPacket) {
	for i, v := range a {
		if i > 0 {
			if math.Abs(float64(v.Packet.SequenceNumber-a[i-1].Packet.SequenceNumber)) > 10 {
				t.Fatal("big jump in sequence numbers")
			}
		}
	}
}

var _ = checkTSdeviation

func checkTSdeviation(t *testing.T, a []XPacket, rtphz int) {
	for _, x := range a {
		{
			expected := uint32(x.t.UnixNano() * int64(rtphz) / int64(time.Second))

			deviation := int32(expected - x.Packet.Timestamp)
			if deviation < 0 {
				deviation = -deviation
			}
			if deviation > int32(rtphz/2) {
				t.Fatal("timestamp deviation > one half second! fatal")
			}
		}
	}
}
