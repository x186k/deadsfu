package rtpsplice

import (
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

type XPacket struct {
	rtp.Packet
	t           time.Time
	isSplicable bool
	source      RtpSource
	setPending  RtpSource
}

func ReadXPackets(fn string, ssrc uint32) (r []XPacket) {

	f, err := os.Open(fn)
	checkPanic(err)

	p, t, err := ReadPcap2RTP(f)
	checkPanic(err)

	for i := range p {
		if p[i].SSRC == ssrc {
			xp := XPacket{}
			xp.Packet = p[i]
			xp.t = t[i]
			xp.isSplicable = ContainSPS(p[i].Payload)
			xp.source = Video1
			r = append(r, xp)
		}
	}

	return
}

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

// DoSpliceTest will merge two Xpacket streams
// using the splicer and return the result
//
func DoSpliceTest(t *testing.T, merged []XPacket, active RtpSource) []XPacket {

	s := &RtpSplicer{}

	s.active = active

	o := make([]XPacket, 0)

	for _, v := range merged {

		if v.setPending != None {
			s.pending = v.setPending
		}

		new := s.SpliceRTP(&v.Packet, v.source, v.t.UnixNano(), 90000)
		if new != nil {
			//			println(len(merged))
			x := XPacket{}
			x.Packet = *new
			x.t = v.t
			x.source = v.source
			x.isSplicable = v.isSplicable
			o = append(o, x)
		}

	}

	return o
}

//Munge will create a second XPacket from an originsl XPacket
// with many per-packet attributes modified
// so the new array can be used for testing
//
//
// new.t = v.t+1
// new.packet=cloned packet
// new.packet.ssrc = ^v.ssrc
// new.packet.timestamp += X
// new.packet.seqno += Y
// new.sps = v.sps
// new.rtpsource = newsrc
//

func Munge(t *testing.T, a []XPacket, newsrc RtpSource) (r []XPacket) {
	for i, v := range a[1:] {
		assert.Equal(t, v.SSRC, a[i].SSRC, "ssrc must be same")
		assert.Equal(t, v.source, Video1, "must be video 1")
	}

	for _, v := range a {
		x := XPacket{}

		x.t = v.t.Add(1) //one nano
		x.isSplicable = v.isSplicable
		x.source = Video2

		x.Packet = v.Packet
		x.Packet.SSRC = v.Packet.SSRC + 1
		x.Packet.Timestamp = v.Packet.Timestamp + math.MaxUint32/2
		x.Packet.SequenceNumber = v.Packet.SequenceNumber + math.MaxUint16/2
		r = append(r, x)
	}

	return
}

func checkKeyframeOnSSRCChange(t *testing.T, a []XPacket) {
	for i, v := range a {
		if i > 0 {
			if v.SSRC != a[i-1].SSRC && !v.isSplicable {
				t.Fatal("SPS is false, on SSRC transition, must be true for valid stream")
			}
		}
	}
}

func checkSeqno(t *testing.T, a []XPacket) {
	for i, v := range a {
		if i > 0 {
			if math.Abs(float64(v.Packet.SequenceNumber-a[i-1].Packet.SequenceNumber)) > 10 {
				t.Fatal("big jump in sequence numbers")
			}
		}
	}
}

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

func Test1_RTPSplice(t *testing.T) {

	//WE KEEP MULTIPLE SSRCs IN A PCAPNG for regression testing
	//why:
	//we keep the pcapng files as wholes without splitting into the
	//various SSRC flows.
	// this has downsides, but maybe turn out to be very powerful
	// if we need to debug/inspect a particular call from a end-user
	// in that case, we will we want to be using merged SSRC files,
	// not hand-split individual SSRC files

	fn := "../lfs/h264.012021.pcapng"
	a := ReadXPackets(fn,0x58F98CC5)
	b := Munge(t, a, Video2)
	// for i := 0; i < 50; i++ {
	// 	fmt.Println(i, a[i])
	// 	fmt.Println(i, b[i])
	// }
	// for i, v := range a[:50] {
	// 	fmt.Println(i, v)
	// }
	// for i, v := range b[:50] {
	// 	fmt.Println(i, v)
	// }

	//	fmt.Println("lena", len(a))
	//fmt.Println("lenb", len(b))

	m := MergeAB(t, a, b)
	m[10].setPending = Video2
	c := DoSpliceTest(t, m, Video1)
	//assert.Equal(t, len(m), len(c), "in/out must be same len")

	checkTSdeviation(t, c, 90000)
	checkKeyframeOnSSRCChange(t, c)
	checkSeqno(t, c)

	// for i := range m {
	// //	fmt.Println(m[i])
	// }
}

func (x XPacket) String() string {
	//return fmt.Sprint(x.t.UnixNano(), x.source, x.sps, x.Packet.SequenceNumber, x.Packet.Timestamp, x.Packet.SSRC, x.Packet.Marker)

	expected := uint32(x.t.UnixNano() * 90000 / int64(time.Second))
	ts2 := x.Packet.Timestamp
	tsd := int32(expected - ts2)
	spsstr := "  "
	if x.isSplicable {
		spsstr = "t "
	}

	return fmt.Sprint(x.source, spsstr, ts2, expected, tsd, x.Packet.SequenceNumber, x.Packet.SSRC)

	//return fmt.Sprintln(x.t, x.source)
	//return "ouch"
}
