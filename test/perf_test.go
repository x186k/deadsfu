package test

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/pion/rtp"
)

type WriteRtpIntf interface {
	WriteRTP(p *rtp.Packet) error
}

type RtpSplicer struct {
	lastUnixnanosNow int64
	lastSSRC         uint32
	lastTS           uint32
	tsOffset         uint32
	lastSN           uint16
	snOffset         uint16
}

func (s *RtpSplicer) SpliceWriteRTPPointer(trk WriteRtpIntf, p *rtp.Packet, unixnano int64, rtphz int64) {

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	// 12/30/21 maybe we should use something else other than SSRC transitions?
	if p.SSRC != s.lastSSRC {

		if unixnano == 0 {
			panic("unixnano cannot be zero.")
		}

		td1 := unixnano - s.lastUnixnanosNow // nanos
		if td1 < 0 {
			td1 = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		//td2 := td1 * rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		td2 := td1 / (int64(time.Second) / rtphz) //convert nanos -> 90khz or similar clockrate. speed not important
		if td2 == 0 {
			td2 = 1
		}
		s.tsOffset = p.Timestamp - (s.lastTS + uint32(td2))
		s.snOffset = p.SequenceNumber - s.lastSN - 1

	}

	p.Timestamp -= s.tsOffset
	p.SequenceNumber -= s.snOffset

	// xdbg := true
	// if xdbg {
	// 	if p.SSRC != s.lastSSRC && rtphz == 90000 {
	// 		pl("last ts", s.lastTS, s.lastUnixnanosNow)
	// 		pl("new ts", p.Timestamp, unixnano)
	// 	}
	// }

	s.lastUnixnanosNow = unixnano
	s.lastTS = p.Timestamp
	s.lastSN = p.SequenceNumber
	s.lastSSRC = p.SSRC

	//I had believed it was possible to see: io.ErrClosedPipe {
	// but I no longer believe this to be true
	// if it turns out I can see those, we will need to adjust
	err := trk.WriteRTP(p)
	if err != nil {
		panic(err)
	}
}

func (s *RtpSplicer) SpliceWriteRTP(trk WriteRtpIntf, p rtp.Packet, unixnano int64, rtphz int64) {

	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	// 12/30/21 maybe we should use something else other than SSRC transitions?
	if p.SSRC != s.lastSSRC {

		if unixnano == 0 {
			panic("unixnano cannot be zero.")
		}

		td1 := unixnano - s.lastUnixnanosNow // nanos
		if td1 < 0 {
			td1 = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		//td2 := td1 * rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		td2 := td1 / (int64(time.Second) / rtphz) //convert nanos -> 90khz or similar clockrate. speed not important
		if td2 == 0 {
			td2 = 1
		}
		s.tsOffset = p.Timestamp - (s.lastTS + uint32(td2))
		s.snOffset = p.SequenceNumber - s.lastSN - 1

	}

	p.Timestamp -= s.tsOffset
	p.SequenceNumber -= s.snOffset

	// xdbg := true
	// if xdbg {
	// 	if p.SSRC != s.lastSSRC && rtphz == 90000 {
	// 		pl("last ts", s.lastTS, s.lastUnixnanosNow)
	// 		pl("new ts", p.Timestamp, unixnano)
	// 	}
	// }

	s.lastUnixnanosNow = unixnano
	s.lastTS = p.Timestamp
	s.lastSN = p.SequenceNumber
	s.lastSSRC = p.SSRC

	//I had believed it was possible to see: io.ErrClosedPipe {
	// but I no longer believe this to be true
	// if it turns out I can see those, we will need to adjust
	err := trk.WriteRTP(&p)
	if err != nil {
		panic(err)
	}
}

type Z struct{}

func (z Z) WriteRTP(p *rtp.Packet) error {
	return nil
}

var z Z

func BenchmarkSplicePointer(b *testing.B) {
	spl := &RtpSplicer{}
	p := &rtp.Packet{}
	for i := 0; i < b.N; i++ {
		spl.SpliceWriteRTPPointer(z, p, int64(i), 90000)
	}
}
func BenchmarkSpliceStack(b *testing.B) {
	spl := &RtpSplicer{}
	p := rtp.Packet{}
	for i := 0; i < b.N; i++ {
		spl.SpliceWriteRTP(z, p, int64(i), 90000)
	}
}

type Pptr *rtp.Packet


func TestX(t*testing.T) {
	var i *rtp.Packet


	fmt.Fprintln(os.Stderr,9999)
	fmt.Printf("Size of *rtp.packet (reflect.TypeOf.Size): %d\n", reflect.TypeOf(i).Size())
	fmt.Printf("Size of *rtp.packet  (unsafe.Sizeof): %d\n", unsafe.Sizeof(i))

	var j rtp.Packet
	fmt.Printf("Size of rtp.packet (reflect.TypeOf.Size): %d\n", reflect.TypeOf(j).Size())
    fmt.Printf("Size of rtp.packet  (unsafe.Sizeof): %d\n", unsafe.Sizeof(j))
}



