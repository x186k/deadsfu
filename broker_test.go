package main

import (
	//"sync"
	//"sync"
	"log"
	"os"
	"testing"
	"time"

	"github.com/pion/rtp"
)

var N int

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)
	os.Exit(m.Run())
}

func BenchmarkBrokerNoWrite(b *testing.B) {

	a := NewXBroker()
	go a.Start()

	c := a.Subscribe()
	<-c

	// pp := sync.Pool{
	// 	// New optionally specifies a function to generate
	// 	// a value when Get would otherwise return nil.
	// 	New: func() interface{} { return new(XPacket) },
	// }

	d := make(chan struct{})
	go func() {

		for z := range c {

			zz := z.(*XPacket)
			//pp.Put(zz)
			N += int(zz.typ)
		}
		close(d)
	}()

	//println(88,b.N)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//p := pp.Get().(*XPacket)
		p := XPacket{}
		p.typ = Video
		if i%200 == 0 {
			p.keyframe = true
		} else {
			p.keyframe = false
		}
		a.Publish(&p)

	}
	b.StopTimer()
	a.Unsubscribe(c)

	<-d
}

type Z struct {
	//nwrite int
}

func (z *Z) WriteRTP(p *rtp.Packet) error {
	//z.nwrite++
	return nil
}

func BenchmarkBrokerWithWriter1Pairs(b *testing.B) {
	benchmarkBrokerWithWriter(b, 1)
}
func BenchmarkBrokerWithWriter10Pairs(b *testing.B) {
	benchmarkBrokerWithWriter(b, 10)
}
func BenchmarkBrokerWithWriter100Pairs(b *testing.B) {
	benchmarkBrokerWithWriter(b, 100)
}

func benchmarkBrokerWithWriter(b *testing.B, numpairs int) {

	a := NewXBroker()
	go a.Start()

	c := a.Subscribe()
	<-c

	// pp := sync.Pool{
	// 	// New optionally specifies a function to generate
	// 	// a value when Get would otherwise return nil.
	// 	New: func() interface{} { return new(XPacket) },
	// }

	d := make(chan struct{})
	go func() {

		for z := range c {

			zz := z.(*XPacket)
			//pp.Put(zz)
			N += int(zz.typ)
		}
		close(d)
	}()

	trks := NewTxTracks()

	for i := 0; i < numpairs; i++ {
		vidwriter := &Z{}
		pair := TxTrackPair{
			aud: TxTrack{
				track:     vidwriter,
				splicer:   RtpSplicer{},
				clockrate: 48000,
			},
			vid: TxTrack{
				track:     vidwriter,
				splicer:   RtpSplicer{},
				clockrate: 90000,
			},
		}
		trks.Add(&pair)
	}

	ch := a.Subscribe()
	go groupWriter(ch, trks)

	//println(88,b.N)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//p := pp.Get().(*XPacket)

		p := XPacket{
			arrival:  0,
			pkt:      &rtp.Packet{},
			typ:      0,
			keyframe: false,
		}

		p.typ = Video
		if i%200 == 0 {
			p.keyframe = true
		} else {
			p.keyframe = false
		}
		a.Publish(&p)

	}
	b.StopTimer()
	a.Unsubscribe(c)

	<-d

	time.Sleep(time.Second)

	//data race
	// nn:=0
	// for k:=range trks.live{
	// 	z:=k.vid.track.(*Z)
	// 	nn+=z.nwrite
	// }
	// log.Println("num writes", nn)
}

func TestNanosecondsPerSubscriberSend(b *testing.T) {

	var r testing.BenchmarkResult

	r = testing.Benchmark(BenchmarkBrokerWithWriter1000PairsPool)
	r.Extra["ns/send-op"] = float64(r.T) / float64(r.N) / 1000
	println("1000sends, with pool:", r.String())

	r = testing.Benchmark(BenchmarkBrokerWithWriter1000PairsNoPool)
	r.Extra["ns/send-op"] = float64(r.T) / float64(r.N) / 1000
	println("1000sends, without pool:", r.String())

}
