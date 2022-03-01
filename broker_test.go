package main

import (
	//"sync"
	//"sync"
	"log"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/pion/rtp"
	//"github.com/x186k/deadsfu"
)

// c@macmini ~/D/deadsfu (main) [1]> go test -bench='^BenchmarkBrokerWithWriter' . -run='^$' .
// goos: darwin
// goarch: amd64
// pkg: github.com/x186k/deadsfu
// cpu: Intel(R) Core(TM) i5-8500B CPU @ 3.00GHz
// BenchmarkBrokerWithWriter1PairsPool-6        	 4031882	       302.8 ns/op	       302.8 ns/write	      33 B/op	       0 allocs/op
// BenchmarkBrokerWithWriter10PairsPool-6       	 3100899	       422.4 ns/op	        42.24 ns/write	      33 B/op	       0 allocs/op
// BenchmarkBrokerWithWriter100PairsPool-6      	  693356	      1987 ns/op	        19.87 ns/write	      32 B/op	       0 allocs/op
// BenchmarkBrokerWithWriter1000PairsPool-6     	   87928	     20177 ns/op	        20.18 ns/write	      15 B/op	       0 allocs/op
// BenchmarkBrokerWithWriter1PairsNoPool-6      	 3432055	       359.8 ns/op	       359.8 ns/write	     181 B/op	       2 allocs/op
// BenchmarkBrokerWithWriter10PairsNoPool-6     	 2623671	       438.1 ns/op	        43.81 ns/write	     181 B/op	       2 allocs/op
// BenchmarkBrokerWithWriter100PairsNoPool-6    	  609979	      1992 ns/op	        19.92 ns/write	     181 B/op	       2 allocs/op
// BenchmarkBrokerWithWriter1000PairsNoPool-6   	   56983	     20324 ns/op	        20.32 ns/write	     182 B/op	       2 allocs/op
// PASS
// ok  	github.com/x186k/deadsfu	12.716s

var N int

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)
	os.Exit(m.Run())
}

// var pool = sync.Pool{
// 	// New optionally specifies a function to generate
// 	// a value when Get would otherwise return nil.
// 	New: func() interface{} { return new(XPacket) },
// }

func BenchmarkBrokerNoWrite(b *testing.B) {

	a := NewXBroker()
	go a.Start()

	c := a.Subscribe()
	<-c

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

type DummyWriter struct {
	//nwrite int
}

func (z *DummyWriter) WriteRTP(p *rtp.Packet) error {
	//z.nwrite++
	return nil
}

func BenchmarkBrokerWithWriter1PairsNoPool(b *testing.B) {
	benchmarkBrokerWithWriter(b, 1)
}
func BenchmarkBrokerWithWriter10PairsNoPool(b *testing.B) {
	benchmarkBrokerWithWriter(b, 10)
}
func BenchmarkBrokerWithWriter100PairsNoPool(b *testing.B) {
	benchmarkBrokerWithWriter(b, 100)
}
func BenchmarkBrokerWithWriter1000PairsNoPool(b *testing.B) {
	benchmarkBrokerWithWriter(b, 1000)
}

func benchmarkBrokerWithWriter(b *testing.B, numwrites int) {

	trks := NewTxTracks()

	for i := 0; i < numwrites; i++ {
		vidwriter := &DummyWriter{}
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

	a := NewXBroker()
	go a.Start()
	ch := a.Subscribe()
	go groupWriter(ch, trks)

	b.ReportAllocs()
	b.ResetTimer()

	var p *XPacket
	p = &XPacket{
		arrival:  0,
		pkt:      rtp.Packet{},
		typ:      0,
		keyframe: false,
		buf:      make([]byte, 1540),
	}

	// if usepool {
	// 	p = xpacketPool.Get().(*XPacket)
	// 	*p = XPacket{
	// 		arrival:  0,
	// 		pkt:      rtp.Packet{},
	// 		typ:      0,
	// 		keyframe: false,
	// 	}
	// }

	for i := 0; i < b.N; i++ {

		p = &XPacket{
			arrival:  0,
			pkt:      rtp.Packet{},
			typ:      Video,
			keyframe: false,
		}

		p.keyframe = i%200 == 0

		a.Publish(p)

	}
	b.StopTimer()
	a.Unsubscribe(ch)

	time.Sleep(time.Millisecond * 5) // wait for drain

	durintf := GetUnexportedField(reflect.ValueOf(b).Elem().FieldByName("duration"))
	duration := durintf.(time.Duration)

	b.ReportMetric(float64(duration)/float64(b.N)/float64(numwrites), "ns/write")

	//data race
	// nn:=0
	// for k:=range trks.live{
	// 	z:=k.vid.track.(*Z)
	// 	nn+=z.nwrite
	// }
	// log.Println("num writes", nn)
}

func GetUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}
