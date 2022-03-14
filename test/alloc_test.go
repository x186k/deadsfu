package test

import (
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/pion/rtp"
	//"github.com/x186k/deadsfu/internal/sfu"
)

type XPacket1500 struct {
	Arrival  int64
	Pkt      rtp.Packet
	Typ      int32
	Keyframe bool
	Buf      [1500]byte
}
type XPacket9000 struct {
	Arrival  int64
	Pkt      rtp.Packet
	Typ      int32
	Keyframe bool
	Buf      [9000]byte
}

func BenchmarkAllocStack1500(b *testing.B) {
	for N := 0; N < b.N; N++ {
		// a := XXPacket{}
		// a.Buf = make([]byte, 1460)
		a := XPacket1500{}

		_ = a
	}
}

var Obj1500 XPacket1500
var Obj9000 XPacket9000

func BenchmarkAllocHeap1500(b *testing.B) {
	for N := 0; N < b.N; N++ {
		Obj1500 = XPacket1500{}
		_ = Obj1500
	}
}

func BenchmarkAllocHeap1500Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Obj1500 = XPacket1500{}
			_ = Obj1500
		}
	})
	b.StopTimer() // required to get duration
	reportCPUUtil(b, 1500)
}

func BenchmarkAllocHeap9000(b *testing.B) {
	for N := 0; N < b.N; N++ {
		Obj9000 = XPacket9000{}
		_ = Obj9000
	}
}

func BenchmarkAllocHeap9000Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Obj9000 = XPacket9000{}
			_ = Obj9000
		}
	})
	b.StopTimer() // required to get duration

	reportCPUUtil(b, 9000)
}

//for example
// units -v '100megabit/sec * 1/1500bytes * 70ns'
// units -v '100megabit/sec * 1byte/8bits * 1sec/1e9ns *   1/1500bytes * 70ns'
// units -v '100megabit/sec * 1/1500bytes * 70ns'
//     Definition: 0.00058333333
func reportCPUUtil(b *testing.B, mtu float64) {
	duration := GetDuration(b)
	nsPerOp := float64(duration) / float64(b.N)
	b.ReportMetric(nsPerOp, "ns/op2")

	averagePacketLen := mtu / 2

	cpuutil := 100e6 / 8 / 1e9 / averagePacketLen * nsPerOp
	b.ReportMetric(cpuutil, "100mbps-cpuFraction")
	b.ReportMetric(cpuutil*100, "100mbps-cpuPercent")
}

var bytePool1500 = sync.Pool{
	New: func() interface{} {
		return new(XPacket1500)
	},
}
var bytePool9000 = sync.Pool{
	New: func() interface{} {
		return new(XPacket9000)
	},
}

var Pub int

func BenchmarkAllocPool1500(b *testing.B) {
	for N := 0; N < b.N; N++ {
		obj := bytePool1500.Get().(*XPacket1500)
		_ = obj
		Pub += int(obj.Arrival)
		bytePool1500.Put(obj)
	}
}
func BenchmarkAllocPool9000(b *testing.B) {
	for N := 0; N < b.N; N++ {
		obj := bytePool9000.Get().(*XPacket9000)
		_ = obj
		Pub += int(obj.Arrival)
		bytePool9000.Put(obj)
	}
}
func BenchmarkAllocPoolParallel9000(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			obj := bytePool9000.Get().(*XPacket9000)
			_ = obj
			Pub += int(obj.Arrival)
			bytePool9000.Put(obj)
		}
	})

}

func BenchmarkXX(b *testing.B) {

	for i := 0; i < b.N; i++ {
		time.Sleep(time.Microsecond)
	}
}

func GetDuration(b *testing.B) time.Duration {

	durintf := GetUnexportedField(reflect.ValueOf(b).Elem().FieldByName("duration"))
	duration := durintf.(time.Duration)
	return duration
}

func GetUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}
