package test

import (
	"sync"
	"testing"

	"github.com/x186k/deadsfu/internal/sfu"
)

func BenchmarkAllocStack(b *testing.B) {
	for N := 0; N < b.N; N++ {
		// a := sfu.XPacket{}
		// a.Buf = make([]byte, 1460)
		a := foo()

		_ = a
	}
}

var obj sfu.XPacket

func foo() sfu.XPacket {
	a := sfu.XPacket{}
	a.Buf = make([]byte, 1460)
	return a
}

func BenchmarkAllocHeap(b *testing.B) {
	for N := 0; N < b.N; N++ {
		obj = foo()
		_ = obj
	}
}

var bytePool = sync.Pool{
	New: func() interface{} {
		a := foo()

		return &a
	},
}

func BenchmarkAllocPool(b *testing.B) {
	for N := 0; N < b.N; N++ {
		obj := bytePool.Get().(*sfu.XPacket)
		_ = obj
		bytePool.Put(obj)
	}
}

var Pub int64

func BenchmarkAllocQuasiPool10(b *testing.B) {
	const nn = 10

	a := make([]*sfu.XPacket, b.N)

	var x [nn][1540]byte
	var y [nn]sfu.XPacket

	b.ResetTimer()
	for N := 0; N < b.N; N++ {

		if N%nn == 0 {
			x = [nn][1540]byte{}
			y = [nn]sfu.XPacket{}
		}

		obj := y[N%nn]
		a[N] = &obj
		obj.Buf = x[N%nn][:]
		_ = obj
		Pub += int64(obj.Buf[0])
	}
}
func BenchmarkAllocQuasiPool1000(b *testing.B) {
	const nn = 1000

	a := make([]*sfu.XPacket, b.N)

	var x [nn][1540]byte
	var y [nn]sfu.XPacket

	b.ResetTimer()
	for N := 0; N < b.N; N++ {

		if N%nn == 0 {
			x = [nn][1540]byte{}
			y = [nn]sfu.XPacket{}
		}

		obj := y[N%nn]
		a[N] = &obj
		obj.Buf = x[N%nn][:]
		_ = obj
		Pub += int64(obj.Buf[0])
	}
}

func BenchmarkAllocQuasiPool10000(b *testing.B) {
	const nn = 10000

	a := make([]*sfu.XPacket, b.N)

	var x [nn][1540]byte
	var y [nn]sfu.XPacket

	b.ResetTimer()
	for N := 0; N < b.N; N++ {

		if N%nn == 0 {
			x = [nn][1540]byte{}
			y = [nn]sfu.XPacket{}
		}

		obj := y[N%nn]
		a[N] = &obj
		obj.Buf = x[N%nn][:]
		_ = obj
		Pub += int64(obj.Buf[0])
	}
}
