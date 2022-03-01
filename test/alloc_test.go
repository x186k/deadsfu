package test

import (
	"sync"
	"testing"
	"github.com/x186k/deadsfu/internal/sfu"
	
)

func BenchmarkAllocStack(b *testing.B) {
	for N := 0; N < b.N; N++ {
		a := sfu.XPacket{}
		a.buf = make([]byte, 1460)

		_ = a
	}
}

var obj sfu.XPacket

func foo() sfu.XPacket {
	a := sfu.XPacket{}
	a.buf = make([]byte, 1460)
	return a
}

func BenchmarkAllocHeap(b *testing.B) {
	for N := 0; N < b.N; N++ {
		obj = sfu.XPacket{}
		obj.buf = make([]byte, 1460)
		_ = obj
	}
}

var bytePool = sync.Pool{
	New: func() interface{} {
		a := sfu.XPacket{}
		a.buf = make([]byte, 1460)
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
