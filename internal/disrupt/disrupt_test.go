package disrupt

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var A, B int64

var X, Y uint64

func BenchmarkLoadInt64(b *testing.B) {
	b.RunParallel(func(p *testing.PB) {
		k := int64(0)
		for p.Next() {
			k += atomic.LoadInt64(&A)
		}
		atomic.StoreInt64(&B, k)
	})
}

func BenchmarkLoadUInt64(b *testing.B) {
	b.RunParallel(func(p *testing.PB) {
		k := uint64(0)
		for p.Next() {
			k += atomic.LoadUint64(&X)
		}
		atomic.StoreUint64(&Y, k)
	})
}

func BenchmarkDisrupt(b *testing.B) {

	w := sync.WaitGroup{}

	w.Add(1)

	a := NewDisrupt[int64](4096 * 8 * 8)

	go func() {

		time.Sleep(100)

		for i := int64(0); i < int64(b.N); i++ {
			a.Put(i)
		}

		w.Done()

	}()

	b.ResetTimer()

	for i := int64(0); i < int64(b.N); i++ {
		v, k, ok := a.Get(i)
		if int64(v) != i || k != i+1 || !ok {
			b.Fatal("bad vals", i, v, k, ok)
		}
	}

	b.StopTimer()

	w.Wait()

}

var C, D [1500]byte

func Benchmark1500Copy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		C = D

	}
}

func XBenchmarkDisrupt1500(b *testing.B) {

	w := sync.WaitGroup{}

	w.Add(1)

	a := NewDisrupt[[1500]byte](4096 * 8 * 8 * 8)

	go func() {

		time.Sleep(100)

		var z [1500]byte

		for i := int64(0); i < int64(b.N); i++ {
			a.Put(z)
		}

		w.Done()

	}()

	b.ResetTimer()

	for i := int64(0); i < int64(b.N); i++ {
		v, k, ok := a.Get(i)
		_ = v
		if k != i+1 || !ok {
			b.Fatal("bad vals", i, k, ok)
		}
	}

	b.StopTimer()

	w.Wait()

}

func TestDisrupt(t *testing.T) {

	w := sync.WaitGroup{}

	w.Add(1)

	N := int(1e7)

	a := NewDisrupt[int64](2048)

	go func() {

		time.Sleep(time.Microsecond)

		for i := int64(0); i < int64(N); i++ {
			time.Sleep(1)
			a.Put(i)
		}

		w.Done()

	}()

	for i := int64(0); i < int64(N); i++ {
		v, k, ok := a.Get(i)
		if int64(v) != i || k != i+1 || !ok {
			// assert.FailNow(t, i, v)
			// assert.Equal(t, i+1,k)
			// assert.Equal(t, true, ok)

			t.Fatalf("bad vals v/%v expect/%v, k/%v exp/%v,  ok/%v", v, i, k, i+1, ok)
		}
	}

	w.Wait()

}

func TestPutGet1(t *testing.T) {

	w := sync.WaitGroup{}

	w.Add(1)
	a := NewDisrupt[int](100)

	go func() {

		t0 := time.Now()

		v, i, ok := a.Get(0)

		assert.Equal(t, 99, v)
		assert.Equal(t, int64(1), i)
		assert.Equal(t, true, ok)
		dur := time.Since(t0)
		assert.GreaterOrEqual(t, dur, time.Millisecond, ok)

		w.Done()

	}()

	time.Sleep(time.Millisecond)
	a.Put(99)

	w.Wait()

}
