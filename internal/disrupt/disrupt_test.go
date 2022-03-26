package disrupt

import (
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	a := NewDisrupt[int64](int(math.Pow(2, 24)))

	go func() {

		runtime.LockOSThread()
		time.Sleep(time.Millisecond)

		for i := int64(0); i < int64(b.N); i++ {
			a.Put(i)
		}
		a.Close()

		w.Done()

	}()

	b.ResetTimer()

	runtime.LockOSThread()
	for ix := int64(0); ix < int64(b.N); ix++ {
		val, nextix, ok := a.Get(ix)
		if int64(val) != ix || nextix != ix+1 || !ok {
			b.Fatalf("bad vals  ix:%v val:%v nextix:%v ok:%v", ix, val, nextix, ok)
		}
	}

	b.StopTimer()

	var zero int64
	v, ix, isopen := a.Get(int64(b.N))
	require.Equal(b, zero, v)
	require.Equal(b, int64(b.N), ix)
	require.Equal(b, false, isopen)

	w.Wait()

}

var C, D [1500]byte

func Benchmark1500Copy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		C = D

	}
}

func TestDisrupt(t *testing.T) {

	w := sync.WaitGroup{}

	w.Add(1)

	N := int(1e7)

	a := NewDisrupt[int64](int(math.Pow(2, 12)))

	go func() {

		time.Sleep(time.Microsecond)

		for i := int64(0); i < int64(N); i++ {
			a.Put(i)
			runtime.Gosched()
		}

		a.Close()

		w.Done()

	}()

	for i := int64(0); i < int64(N); i++ {
		v, k, isopen := a.Get(i)
		if int64(v) != i || k != i+1 || !isopen {
			require.Equal(t, i, v)
			require.Equal(t, i+1, k)
			require.Equal(t, true, isopen)
		}
	}

	v, k, isopen := a.Get(int64(N))

	var zero int64

	require.Equal(t, zero, v)
	require.Equal(t, int64(N), k)
	require.Equal(t, false, isopen)

	w.Wait()

}

func TestPutGet1(t *testing.T) {

	w := sync.WaitGroup{}

	w.Add(1)
	a := NewDisrupt[int](256)

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
