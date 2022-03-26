package disrupt

import (
	"log"
	"sync"
	"sync/atomic"
	"unsafe"
)

type nolock struct{}

func (*nolock) Lock()   {}
func (*nolock) Unlock() {}

const CacheLine = 64

// SPMC
type Disrupt[T any] struct {
	next   int64
	_2     [CacheLine]byte
	len64  int64
	_3     [CacheLine]byte
	mask64 int64
	_4     [CacheLine]byte
	cond   sync.Cond
	_5     [CacheLine]byte
	buf    []T
	_1     [CacheLine]byte
}

func NewDisrupt[T any](n int) *Disrupt[T] {

	if n == 0 || (n&(n-1)) != 0 {
		log.Fatal("require positive power of two")
	}

	buf := make([]T, n)

	return &Disrupt[T]{
		cond:   sync.Cond{L: &nolock{}},
		buf:    buf,
		len64:  int64(n),
		mask64: int64(n - 1),
	}
}

func (d *Disrupt[T]) Close() {

	i := atomic.LoadInt64(&d.next)
	atomic.StoreInt64(&d.next, -i)

	d.cond.Broadcast()
	//d.cond.Signal()   //must uncomment signal below when using this
}

func (d *Disrupt[T]) Put(v T) {

	i := atomic.LoadInt64(&d.next)
	//	ix := i % d.len64
	ix := i & d.mask64

	if i < 0 {
		log.Fatal("closed")
	}

	if RaceEnabled {
		RaceAcquire(unsafe.Pointer(d))
		//RaceDisable()
	}

	d.buf[ix] = v

	if RaceEnabled {
		//RaceEnable()
		RaceRelease(unsafe.Pointer(d))
	}

	i++
	atomic.StoreInt64(&d.next, i)

	d.cond.Broadcast()
	//d.cond.Signal()   //must uncomment signal below when using this

}

func (d *Disrupt[T]) Get(k int64) (value T, next int64, more bool) {

	//ix := k % d.len64

again:

	ix := k & d.mask64

	// if k >= i {
	// 	log.Fatal("invalid index too high")
	// }

	for j := atomic.LoadInt64(&d.next); k >= j; j = atomic.LoadInt64(&d.next) {
		if j < 0 { //closed?
			if k >= -j { // no values left
				var zeroval T
				return zeroval, k, false
			}
			break
		} else {
			d.cond.Wait()
			//d.cond.Signal() // wake any other waiters, when not using broadcast in Put
		}
	}

	if RaceEnabled {
		RaceAcquire(unsafe.Pointer(d))
		//RaceDisable()
	}

	val := d.buf[ix]

	if RaceEnabled {
		//RaceEnable()
		RaceRelease(unsafe.Pointer(d))
	}

	// did we grab stale data?

	j := atomic.LoadInt64(&d.next)

	if j < 0 { // if closed, fix sign
		j = -j
	}
	if k <= (j - d.len64) { // we read possibly overwritten data

		k++ //discard bad data
		goto again

		// val = zeroval
		// k = j - 1
	}

	k++

	return val, k, true

}
