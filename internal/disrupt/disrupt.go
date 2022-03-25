package disrupt

import (
	"log"
	"sync"
	"sync/atomic"
)

type nolock struct{}

func (*nolock) Lock()   {}
func (*nolock) Unlock() {}

// SPMC
type Disrupt[T any] struct {
	cond   sync.Cond
	buf    []T
	next   int64
	len64  int64
	mask64 int64
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

func (d *Disrupt[T]) Put(v T) {

	i := atomic.LoadInt64(&d.next)
	//	ix := i % d.len64
	ix := i & d.mask64
	d.buf[ix] = v
	i++
	atomic.StoreInt64(&d.next, i)

	d.cond.Broadcast()
	//d.cond.Signal()   //must uncomment signal below when using this

}

func (d *Disrupt[T]) Get(k int64) (T, int64, bool) {

	var zeroval T

	//ix := k % d.len64

	ix := k & d.mask64

	// if k >= i {
	// 	log.Fatal("invalid index too high")
	// }

	for k >= atomic.LoadInt64(&d.next) {
		d.cond.Wait()
		//d.cond.Signal() // wake any other waiters, when not using broadcast in Put
	}

	val := d.buf[ix]

	i := atomic.LoadInt64(&d.next)
	if k <= (i - d.len64) { // XXX should I be more conservative? len64-1/2 ?
		return zeroval, i, false // XXX can be improved, discard only 1/2 ?
	}

	k++

	return val, k, true

}
