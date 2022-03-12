package sfu

import (
	"sync"
	"sync/atomic"
)

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

/*
The XBroker does these things:
- does broadcast fan-out of rtp packets to Go channels
- does broadcast fan-out of rtp packets to Pion Tracks
- records GOPs from keyframe, and shares the PGOP or GOP-so-far with Subscribers
*/

const (
	BrokerOutputChannelDepth = 1
)

var xpool = NewCheckedPool(func() interface{} {
	a := new(XPacket)
	//a.buf = make([]byte, 1460)
	return a
})

type GopCapture struct {
	// first is immutable, after creation
	// recount is an immutable pointer
	// last is mutable while the struct is owned by xbroker
	// last is only updated by a single reader/writer (xbroker)
	// last is immutable after the struct is shared/returned by Subscribe
	refcount *int32
	first    *XPacket // immutable
	last     *XPacket
}

// only called by xbroker, non-concurrent
func (g *GopCapture) AddPacket(x *XPacket) {
	x.Next = nil // potentially redundant, say if we reset/clear object on Get() from pool
	g.last.Next = x
	g.last = x
}

func (g *GopCapture) IncRef() {
	atomic.AddInt32(g.refcount, 1)
}

func (g *GopCapture) DecRef() {
	n := atomic.AddInt32(g.refcount, -1)
	if n == 0 {
		// there should be no one else referenceing this GopCapture
		// that means it is safe to Put the XPackets back to pool

		a := g.first
		for a != nil {
			next := a.Next
			xpool.Put(a)
			a = next
		}
	}
}

type XBroker struct {
	mu   sync.Mutex
	subs map[RingBuff]struct{} // equiv to map[interface{}] okay!!
	gop  *GopCapture
	tmp  []RingBuff // equiv to []interface{}, okay!!
}

func NewXBroker() *XBroker {
	return &XBroker{
		mu:   sync.Mutex{},
		subs: make(map[RingBuff]struct{}),
		gop:  &GopCapture{},
		tmp:  make([]RingBuff, 0, 100),
	}
}

// Someday consider changing to lock-free
// mutex is find for now
func (b *XBroker) Publish(x *XPacket) {

	if x.Typ != Video && x.Typ != Audio {
		panic("invalid xpkt type")
	}

	b.mu.Lock()

	// work on GOP capture
	if x.Typ == Video && x.Keyframe {
		// new gop

		if b.gop != nil {
			b.gop.DecRef() // this may call pool.Put() many times XXX, okay maybe
		}

		b.gop = &GopCapture{
			first:    x,
			last:     x,
			refcount: new(int32),
		}

		b.gop.IncRef()

	}
	if b.gop != nil {
		b.gop.last.Next = x
		b.gop.last = x
	}

	// I am somewhat undecided if this should be done
	// maybe the non-blocking sends are fine inside the mutex.
	// if we eliminate the mutex, and go lock-free for subscribers list, then it wouldn't be a question, either
	for k := range b.subs {
		b.tmp = append(b.tmp, k)
	}
	b.mu.Unlock()

	for i, ch := range b.tmp {
		_ = ch.WriteSingleNBlk(x) //non-block
		b.tmp[i] = nil
	}
}

func (b *XBroker) Subscribe() (rb RingBuff, gop GopCapture) {

	c := NewRBChan(BrokerOutputChannelDepth, 0)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.subs[c] = struct{}{}

	b.gop.IncRef()

	gopcopy := *b.gop

	gopcopy.IncRef() // caller must call decref

	return c, gopcopy
}

func (b *XBroker) Unsubscribe(rb RingBuff) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.subs, rb)
}
