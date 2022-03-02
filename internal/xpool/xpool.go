package xpool

import (
	"log"
	"sync"
	"time"
	//"github.com/x186k/deadsfu"
)

var _ = XPool{
	Pool: sync.Pool{
		New: func() interface{} {
			//a := new(main.XPacket)
			//a.buf = make([]byte, 1460)
			panic("uncomment surrounding lines")
			//return a
		},
	},
	free:  make(map[interface{}]struct{}),
	inuse: make(map[interface{}]time.Time),
}

type XPool struct {
	mu sync.Mutex

	sync.Pool

	free  map[interface{}]struct{}
	inuse map[interface{}]time.Time
	last  time.Time
}

func (p *XPool) Put(x interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.free[x]; ok {
		panic("put existing")
	}
	p.free[x] = struct{}{}
	delete(p.inuse, x)

	p.Pool.Put(x)
}
func (p *XPool) Get() interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	x := p.Pool.Get()

	delete(p.free, x)
	p.inuse[x] = time.Now()

	if time.Since(p.last) > 3*time.Second {
		p.last = time.Now()
		n := 0
		for _, v := range p.inuse {
			if time.Since(v) > time.Second*10 {
				n++
			}
		}
		log.Printf("%d inuse >10 sec, %d inuse, %d free", n, len(p.inuse), len(p.free))
	}

	return x

}
