package sfu

import (
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// var _ = XPool{
// 	Pool: sync.Pool{
// 		New: func() interface{} {
// 			//a := new(main.XPacket)
// 			//a.buf = make([]byte, 1460)
// 			panic("uncomment surrounding lines")
// 			//return a
// 		},
// 	},
// }

type CheckedPoolOutInfo struct {
	t     time.Time
	stack []byte
}

type CheckedPool struct {
	mu sync.Mutex
	New func() interface{}
	pool map[interface{}]struct{}
	out  map[interface{}]CheckedPoolOutInfo
}

func NewCheckedPool(newfunc func() interface{}) *CheckedPool {
	a := &CheckedPool{
		pool: make(map[interface{}]struct{}),
		out:  make(map[interface{}]CheckedPoolOutInfo),
		New:  newfunc,
	}
	go a.Monitor()
	return a
}

func (p *CheckedPool) Put(x interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.out[x]; !ok {
		log.Fatal("not checkedout obj")
	}
	if _, ok := p.pool[x]; ok {
		log.Fatal("already checked in obj")
	}

	p.pool[x] = struct{}{}
	delete(p.out, x)
}

func (p *CheckedPool) Get() interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	outinfo := CheckedPoolOutInfo{t: time.Now(), stack: debug.Stack()}

	if len(p.pool) == 0 {
		x := p.New()
		p.out[x] = outinfo
		return x
	}

	for x := range p.pool {
		delete(p.pool, x)

		if _, ok := p.out[x]; ok {
			log.Fatal("internal err")
		}
		p.out[x] = outinfo
		return x
	}

	panic("never")
}

func (p *CheckedPool) Monitor() {
	for {
		time.Sleep(time.Second)
		p.mu.Lock()
		for _, v := range p.out {
			if time.Since(v.t) > time.Second*10 {
				log.Fatalln("object out of pool too long. stack:", string(v.stack))
			}
		}
		p.mu.Unlock()
	}
}