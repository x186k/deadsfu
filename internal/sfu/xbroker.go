package sfu

import (
	"sync"
)

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

/*
The XBroker does these things:
- does broadcast fan-out of rtp packets to Go channels
- does broadcast fan-out of rtp packets to Pion Tracks
- records GOPs from keyframe, and shares the PGOP or GOP-so-far with Subscribers
*/

const (
	XBrokerInputChannelDepth  = 1000 // no benefit to being small
	XBrokerOutputChannelDepth = 1000 // same
)

type XBroker struct {
	mu      sync.Mutex
	subs    map[chan *XPacket]struct{}
	inCh    chan *XPacket
	gop     []*XPacket
	inLost  int
	outLost int
}

func NewXBroker() *XBroker {
	return &XBroker{
		inCh: make(chan *XPacket, XBrokerInputChannelDepth),
		subs: make(map[chan *XPacket]struct{}),
		gop:  make([]*XPacket, 0, 2000),
	}
}

func (b *XBroker) Start() {

	for m := range b.inCh {

		if m.Typ != Video && m.Typ != Audio {
			panic("invalid xpkt type")
		}

		// fast block
		b.mu.Lock()
		if m.Typ == Video { // save video GOPs
			tooLarge := len(b.gop) > 50000
			if m.Keyframe || tooLarge {
				for i := range b.gop {
					b.gop[i] = nil
				}
				b.gop = b.gop[0:0]
			}
			b.gop = append(b.gop, m)
		}

		// non-blocking send loop
		for ch := range b.subs {
			select {
			case ch <- m:
			default:
				b.outLost++
			}
		}
		b.mu.Unlock()

	}
}

func (b *XBroker) Stop() {
	close(b.inCh)
}

func (b *XBroker) Subscribe() (chan *XPacket, []*XPacket) {

	c := make(chan *XPacket, XBrokerOutputChannelDepth)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.subs[c] = struct{}{}
	tmp := make([]*XPacket, len(b.gop))
	copy(tmp, b.gop)

	return c, tmp
}

func (b *XBroker) Unsubscribe(c chan *XPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.subs, c)
}

//non blocking
func (b *XBroker) Publish(msg *XPacket) {

	select {
	case b.inCh <- msg:
	default:
		b.inLost++
	}

}
