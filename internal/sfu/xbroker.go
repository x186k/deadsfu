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
	mu   sync.Mutex
	subs map[chan *XPacket]struct{}
	inCh chan *XPacket
	buf  []*XPacket
}

func NewXBroker() *XBroker {
	return &XBroker{
		inCh: make(chan *XPacket, XBrokerInputChannelDepth),
		subs: make(map[chan *XPacket]struct{}),
		buf:  make([]*XPacket, 0, 2000),
	}
}

func (b *XBroker) Start() {

	tmp := make([]chan *XPacket, 0)

	for m := range b.inCh {

		if m.Typ != Video && m.Typ != Audio {
			panic("invalid xpkt type")
		}

		// fast block
		b.mu.Lock()
		if m.Typ == Video { // save video GOPs
			tooLarge := len(b.buf) > 50000
			if m.Keyframe || tooLarge {
				for i := range b.buf {
					b.buf[i] = nil
				}
				b.buf = b.buf[0:0]
			}
			b.buf = append(b.buf, m)
		}
		tmp = tmp[0:0]
		for k := range b.subs {
			tmp = append(tmp, k)
		}
		b.mu.Unlock()

		// blocking possible
		for i, ch := range tmp {
			ch <- m // blocking possible
			tmp[i] = nil
		}
		//pl(2)
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
	tmp := make([]*XPacket, len(b.buf))
	copy(tmp, b.buf)

	return c, tmp
}

func (b *XBroker) Unsubscribe(c chan *XPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.subs, c)
}

func (b *XBroker) Publish(msg *XPacket) {
	pl()
	b.inCh <- msg
	pl()
}
