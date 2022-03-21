package sfu

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
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
	mu        sync.Mutex
	subs      map[chan *XPacket]struct{}
	inCh      chan *XPacket
	gop       []*XPacket
	droppedRx int32 // concurrent/atomic increments
	droppedTx int   // non-current increments
	// capacityMaxRx int
	// capacityMaxTx int
}

var TimerXPacket XPacket

func NewXBroker() *XBroker {
	return &XBroker{
		mu:        sync.Mutex{},
		subs:      make(map[chan *XPacket]struct{}),
		inCh:      make(chan *XPacket, XBrokerInputChannelDepth),
		gop:       make([]*XPacket, 0, 2000),
		droppedRx: 0,
		droppedTx: 0,
	}
}

func (b *XBroker) Start() {

	gotKF := false

	var lastVideo int64 = nanotime()
	var sendingIdleVid bool = true

	for m := range b.inCh {
		//b.capacityMaxRx = MaxInt(b.capacityMaxRx, cap(b.inCh)+1)

		switch m.Typ {
		case Audio:
		case Video:

			lastVideo = m.Arrival // faster than nanotime()

			if sendingIdleVid && m.Keyframe {
				sendingIdleVid = false
				//log.Println("SWITCHING TO INPUT, NOW INPUT VIDEO PRESENT")
			}

			if sendingIdleVid {
				continue
			}
		case IdleVideo:

			rxActive := m.Arrival-lastVideo <= int64(time.Second) // use arrival, not nanotime(), its cheaper

			if !rxActive && !sendingIdleVid && m.Keyframe {
				sendingIdleVid = true
				//log.Println("SWITCHING TO IDLE, NO INPUT VIDEO PRESENT")
			}

			if !sendingIdleVid {
				continue
			}

			m.Typ = Video //racy??

		default:
			log.Fatal("invalid xpkt type")
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
				gotKF = true
			}
		}
		if gotKF {
			b.gop = append(b.gop, m) // save audio and video for replay
		}

		// non-blocking send loop
		for ch := range b.subs {
			select {
			case ch <- m:
				//b.capacityMaxTx = MaxInt(b.capacityMaxTx, cap(ch))
			default:
				b.droppedTx++
				errlog.Println("xbroker TX drop count", b.droppedTx)
			}
		}
		b.mu.Unlock()
	}

	// NO NO NO!
	// we require/expect all subscribers
	// to terminate independantly from the close of the broker input chan
	//
	// so, we don't close the subscriber's input channels.
	// if we did this, we will try to close channels twice sometimes.
	//
	// Close all subscriber channeles
	// b.mu.Lock()
	// for k := range b.subs {
	// 	close(k) // close Writer() func
	// }
	// b.mu.Unlock()
}

func (b *XBroker) Stop() {
	//panic("this is done by idle generator")
	//racy
	close(b.inCh)
}

func (b *XBroker) Subscribe() chan *XPacket {

	c := make(chan *XPacket, XBrokerOutputChannelDepth)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.subs[c] = struct{}{}

	return c
}

func (b *XBroker) SubscribeReplay() chan *XPacket {

	c := make(chan *XPacket, len(b.gop)+XBrokerOutputChannelDepth)
	for _, v := range b.gop {
		c <- v // pre load gop into channel
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.subs[c] = struct{}{}

	return c
}

// Unsubscribe
// you may unsubscribe multiple times on the same channel
// this functionality is needed for the Replay() func logic
func (b *XBroker) Unsubscribe(c chan *XPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subs[c]; ok {
		delete(b.subs, c)
		close(c)
	}
}

// non blocking
// concurrent use
func (b *XBroker) Publish(msg *XPacket) {

	select {
	case b.inCh <- msg:
	default:
		atomic.AddInt32(&b.droppedRx, 1)
		errlog.Println("xbroker RX drop count", b.droppedRx)
	}

}

func MaxInt(x, y int) int {
	if x < y {
		return y
	}
	return x
}
