package sfu

import (
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
	BrokerInputChannelDepth  = 2
	BrokerOutputChannelDepth = 2
)

type XBroker struct {
	msgCh chan xany
}

type xany interface{} // go 1.18 is here soon

type XBrokerMsgSub chan xany
type XBrokerMsgUnSub chan xany
type XBrokerMsgTick struct{}

func NewXBroker() *XBroker {
	return &XBroker{
		msgCh: make(chan xany, BrokerInputChannelDepth), // must be unbuf/sync!

	}
}

func (b *XBroker) Start() {

	var buf []*XPacket = make([]*XPacket, 0)

	// this map is how we add/remove subscribers to the broker
	// the subscribers are identified by a *TxTrackGroup
	// that's how they are identified when being adding, or being deleting
	subs := make(map[chan xany]struct{})

	// freqtable := make(map[int]int)
	// for i := 0; i <= 5; i++ {
	// 	freqtable[i] = 0
	// }

	/// XXX must handle shutdown
	go func() {
		for {
			b.msgCh <- XBrokerMsgTick{}
			time.Sleep(time.Millisecond * 100)
		}
	}()

	var idleDone chan struct{} // buffered NOTOK
	var lastRx int64 = nanotime()
	var isIdle bool

	for mm := range b.msgCh {

		switch m := mm.(type) {
		case XBrokerMsgTick:
			//pl("tick")
			if !isIdle && (nanotime()-lastRx > int64(time.Second)) {
				isIdle = true
				//pl("->isIdle", isIdle)

				idleDone = make(chan struct{})
				go noSignalGeneratorGr(idleDone, idleMediaPackets, b.msgCh)
			}
		case XBrokerMsgSub:

			if _, ok := subs[m]; ok {
				panic("cant add twice")
			}

			subs[m] = struct{}{}

			pktcopy := make([]*XPacket, len(buf))
			copy(pktcopy, buf)

			m <- pktcopy // new subscribers get a copy of the gop so far

		case XBrokerMsgUnSub:

			if _, ok := subs[m]; !ok {
				panic("not found!")
			}

			close(m)
			delete(subs, m)

		case *XPacket:

			if m.Typ != Video && m.Typ != Audio && m.Typ != IdleVideo {
				panic("invalid xpkt type")
			}

			if m.Typ == Video {
				lastRx = nanotime()
				if isIdle {
					isIdle = false
					//pl("->isIdle", isIdle)
					close(idleDone)
				}
			}

			// STEP1: we save video XPacket's in the gop-so-far
			tooLarge := len(buf) > 50000
			if m.Typ == Video || m.Typ == IdleVideo { // save video GOPs

				if m.Keyframe || tooLarge {
					for i := range buf {
						buf[i] = nil
						//xpacketPool.Put(v)
					}
					buf = buf[0:0]
					// old buf = make([]*XPacket, 1, 300) // XXX pool? or clear slice
				}
				buf = append(buf, m)

				// this sanity check moved to the receiving side
				// if len(buf) > 0 && !buf[0].keyframe {
				// 	panic("replay must begin with KF, or be empty")
				// }
			}

			// STEP2, WAS: on-keyframe,
			// for-each chan-subscr, add the pair to the TxTracks map, close the chan, delete from chan-map
			// using two for-loops for compiler reasons: https://go.dev/doc/go1.11#performance-compiler

			//once := true
			for ch := range subs {
				// if once {
				// 	once = false
				// } else {
				// 	tmp := xpacketPool.Get().(*XPacket)
				// 	copy := *m
				// 	*tmp = copy
				// 	m = tmp
				// }

				ch <- m

			}
		}
	}
}

func (b *XBroker) Stop() {
	close(b.msgCh)
}

func (b *XBroker) Subscribe() chan xany {
	c := make(chan xany, BrokerOutputChannelDepth)
	b.msgCh <- XBrokerMsgSub(c)
	return c
}

func (b *XBroker) Unsubscribe(c chan xany) {
	b.msgCh <- XBrokerMsgUnSub(c)
}

func (b *XBroker) Publish(msg *XPacket) {
	b.msgCh <- msg
}