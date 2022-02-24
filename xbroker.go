package main

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
	BrokerInputChannelDepth  = 50
	BrokerOutputChannelDepth = 50
)

type XBroker struct {
	msgCh chan xany
}

type xany interface{} // go 1.18 is here soon

type XBrokerMsgSub chan xany
type XBrokerMsgUnSub chan xany

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


	for mm := range b.msgCh {

		switch m := mm.(type) {
		case XBrokerMsgSub:

			if _, ok := subs[m]; ok {
				panic("cant add twice")
			}

			subs[m] = struct{}{}

			m <- buf // new subscribers get a copy of the gop so far

		case XBrokerMsgUnSub:

			if _, ok := subs[m]; !ok {
				panic("not found!")
			}

			close(m)
			delete(subs, m)

		case *XPacket:
			if m.typ != Video && m.typ != Audio {
				panic("invalid xpkt type")
			}

			// TESTING, vid only
			// if m.typ != Video { // save video GOPs
			// 	break
			// }

			// STEP1: we save video XPacket's in the gop-so-far
			if m.typ == Video { // save video GOPs
				if len(buf) > 50000 { //oversize protection // XXX >cap(buf)
					buf = make([]*XPacket, 0)
				}
				if m.keyframe {
					buf = make([]*XPacket, 1, 300) // XXX pool? or clear slice
					buf[0] = m
				} else if len(buf) > 0 {
					buf = append(buf, m)
				}

				// this sanity check moved to the receiving side
				// if len(buf) > 0 && !buf[0].keyframe {
				// 	panic("replay must begin with KF, or be empty")
				// }
			}

			// STEP2, WAS: on-keyframe,
			// for-each chan-subscr, add the pair to the TxTracks map, close the chan, delete from chan-map
			// using two for-loops for compiler reasons: https://go.dev/doc/go1.11#performance-compiler

			//STEP3 send pkt to each chan
			// for ch := range subs {
			// 	select {
			// 	case ch <- m:
			// 	default:
			// 		panic("no")
			// 	}
			// }

			for ch := range subs {
				ch <- m

				if false {
					// l := len(ch)
					// freqtable[l] += 1
					//pl(unsafe.Pointer(b), l, freqtable[l])

					select {
					case ch <- m:
					default:
						// for i := 0; i <= cap(ch); i++ {
						// 	println("hist ", i, freqtable[i])
						// }
						// log.Println(len(ch), cap(ch))
						panic("blocking send cap hit")
					}
				}
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
