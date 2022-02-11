package main

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

/*
The XBroker does these things:
- does broadcast fan-out of rtp packets to Go channels
- does broadcast fan-out of rtp packets to Pion Tracks
- records GOPs from keyframe, and shares the PGOP or GOP-so-far with Subscribers
*/

type XBroker struct {
	msgCh chan xany
}

type xany interface{} // go 1.18 is here soon

type XBrokerMsgSub *TxTrackSet
type XBrokerMsgUnSub *TxTrackSet

func NewXBroker() *XBroker {
	return &XBroker{
		msgCh: make(chan xany), // must be unbuf/sync!
	}
}

func (b *XBroker) Start() {

	var buf []XPacket = make([]XPacket, 0)

	// tracks are kept here before keyframe while forwarding to a chan
	// this channel must be sync.
	// we need to be sure when a 'close/done' message is sent here,
	// nothing else will be written by the chan receiver/GR 
	subs := make(map[*TxTrackSet]chan XPacket)

	// tracks are moved here after keyframe for direct writing by myself
	txtr := make(map[*TxTrackSet]struct{})

	for mm := range b.msgCh {

		switch m := mm.(type) {
		case XBrokerMsgSub:
			_, ok := subs[m]
			if ok {
				panic("can't add pre existing")
			}
			ch := make(chan XPacket) //must be unbuf!
			subs[m] = ch

			go gopReplay(ch, m, buf) //ending this must be sync!, all writes must be complete!

		case XBrokerMsgUnSub:
			_, ok := subs[m]
			if ok { // found track in chan map
				subs[m] <- XPacket{typ: GopReplayEof} // synchronous EOF message
				close(subs[m])                        // closing is not sync, thats why we send an EOF before this
				delete(subs, m)
			} else {
				_, ok := txtr[m]
				if !ok {
					panic("not found on either map!")
				}
				delete(txtr, m)
			}
		case XPacket:
			// TESTING, vid only
			// if m.typ != Video { // save video GOPs
			// 	break
			// }

			// STEP1: we save video XPacket's in the gop-so-far
			if m.typ == Video { // save video GOPs
				if len(buf) > 50000 { //oversize protection // XXX >cap(buf)
					buf = make([]XPacket, 0)
				}
				if m.keyframe {
					buf = make([]XPacket, 1, 300) // XXX pool? or clear slice
					buf[0] = m
				} else if len(buf) > 0 {
					buf = append(buf, m)
				}

				// this sanity check moved to the receiving side
				// if len(buf) > 0 && !buf[0].keyframe {
				// 	panic("replay must begin with KF, or be empty")
				// }
			}

			// STEP2 sync recv new track messages

			if m.typ == Video && m.keyframe {
				//pl("keyframe on broker:", unsafe.Pointer(b))

				//we do these as two fors, because the compiler will optimize the 2nd for
				for k, v := range subs {
					txtr[k] = struct{}{}
					subs[k] <- XPacket{typ: GopReplayEof} // synchronous EOF message
					close(v)
				}
				for k := range subs { // https://go.dev/doc/go1.11#performance-compiler
					delete(subs, k)
				}
			}

			//STEP2 we send it to all chan-subscribers
			for _, ch := range subs {
				// should this be non-blocking?
				ch <- m
			}

			//STEP3 send the packet to tracks
			// if true && m.typ == Video {
			// 	//pl("pkt", len(m.pkt.Payload), m.pkt.SSRC, m.keyframe, m.pkt.SequenceNumber, m.pkt.Timestamp)
			// }
			if m.typ != Video && m.typ != Audio {
				panic("invalid xpkt type")
			}
			for txt := range txtr {
				txt.SpliceWriteRTP(m, nanotime())
				//pl(txt.vid.splicer.lastUnixnanosNow)
			}
		}
	}
}

func (b *XBroker) Stop() {
	close(b.msgCh)
}

func (b *XBroker) Subscribe(tr *TxTrackSet) {
	//msgCh := make(chan XPacket, 5)
	b.msgCh <- XBrokerMsgSub(tr)
}

func (b *XBroker) Unsubscribe(tr *TxTrackSet) {
	b.msgCh <- XBrokerMsgUnSub(tr)
}

func (b *XBroker) Publish(msg XPacket) {
	b.msgCh <- msg
}
