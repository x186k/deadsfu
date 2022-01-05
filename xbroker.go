package main

import (
	"io"
)

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

/*
The XBroker does these things:
- does broadcast fan-out of rtp packets to Go channels
- does broadcast fan-out of rtp packets to Pion Tracks
- records GOPs from keyframe, and shares the PGOP or GOP-so-far with Subscribers
*/

type XBroker struct {
	stopCh    chan struct{}
	publishCh chan xany
	subChCh   chan chan xany
	unsubChCh chan chan xany
	subTrCh   chan *TxTrack
	unsubTrCh chan *TxTrack
}

type xany interface{} // go 1.18 is here soon

var _ = NewXBroker

func NewXBroker() *XBroker {
	return &XBroker{
		stopCh:    make(chan struct{}),
		publishCh: make(chan xany, 1),
		subChCh:   make(chan chan xany, 1),
		unsubChCh: make(chan chan xany, 1),
		subTrCh:   make(chan *TxTrack), // MUST! BE UNBUF
		unsubTrCh: make(chan *TxTrack), // MUST! BE UNBUF
	}
}

func (b *XBroker) Start() {

	var buf []XPacket = nil

	subs := make(map[chan xany]struct{})

	tracks := make(map[*TxTrack]struct{})

	for {
		select {
		case <-b.stopCh:
			return

		case msgCh := <-b.subChCh:
			subs[msgCh] = struct{}{}
			if buf != nil {
				msgCh <- buf
			} else {
				msgCh <- []XPacket{}
			}

		case msgCh := <-b.unsubChCh:
			delete(subs, msgCh)

		case mm := <-b.publishCh:

			switch m := mm.(type) {
			case XPacket:
				// STEP1: we save video XPacket's in the gop-so-far
				if m.typ == Video { // save video GOPs
					if len(buf) > 50000 { //oversize protection // XXX >cap(buf)
						buf = nil
					}
					if m.keyframe {
						buf = make([]XPacket, 0, 100) // XXX pool?

					}
					if buf != nil {
						buf = append(buf, m)
					}

					// this sanity check moved to the receiving side
					// if len(buf) > 0 && !buf[0].keyframe {
					// 	panic("replay must begin with KF, or be empty")
					// }
				}
				//STEP2 we send it to all chan-subscribers
				for msgCh := range subs {
					// msgCh is buffered, use non-blocking send to protect the broker:
					// select {
					// case msgCh <- m:
					// default:
					// 	pl("dropped packet/msg")
					// }
					msgCh <- m
				}
				//STEP3 send the packet to tracks

				if m.typ != Video { // save video GOPs
					break
				}

				for txt := range tracks {

					SpliceRTP(&txt.splicer, &m.pkt, nanotime(), int64(txt.clockrate)) // writes all over m.pkt.Header
					//pl(999, m.pkt)
					err := txt.track.WriteRTP(&m.pkt) // faster than packet.Write()
					if err == io.ErrClosedPipe {
						panic("unexpected ErrClosedPipe")
					} else if err != nil {
						errlog.Println(err.Error())
					}

				}

			default:
				panic("xpacket only")
			}
		case txt := <-b.subTrCh:
			tracks[txt] = struct{}{}

		case txt := <-b.unsubTrCh:
			delete(tracks, txt)
		}
	}
}

func (b *XBroker) Stop() {
	close(b.stopCh)
}

func (b *XBroker) Subscribe(msgCh chan xany) {
	//msgCh := make(chan XPacket, 5)
	b.subChCh <- msgCh
}

func (b *XBroker) UnsubscribeClose(msgCh chan xany) {
	close(msgCh)
	b.unsubChCh <- msgCh
}

func (b *XBroker) Publish(msg XPacket) {
	b.publishCh <- msg
}
