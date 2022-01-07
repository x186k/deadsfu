package main

import (
	"io"
	"sync"
)

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

/*
The XBroker does these things:
- does broadcast fan-out of rtp packets to Go channels
- does broadcast fan-out of rtp packets to Pion Tracks
- records GOPs from keyframe, and shares the PGOP or GOP-so-far with Subscribers
*/

type XBroker struct {
	msgCh  chan xany
	txtsMu sync.Mutex
	txts   map[*TxTrack]struct{}
}

type XBrokerMsgStop struct{} // https://goplay.tools/snippet/9K4u1ESBg6A
type XBrokerMsgSub chan xany
type XBrokerMsgUnSub chan xany

type xany interface{} // go 1.18 is here soon

var _ = NewXBroker

func NewXBroker() *XBroker {
	return &XBroker{
		msgCh: make(chan xany, 1),
		txts:  make(map[*TxTrack]struct{}),
	}
}

func (b *XBroker) Start() {

	var buf []XPacket = nil

	subs := make(map[chan xany]struct{})

	for mm := range b.msgCh {

		switch m := mm.(type) {
		case XBrokerMsgSub:
			subs[m] = struct{}{}
			if buf != nil {
				m <- buf
			} else {
				m <- []XPacket{}
			}
		case XBrokerMsgUnSub:
			delete(subs, m)
		case XBrokerMsgStop:
			return
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

			b.txtsMu.Lock()
			//pl(len(b.txts))

			for txt := range b.txts {
				copy := m.pkt

				// if you accidentially pass a copy of the first param, seqno gunna always be one/wrong on other side
				SpliceRTP(&txt.splicer, &copy, m.now, int64(txt.clockrate)) // writes all over m.pkt.Header
				//pl(888,m.pkt.SequenceNumber,m.pkt.Timestamp,len(b.txts))

				err := txt.track.WriteRTP(&copy) // faster than packet.Write()
				if err == io.ErrClosedPipe {
					panic("unexpected ErrClosedPipe")
				} else if err != nil {
					errlog.Println(err.Error())
				}
			}

			b.txtsMu.Unlock()

		}
	}
}

func (b *XBroker) Stop() {
	close(b.msgCh)
}

func (b *XBroker) Subscribe(msgCh chan xany) {
	//msgCh := make(chan XPacket, 5)
	b.msgCh <- XBrokerMsgSub(msgCh)
}

func (b *XBroker) UnsubscribeClose(msgCh chan xany) {
	close(msgCh)
	b.msgCh <- XBrokerMsgUnSub(msgCh)
}

func (b *XBroker) Publish(msg XPacket) {
	b.msgCh <- msg
}

func (b *XBroker) AddTrack(txt *TxTrack) {
	b.txtsMu.Lock()
	b.txts[txt] = struct{}{}
	b.txtsMu.Unlock()
}

func (b *XBroker) DelTrack(txt *TxTrack) {

	b.txtsMu.Lock()
	if _, ok := b.txts[txt]; !ok {
		panic("broker.deltrack on no such track")
	}
	delete(b.txts, txt)
	b.txtsMu.Unlock()
}
