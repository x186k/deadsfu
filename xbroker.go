package main

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
	subCh     chan chan xany
	unsubCh   chan chan xany
}

type xany interface{} // go 1.18 is here soon

var _ = NewXBroker

func NewXBroker() *XBroker {
	return &XBroker{
		stopCh:    make(chan struct{}),
		publishCh: make(chan xany, 1),
		subCh:     make(chan chan xany, 1),
		unsubCh:   make(chan chan xany, 1),
	}
}

func (b *XBroker) Start() {

	var buf []XPacket = nil

	subs := map[chan xany]struct{}{}
	for {
		select {
		case <-b.stopCh:
			return

		case msgCh := <-b.subCh:
			subs[msgCh] = struct{}{}
			if buf != nil {
				msgCh <- buf
			} else {
				msgCh <- []XPacket{}
			}

		case msgCh := <-b.unsubCh:
			delete(subs, msgCh)

		case mm := <-b.publishCh:

			switch m := mm.(type) {
			case XPacket:
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
				for msgCh := range subs {
					// msgCh is buffered, use non-blocking send to protect the broker:
					// select {
					// case msgCh <- m:
					// default:
					// 	pl("dropped packet/msg")
					// }
					msgCh <- m
				}
			default:
				panic("xpacket only")
			}
		}
	}
}

func (b *XBroker) Stop() {
	close(b.stopCh)
}

func (b *XBroker) Subscribe(msgCh chan xany) {
	//msgCh := make(chan XPacket, 5)
	b.subCh <- msgCh
}

func (b *XBroker) UnsubscribeClose(msgCh chan xany) {
	close(msgCh)
	b.unsubCh <- msgCh
}

func (b *XBroker) Publish(msg XPacket) {
	b.publishCh <- msg
}
