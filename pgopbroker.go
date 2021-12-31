package main

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

// the Partial GOP Broker
// can publish/broadcast pkts
// but can also serve up the current GOP so far
type PgopBroker struct {
	stopCh    chan struct{}
	publishCh chan xany
	subCh     chan chan xany
	unsubCh   chan chan xany
}

type xany interface{}

var _ = NewPgopBroker

func NewPgopBroker() *PgopBroker {
	return &PgopBroker{
		stopCh:    make(chan struct{}),
		publishCh: make(chan xany, 1),
		subCh:     make(chan chan xany, 1),
		unsubCh:   make(chan chan xany, 1),
	}
}

func (b *PgopBroker) Start() {

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
					if len(buf) > 50000 { //oversize protection
						buf = nil
					}
					if m.keyframe {
						buf = make([]XPacket, 0, 100)
					}
					if buf != nil {
						buf = append(buf, m)
					}
					//XXXX remove me
					// this sanity check moved to the receiving side
					// if len(buf) > 0 && !buf[0].keyframe {
					// 	panic("replay must begin with KF, or be empty")
					// }
				}
				for msgCh := range subs {
					// msgCh is buffered, use non-blocking send to protect the broker:
					select {
					case msgCh <- m:
					default:
						pl("dropped packet/msg")
					}
				}
			default:
				panic("xpacket only")
			}
		}
	}
}

func (b *PgopBroker) Stop() {
	close(b.stopCh)
}

func (b *PgopBroker) Subscribe(msgCh chan xany) {
	//msgCh := make(chan XPacket, 5)
	b.subCh <- msgCh
}

func (b *PgopBroker) UnsubscribeClose(msgCh chan xany) {
	close(msgCh)
	b.unsubCh <- msgCh
}

func (b *PgopBroker) Publish(msg XPacket) {
	b.publishCh <- msg
}
