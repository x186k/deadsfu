package main

import "time"

//credit for inspiration to https://stackoverflow.com/a/49877632/86375

// the Partial GOP Broker
// can publish/broadcast pkts
// but can also serve up the current GOP so far
type PgopBroker struct {
	stopCh      chan struct{}
	publishCh   chan XPacket
	subCh       chan chan XPacket
	subReplayCh chan chan XPacket
	unsubCh     chan chan XPacket
}

var _ = NewPgopBroker

func NewPgopBroker() *PgopBroker {
	return &PgopBroker{
		stopCh:      make(chan struct{}),
		publishCh:   make(chan XPacket, 1),
		subCh:       make(chan chan XPacket, 1),
		subReplayCh: make(chan chan XPacket, 1),
		unsubCh:     make(chan chan XPacket, 1),
	}
}

func (b *PgopBroker) Start() {
	buf := make([]XPacket, 0)

	subs := map[chan XPacket]struct{}{}
	for {
		select {
		case <-b.stopCh:
			return

		case msgCh := <-b.subCh:
			subs[msgCh] = struct{}{}

		case msgCh := <-b.subReplayCh:
			subs[msgCh] = struct{}{}
			// start replay
			go PgopReplay(buf, msgCh)

		case msgCh := <-b.unsubCh:
			delete(subs, msgCh)

		case m := <-b.publishCh:

			if m.typ == Video { // save video GOPs
				if m.keyframe || len(buf) > 50000 { // handle runaway growth
					buf = make([]XPacket, 0) // XXX alloc optimize opportunity
				}
				buf = append(buf, m)
			}

			for msgCh := range subs {
				// msgCh is buffered, use non-blocking send to protect the broker:
				select {
				case msgCh <- m:
				default:
					pl("dropped packet/msg")
				}
			}
		}
	}
}

func (b *PgopBroker) Stop() {
	close(b.stopCh)
}

func (b *PgopBroker) Subscribe(msgCh chan XPacket) {
	//msgCh := make(chan XPacket, 5)
	b.subCh <- msgCh
}

func (b *PgopBroker) SubscribeReplay(msgCh chan XPacket) {
	//msgCh := make(chan XPacket, 5)
	b.subReplayCh <- msgCh
}

func (b *PgopBroker) UnsubscribeClose(msgCh chan XPacket) {
	close(msgCh)
	b.unsubCh <- msgCh
}

func (b *PgopBroker) Publish(msg XPacket) {
	b.publishCh <- msg
}

func PgopReplay(buf []XPacket, ch chan XPacket) {
	if len(buf) == 0 {
		return
	}

	delta := nanotime() - buf[0].now // linear regression or other would be better

	for p := range ch {
		deadline := p.now + delta
		sleep := deadline - nanotime()

		if sleep < 0 {
			sleep = 0
		}
		time.Sleep(time.Duration(sleep))

		ch <- p
	}

}
