package main

import (
	"sync"

	"github.com/pion/rtp"
)

type Pubsub struct {
	mu   sync.RWMutex
	subs []chan rtp.Packet
}

func (ps *Pubsub) Subscribe(ch chan rtp.Packet) *chan rtp.Packet {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.subs = append(ps.subs, ch)

	return &ps.subs[len(ps.subs)-1]
}

func (ps *Pubsub) Unubscribe(removed *chan rtp.Packet) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	//close(*removed)

	// delete slice trick
	*removed = ps.subs[len(ps.subs)-1]
	ps.subs[len(ps.subs)-1] = nil
	ps.subs = ps.subs[:len(ps.subs)-1]
}

func (ps *Pubsub) Publish(p rtp.Packet) {

	// faster lock period
	ps.mu.RLock()
	a := make([]chan rtp.Packet, len(ps.subs))
	copy(a, ps.subs)
	ps.mu.RUnlock()

	discardOnBusy := true

	for _, v := range a {
		if discardOnBusy {
			select {
			case v <- p:
			default:
			}
		} else {
			v <- p
		}
	}
}
