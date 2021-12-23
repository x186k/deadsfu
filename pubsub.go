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

func (ps *Pubsub) UnsubscribeAndClose(removed *chan rtp.Packet) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	close(*removed)

	// delete slice trick
	*removed = ps.subs[len(ps.subs)-1]
	ps.subs[len(ps.subs)-1] = nil
	ps.subs = ps.subs[:len(ps.subs)-1]
}

func (ps *Pubsub) Publish(p rtp.Packet) {

	discardOnBusy := true

	// cannot make a copy of the slice
	// in order to reduce lock period.
	// as it creates a race on send/close
	ps.mu.RLock()
	for _, v := range ps.subs {
		if discardOnBusy {
			select {
			case v <- p:
			default:
			}
		} else {
			v <- p
		}
	}
	ps.mu.RUnlock()
}
