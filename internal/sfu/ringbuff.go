package sfu

type RingBuff interface {
	ReadSingleBlk() *XPacket        // blocking for func Writer()
	WriteSingleNBlk(v *XPacket) bool // non-blocking for func OnTrack()
}

type RBChan struct {
	c chan *XPacket
}

func NewRBChan(size, pause int32) *RBChan {
	return &RBChan{
		c: make(chan *XPacket, size),
	}
}

func (r *RBChan) ReadSingleBlk() *XPacket {

	select {
	case a, ok := <-r.c:
		if !ok {
			panic("no")
		}
		return a
	default:
		return nil
	}

}

func (r *RBChan) WriteSingleNBlk(x *XPacket) bool {

	select {
	case r.c <- x:
		return true
	default:
		return false
	}

}
