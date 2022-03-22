package sfu

import "github.com/pion/webrtc/v3"

var controlCh = make(chan any, 100)

type msgNewPub struct {
	roomname string
	offer    string
	ansCh      chan msgNewPubAns
	xpch     chan<- *XPacket
}

type msgNewPubAns struct {
	sd  *webrtc.SessionDescription
	err error
}

func controllerGr() {

	mm := make(map[string]chan *XPacket)

	getRoomChan := func(n string) chan *XPacket {
		if _, ok := mm[n]; !ok {
			mm[n] = make(chan *XPacket)
		}
		return mm[n]
	}

	for i := range controlCh {

		switch m := i.(type) {
		case msgNewPub:
			m.xpch = getRoomChan(m.roomname)

			go func(){
				err:=pubHandlerCreatePeerconn(m)

				if err!=nil{
					xxx really should be:
					controlCh <- msgNewPubAns{err:err}

					m.ansCh<-msgNewPubAns{err:err}
					return
				}
				m.ansCh<-msgNewPubAns{err:err}


			}()
			
		case msgNewPubAns:

		}

	}

}
