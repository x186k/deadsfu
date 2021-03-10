package rtpsplice

import (
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pion/rtp"
)

type RtpSource byte // make a byte, so everything is atomic! Yay mom!

const (
	NoSource RtpSource = iota
	Video1
	Video2
	Video3
	Audio = 50
	Idle  = 100
)

type KeyFrameType int

const (
	H264 KeyFrameType = iota
	Opus
)

type RtpSplicer struct {
	mu               sync.Mutex
	Name             string
	lastSSRC         uint32
	lastSN           uint16
	lastTS           uint32
	lastUnixnanosNow int64
	snOffset         uint16
	tsOffset         uint32
	Active           RtpSource // Never set this directly, even though it is exported
	Pending          RtpSource // This is the one to set
	//tsFrequencyDelta []FrequencyPair
}

// type FrequencyPair struct {
// 	delta uint32
// 	count uint64 // better be safe than sorry
// }

func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

// IsActiveOrPending hopefully inlineable
// not-mutexed on purpose, no mutex needed on byte-wide variables
func (s *RtpSplicer) IsActiveOrPending(src RtpSource) bool {
	isactive := s.Active == src
	ispending := s.Pending == src

	if !isactive && !ispending {
		return false
	}
	return true
}

// findMostFrequentDelta is used to find inter-frame period
// not-mutexed on purpose, only called from inside mutexed func
// func (s *RtpSplicer) findMostFrequentDelta(fallback uint32) (delta uint32) {
// 	var n uint64

// 	for i, v := range s.tsFrequencyDelta {

// 		log.Println("findMostFrequentDelta:", i, v.count, v.delta)

// 		if v.count >= n {
// 			n = v.count
// 			delta = v.delta
// 		}
// 	}
// 	if n > 2 {
// 		log.Println("rtpsplice: findMostFrequentDelta, clockDelta from observations:", delta)
// 		return delta
// 	} else {
// 		log.Println("rtpsplice: findMostFrequentDelta, clockDelta from fallback:", fallback)
// 		return fallback
// 	}
// }

// not-mutexed on purpose, only called from inside mutexed func
// func (s *RtpSplicer) trackTimestampDeltas(delta uint32) {
// 	// classic insert into sorted set  https://golang.org/pkg/sort/#Search

// 	//log.Println(delta)
// 	i := sort.Search(len(s.tsFrequencyDelta), func(i int) bool { return s.tsFrequencyDelta[i].delta <= delta })
// 	if i < len(s.tsFrequencyDelta) && s.tsFrequencyDelta[i].delta == delta {
// 		s.tsFrequencyDelta[i].count++
// 	} else {
// 		// x is not present in data,
// 		// but i is the index where it would be inserted.
// 		// go slice tricks! https://github.com/golang/go/wiki/SliceTricks#insert
// 		s.tsFrequencyDelta = append(s.tsFrequencyDelta, FrequencyPair{})
// 		copy(s.tsFrequencyDelta[i+1:], s.tsFrequencyDelta[i:])
// 		s.tsFrequencyDelta[i] = FrequencyPair{delta: delta, count: 0}
// 	}
// }

// SpliceRTP
// this is carefully handcrafted, be careful
//
// we may want to investigate adding seqno deltas onto a master counter
// as a way of making seqno most consistent in the face of lots of switching,
// and also more robust to seqno bug/jumps on input
//
// This grabs mutex after doing a fast, non-mutexed check for applicability
func (s *RtpSplicer) SpliceRTP(o *rtp.Packet, src RtpSource, unixnano int64, rtphz int64, keytype KeyFrameType) *rtp.Packet {

		// take mutex before changing stuff, or accessing >byte size
		s.mu.Lock()
		defer s.mu.Unlock()

	//do not mutex this, it's okay
	isactive := s.Active == src
	ispending := s.Pending == src
	if !isactive && !ispending {
		return nil
	}



	foo:=false
	if ispending {
		iskeyframe := true

		switch keytype {
		case H264:
			iskeyframe = ContainSPS(o.Payload) // performance short-circuit
		case Opus:
			iskeyframe = true
		}

		if !iskeyframe {
			return nil
		}

		log.Printf("SpliceRTP: %v: keyframe on pending source %v", s.Name, src)

		s.Active = src
		s.Pending = NoSource
		foo=true
	}

	copy := *o
	// credit to Orlando Co of ion-sfu
	// for helping me decide to go this route and keep it simple
	// code is modeled on code from ion-sfu
	if o.SSRC != s.lastSSRC || foo {
		log.Printf("SpliceRTP: %v: ssrc changed new=%v cur=%v", s.Name, o.SSRC, s.lastSSRC)

		td := unixnano - s.lastUnixnanosNow // nanos
		if td < 0 {
			td = 0 // be positive or zero! (go monotonic clocks should mean this never happens)
		}
		td *= rtphz / int64(time.Second) //convert nanos -> 90khz or similar clockrate
		if td == 0 {
			td = 1
		}
		s.tsOffset = o.Timestamp - (s.lastTS + uint32(td))
		s.snOffset = o.SequenceNumber - s.lastSN - 1

		//log.Println(11111,	copy.SequenceNumber - s.snOffset,s.lastSN)
		// old approach/abandoned
		// timestamp := unixnano * rtphz / int64(time.Second)
		// s.addTS = uint32(timestamp)

		//2970 is just a number that worked very with with chrome testing
		// is it just a fallback
		//clockDelta := s.findMostFrequentDelta(uint32(2970))

		//s.tsFrequencyDelta = s.tsFrequencyDelta[:0] // reset frequency table

		//s.addTS = s.lastSentTS + clockDelta
	}

	// we don't want to change original packet, it gets
	// passed into this routine many times for many subscribers


	copy.Timestamp -= s.tsOffset
	copy.SequenceNumber -= s.snOffset
	//	tsdelta := int64(copy.Timestamp) - int64(s.lastSentTS) // int64 avoids rollover issues
	// if !ssrcChanged && tsdelta > 0 {              // Track+measure uint32 timestamp deltas
	// 	s.trackTimestampDeltas(uint32(tsdelta))
	// }

	s.lastUnixnanosNow = unixnano
	s.lastTS = copy.Timestamp
	s.lastSN = copy.SequenceNumber
	s.lastSSRC = copy.SSRC

	return &copy
}

// ContainSPS detects when an RFC6184 payload contains an H264 SPS (8)
// most encoders will follow this with an PPS (7), and maybe SEI
// this code has evolved from:
// from https://github.com/jech/galene/blob/codecs/rtpconn/rtpreader.go#L45
// the original IDR detector was written by Juliusz Chroboczek @jech from the awesome Galene SFU
// Types sps=7 pps=8 IDR-slice=5
// no writes expects immutable []byte, so
// no mutex is taken
func ContainSPS(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}
	nalu := payload[0] & 0x1F
	if nalu == 0 {
		// reserved
		return false
	} else if nalu <= 23 {
		// simple NALU
		return nalu == 7
	} else if nalu == 24 || nalu == 25 || nalu == 26 || nalu == 27 {
		// STAP-A, STAP-B, MTAP16 or MTAP24
		i := 1
		if nalu == 25 || nalu == 26 || nalu == 27 {
			// skip DON
			i += 2
		}
		for i < len(payload) {
			if i+2 > len(payload) {
				return false
			}
			length := uint16(payload[i])<<8 |
				uint16(payload[i+1])
			i += 2
			if i+int(length) > len(payload) {
				return false
			}
			offset := 0
			if nalu == 26 {
				offset = 3
			} else if nalu == 27 {
				offset = 4
			}
			if offset >= int(length) {
				return false
			}
			n := payload[i+offset] & 0x1F
			if n == 7 {
				return true
			} else if n >= 24 {
				// is this legal?
				println("Non-simple NALU within a STAP")
			}
			i += int(length)
		}
		if i == len(payload) {
			return false
		}
		return false
	} else if nalu == 28 || nalu == 29 {
		// FU-A or FU-B
		if len(payload) < 2 {
			return false
		}
		if (payload[1] & 0x80) == 0 {
			// not a starting fragment
			return false
		}
		return payload[1]&0x1F == 7
	}
	return false
}

// ReadPcap2RTP reads a pcapng into an array of packets
// no mutex needed
func ReadPcap2RTP(reader io.Reader) ([]rtp.Packet, []time.Time, error) {
	var pkts []rtp.Packet
	var timestamps []time.Time

	r, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
	checkPanic(err)

	for {
		data, capinfo, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		// Decode a packet
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		udplayer := packet.Layer(layers.LayerTypeUDP)
		if udplayer == nil {
			panic("non-udp in pcap")
		}

		udp, _ := udplayer.(*layers.UDP)

		var p rtp.Packet
		err = p.Unmarshal(udp.Payload)
		checkPanic(err)

		pkts = append(pkts, p)
		timestamps = append(timestamps, capinfo.Timestamp)
	}

	return pkts, timestamps, nil
}
