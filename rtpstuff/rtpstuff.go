package rtpstuff

import (
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pion/rtp"
)


func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

// IsH264Keyframe detects when an RFC6184 payload contains an H264 SPS (8)
// most encoders will follow this with an PPS (7), and maybe SEI
// this code has evolved from:
// from https://github.com/jech/galene/blob/codecs/rtpconn/rtpreader.go#L45
// the original IDR detector was written by Juliusz Chroboczek @jech from the awesome Galene SFU
// Types sps=7 pps=8 IDR-slice=5
// no writes expects immutable []byte, so
// no mutex is taken
func IsH264Keyframe(payload []byte) bool {
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
