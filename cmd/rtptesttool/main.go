package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	rtpstuff "github.com/x186k/sfu1/rtpstuff"
)

func checkPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func sendUdp() {
	con, err := net.Dial("udp", "127.0.0.1:4000")
	checkPanic(err)

	rtp, t, err := rtpstuff.ReadPcap2RTP(os.Stdin)
	checkPanic(err)

	tstart := time.Now()

	t0 := t[0]

	ssrc := rtp[0].SSRC

	for i, v := range rtp {
		if v.SSRC != ssrc {
			println("fatal: only single SSRC per file allowed")
			os.Exit(-1)
		}
		if v.Version != 2 {
			println("fatal: version!=2, i=", i)
			os.Exit(-1)
		}

		v.PayloadType = 96

		delta := t[i].Sub(t0)
		playtime := tstart.Add(delta)
		sleeptime := time.Until(playtime)
		if sleeptime > 0 {
			time.Sleep(sleeptime)
		}

		buf, err := v.Marshal()
		checkPanic(err)

		_, err = con.Write(buf)
		checkPanic(err)
	}
}

func spsCount() {
	rtp, _, err := rtpstuff.ReadPcap2RTP(os.Stdin)
	checkPanic(err)

	ssrcorig := *ssrc
	if ssrcorig == "" {
		panic("ssrc must be specified")
	}

	ssrcorig = strings.TrimPrefix(ssrcorig, "0x")

	tmp, err := strconv.ParseUint(ssrcorig, 16, 32)

	checkPanic(err)
	xssrc := uint32(tmp)

	var numkeyf = 0

	for i, v := range rtp {
		if v.SSRC != xssrc {
			continue
		}
		if v.Version != 2 {
			println("fatal: version!=2, i=", i)
			os.Exit(-1)
		}

		kf := rtpstuff.IsH264Keyframe(v.Payload)
		if kf {
			numkeyf++
		}
	}
	fmt.Println(numkeyf)
}
func info() {
	rtp, _, err := rtpstuff.ReadPcap2RTP(os.Stdin)
	checkPanic(err)

	ssrc := rtp[0].SSRC
	var numDistinctTs int64 = 1
	var numkeyf = 0

	for i, v := range rtp {
		if v.SSRC != ssrc {
			println("fatal: only single SSRC per file allowed")
			os.Exit(-1)
		}
		if v.Version != 2 {
			println("fatal: version!=2, i=", i)
			os.Exit(-1)
		}

		if i > 0 && v.SequenceNumber-1 != rtp[i-1].SequenceNumber {
			println("seqno discontinuity before ", i)
		}
		if i > 0 && v.Timestamp != rtp[i-1].Timestamp {
			numDistinctTs++
		}
		kf := rtpstuff.IsH264Keyframe(v.Payload)
		if kf {
			numkeyf++
		}
	}
	println("num packets", len(rtp))
	println("numDistinctTs", numDistinctTs)
	println("num keyframe", numkeyf)
}

var sendUdpFlag = flag.Bool("send-udp", false, "send udp from stdin/pcap/rtp to 127.0.0.1, ptype=96")
var infoFlag = flag.Bool("show-info", false, "show total packets and unique ts/frame count from stdin/pcap/rtp")
var spsCountFlag = flag.Bool("sps-count", false, "show sps count from stdin/pcap/rtp")
var ssrc = flag.String("ssrc", "", "8 char hex ssrc")

func main() {
	flag.Parse()

	if *sendUdpFlag {
		sendUdp()
	} else if *spsCountFlag {
		spsCount()
	} else if *infoFlag {
		info()
	} else {
		println("dont know what to do")
	}
}
