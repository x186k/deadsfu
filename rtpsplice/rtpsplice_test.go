package rtpsplice

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"testing"
)

func TestAbs(t *testing.T) {
	got := math.Abs(-1)
	if got != 1 {
		t.Errorf("Abs(-1) = %v; want 1", got)
	}
}

func TestX(t *testing.T) {

	x := []byte{}
	f, err := os.Open("/home/c/x186k-test-pcaps/h264.012021.pcap")
	checkPanic(err)

	p, ts, err := ReadPcap2RTP(f)
	checkPanic(err)

	for _, v := range p {

		x = append(x, v.Payload...)
	}

	err = ioutil.WriteFile("x.264", x, 0777)
	checkPanic(err)

	fmt.Println(99, len(p), len(ts))

	got := math.Abs(-1)
	if got != 1 {
		t.Errorf("Abs(-1) = %v; want 1", got)
	}
}

func x() {}
