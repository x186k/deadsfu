package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
)

var ErrFTLAuthFail = errors.New("FTL authentication failed")

//generally listenResolveAddr should be ""

// ftlServer starts an ftl server on a port, typically 8084
// there is two class of errors in here
// -fatal
// -non-fatal
// fatals invoke checkfatal() which call os.exit()
// non-fatals will return with nil,nil,nil,err
// protocol mistakes are non-fatal
// non-protocol system or networking issues are fatal
func ftlServer(listenResolveAddr, port string, streamkey string) (udpconn *net.UDPConn, tcpconn net.Conn, kvmap map[string]string, scanner *bufio.Scanner, err error) {

	split := strings.Split(streamkey, "-")
	if len(split) != 2 {
		checkFatal(fmt.Errorf("Invalid --obs-key, valid example format: 123-abc"))
	}

	//pre agreed key
	// key := []byte("aBcDeFgHiJkLmNoPqRsTuVwXyZ123456")
	// myid := "123456789"
	myid := split[0]
	key := []byte(split[1])

	kvmap = make(map[string]string)

	ln, err := net.Listen("tcp4", listenResolveAddr+":"+port)
	//fatal
	checkFatal(err)
	defer ln.Close()

	tcpconn, err = ln.Accept()
	//fatal
	checkFatal(err)
	//NO defer c.Close()
	// caller is expected to close when done, since:
	// we must keep the socket open and keep pinging over tcp

	elog.Println("OBS/FTL GOT TCP SOCKET CONNECTION")

	scanner = bufio.NewScanner(tcpconn)

	// w := bufio.NewWriter(conn)
	// w.WriteString()

	var l string

	if !scanner.Scan() {
		err = scanner.Err()
		return
	}
	if l = scanner.Text(); l != "HMAC" {
		err = fmt.Errorf("ftl/no hmac:%s", l)
		return
	}
	log.Println("ftl: got hmac")

	if !scanner.Scan() {
		err = scanner.Err()
		return
	}
	if l = scanner.Text(); l != "" {
		err = fmt.Errorf("ftl/no blank after hmac:%s", l)
		return
	}
	log.Println("ftl: got hmac blank")

	numrand := 128
	message := make([]byte, numrand)
	_, err = rand.Read(message)
	// fatal, system has issues
	checkFatal(err)

	fmt.Fprintf(tcpconn, "200 %s\n", hex.EncodeToString(message))

	if !scanner.Scan() {
		err = scanner.Err()
		return
	}
	connectMsg := "CONNECT " + myid + " $"
	if l = scanner.Text(); !strings.HasPrefix(l, "CONNECT ") {

		err = fmt.Errorf("ftl/no connect:%s", l)
		return
	}
	log.Println("ftl: got connect")

	connectsplit := strings.Split(l, " ")
	if len(connectsplit) < 3 {
		err = fmt.Errorf("ftl: bad connect")
		return
	}

	if connectsplit[1] != myid {
		err = fmt.Errorf("ftl: bad stream key ID, want %s, got %s", myid, connectsplit[1])
		return
	}

	client_hash, err := hex.DecodeString(l[len(connectMsg):])
	logNotFatal(err)

	good := ValidMAC(key, message, client_hash)

	log.Println("ftl: auth is okay:", good)

	if good {
		fmt.Fprintf(tcpconn, "200\n")
	} else {
		err = ErrFTLAuthFail
		return
	}

	z := make(chan bool)

	go func() {
		select {
		case <-time.NewTimer(5 * time.Second).C:
			tcpconn.Close()
			err = fmt.Errorf("ftl: timeout waiting for handshake")
			return
		case <-z:
			log.Println("ftl: handshake complete before timeout")
		}
	}()

	for scanner.Scan() {
		l = scanner.Text()
		if l == "." {
			break
		}
		if l != "" {
			split := strings.SplitN(l, ": ", 2)
			if len(split) == 2 {
				kvmap[split[0]] = split[1]
			} else {
				err = fmt.Errorf("ftl/bad format keyval section: %s", l)
				return
			}
		}
		//fmt.Println(">", l)
	}

	close(z) //stop key read timeout
	log.Println("ftl: got k/v set")

	for k, v := range kvmap {
		log.Println("ftl: key/value", k, v)
	}

	keyvalsOK := true // todo
	//do a consistency check of the key vals
	if !keyvalsOK {
		err = fmt.Errorf("ftl/issue with k/v pairs")
		return
	}

	fmt.Fprintf(tcpconn, "200. Use UDP port 8084\n")

	addr, err := net.ResolveUDPAddr("udp4", listenResolveAddr+":8084")
	//fatal
	checkFatal(err)

	udpconn, err = net.ListenUDP("udp4", addr)
	//fatal
	checkFatal(err)

	err = nil
	return

	//return scanner.Err()
}

// if err := scanner.Err(); err != nil {
// 	fmt.Fprintln(os.Stderr, "reading standard input:", err)
// }

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
