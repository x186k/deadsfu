package ftl

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

func FtlServer(listenResolveAddr, port string, streamkey string) (conn *net.UDPConn, kvmap map[string]string, err error) {

	split := strings.Split(streamkey, "-")
	if len(split) != 2 {
		return nil, nil, fmt.Errorf("Invalid URL streamkey, must be: ftp://host/nnnnn-key")
	}

	//pre agreed key
	// key := []byte("aBcDeFgHiJkLmNoPqRsTuVwXyZ123456")
	// myid := "123456789"
	myid := split[0]
	key := []byte(split[1])

	kvmap = make(map[string]string)

	ln, err := net.Listen("tcp4", listenResolveAddr+":"+port)
	if err != nil {
		return
	}
	defer ln.Close()

	c, err := ln.Accept()
	if err != nil {
		return
	}
	//NO defer c.Close()

	log.Println("ftl: socket accepted")

	scanner := bufio.NewScanner(c)

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
	if err != nil {
		return
	}

	fmt.Fprintf(c, "200 %s\n", hex.EncodeToString(message))

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
	if err != nil {
		return
	}

	good := ValidMAC(key, message, client_hash)

	log.Println("ftl: auth is okay:", good)

	if good {
		fmt.Fprintf(c, "200\n")
	} else {
		err = ErrFTLAuthFail
		return
	}

	z := make(chan bool)

	go func() {
		select {
		case <-time.NewTimer(5 * time.Second).C:
			c.Close()
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
				log.Println("ftl/bad format keyval section", l)
			}
		}
		//fmt.Println(">", l)
	}

	log.Println("ftl: got k/v set")
	close(z) //stop key read timeout

	for k, v := range kvmap {
		log.Println("ftl: key/value", k, v)
	}

	keyvalsOK := true
	//do a consistency check of the key vals
	if !keyvalsOK {
		err = fmt.Errorf("ftl/issue with k/v pairs")
		return
	}

	fmt.Fprintf(c, "200. Use UDP port 8084\n")

	addr, err := net.ResolveUDPAddr("udp4", listenResolveAddr+":8084")
	if err != nil {
		return
	}

	conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		conn = nil
		return
	}

	// PING GR
	go func() {
		log.Println("ftl: ping responder running")
		for scanner.Scan() {
			l = scanner.Text()

			// XXX PING is sometimes followed by streamkey-id
			// but we don't validate it.
			// it is checked for Connect message
			if strings.HasPrefix(l, "PING ") {
				log.Println("ftl: ping")
				fmt.Fprintf(c, "201\n")
			}
		}
		//silently end GR on error
	}()

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
