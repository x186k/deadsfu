package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
)

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)

		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

func main() {
	err := foo()
	checkFatal(err)
}

func foo() error {

	ln, err := net.Listen("tcp", ":8084")
	checkFatal(err)
	defer ln.Close()

	c, err := ln.Accept()
	checkFatal(err)
	defer c.Close()

	scanner := bufio.NewScanner(c)

	// w := bufio.NewWriter(conn)
	// w.WriteString()

	var l string

	if !scanner.Scan() {
		return scanner.Err()
	}
	if l = scanner.Text(); l != "HMAC" {
		return fmt.Errorf("ftl/no hmac:%s", l)
	}
	log.Println("got hmac")

	if !scanner.Scan() {
		return scanner.Err()
	}
	if l = scanner.Text(); l != "" {
		return fmt.Errorf("ftl/no blank after hmac:%s", l)
	}
	log.Println("got hmac blank")

	numrand := 128
	message := make([]byte, numrand)
	_, err = rand.Read(message)
	checkFatal(err)

	fmt.Fprintf(c, "200 %s\n", hex.EncodeToString(message))

	if !scanner.Scan() {
		return scanner.Err()
	}
	const connectMsg = "CONNECT 123456789 $"
	if l = scanner.Text(); !strings.HasPrefix(l, connectMsg) {
		return fmt.Errorf("ftl/no connect:%s", l)
	}
	log.Println("got connect")

	client_hash, err := hex.DecodeString(l[len(connectMsg):])
	checkFatal(err)

	//pre agreed key
	key := []byte("aBcDeFgHiJkLmNoPqRsTuVwXyZ123456")

	good := ValidMAC(key, message, client_hash)

	if good {
		fmt.Fprintf(c, "200\n")
	}

	z := make(chan bool)

	go func() {
		select {
		case <-time.NewTimer(5 * time.Second).C:
			c.Close()
		case <-z:
			println(88)
		}
	}()

	m := make(map[string]string)

	for scanner.Scan() {
		l = scanner.Text()
		if l == "." {
			break
		}
		if l != "" {
			split := strings.SplitN(l, ": ", 2)
			if len(split) == 2 {
				m[split[0]] = split[1]
			} else {
				log.Println("ftl/bad format keyval section", l)
			}
		}
		//fmt.Println(">", l)
	}

	close(z) //stop key read timeout

	for k, v := range m {
		fmt.Println(k, v)
	}

	keyvalsOK := true
	if !keyvalsOK {
		return fmt.Errorf("ftl/issue with k/v pairs")
	}

	fmt.Fprintf(c, "200. Use UDP port 8084\n")

	select {}

	//return scanner.Err()
}

func ValidMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// if err := scanner.Err(); err != nil {
// 	fmt.Fprintln(os.Stderr, "reading standard input:", err)
// }
