package ftlserver

import (
	"bufio"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"errors"
	"fmt"

	"log"
	"net"

	"os"
	"strings"
	"time"
)

const (
	// FTL_INGEST_RESP_UNKNOWN                 = 0
	// FTL_INGEST_RESP_OK                      = 200
	// FTL_INGEST_RESP_PING                    = 201
	// FTL_INGEST_RESP_BAD_REQUEST             = 400 // The handshake was not formatted correctly
	FTL_INGEST_RESP_UNAUTHORIZED            = 401 // This channel id is not authorized to stream
	// FTL_INGEST_RESP_OLD_VERSION             = 402 // This ftl api version is no longer supported
	// FTL_INGEST_RESP_AUDIO_SSRC_COLLISION    = 403
	// FTL_INGEST_RESP_VIDEO_SSRC_COLLISION    = 404
	FTL_INGEST_RESP_INVALID_STREAM_KEY      = 405 // The corresponding channel does not match this key
	// FTL_INGEST_RESP_CHANNEL_IN_USE          = 406 // The channel ID successfully authenticated however it is already actively streaming
	// FTL_INGEST_RESP_REGION_UNSUPPORTED      = 407 // Streaming from this country or region is not authorized by local governments
	// FTL_INGEST_RESP_NO_MEDIA_TIMEOUT        = 408
	// FTL_INGEST_RESP_GAME_BLOCKED            = 409 // The game the user account is set to can't be streamed.
	// FTL_INGEST_RESP_SERVER_TERMINATE        = 410 // The sterver has terminated the stream.
	// FTL_INGEST_RESP_INTERNAL_SERVER_ERROR   = 500
	// FTL_INGEST_RESP_INTERNAL_MEMORY_ERROR   = 900
	// FTL_INGEST_RESP_INTERNAL_COMMAND_ERROR  = 901
	// FTL_INGEST_RESP_INTERNAL_SOCKET_CLOSED  = 902
	// FTL_INGEST_RESP_INTERNAL_SOCKET_TIMEOUT = 903
)

type FtlServer interface {
	TakePacket(inf *log.Logger, dbg *log.Logger, packet []byte) bool
}

type FindServerFunc func(inf *log.Logger, dbg *log.Logger, chanid string) (server FtlServer, hmackey string)

func NewTcpSession(inf *log.Logger, dbg *log.Logger, tcpconn *net.TCPConn, findsvr FindServerFunc, ftpUdpPort int) {
	var err error
	defer tcpconn.Close() //could be redundant

	err = tcpconn.SetKeepAlive(true)
	if err != nil {
		inf.Println("SetKeepAlive", err) //nil err okay
		return
	}

	err = tcpconn.SetKeepAlivePeriod(time.Second * 5)
	if err != nil {
		inf.Println("SetKeepAlivePeriod", err) //nil err okay
		return
	}

	err = tcpconn.SetReadDeadline(time.Now().Add(10 * time.Second)) //ping period is 5sec
	if err != nil {
		inf.Println("SetReadDeadline: ", err) //nil err okay
		return
	}

	inf.Println("OBS/FTL GOT TCP SOCKET CONNECTION")

	scanner := bufio.NewScanner(tcpconn)

	if !scanner.Scan() {
		dbg.Println("waiting hmac/register: error or eof", scanner.Err())
		return
	}

	line := scanner.Text()
	tokens := strings.SplitN(line, " ", 2)
	command := tokens[0]

	if command != "HMAC" {
		inf.Println("unrecognized 1st token on socket:", command)
		return
	}

	var l string

	dbg.Println("ftl: got hmac")

	if !scanner.Scan() {
		dbg.Println("waiting blank: error or eof", scanner.Err())
		return
	}
	if l = scanner.Text(); l != "" {
		inf.Println("ftl/no blank after hmac:", l)
		return
	}
	dbg.Println("ftl: got hmac blank")

	numrand := 128
	message := make([]byte, numrand)
	_, err = crand.Read(message)
	if err != nil {
		inf.Print(err)
		return
	}

	fmt.Fprintf(tcpconn, "200 %s\n", hex.EncodeToString(message))

	if !scanner.Scan() {
		dbg.Println("waiting connect: error or eof", scanner.Err())
		return
	}

	if l = scanner.Text(); !strings.HasPrefix(l, "CONNECT ") {
		inf.Println("ftl/no connect:", l)
		return
	}
	dbg.Println("ftl: got connect")

	connectsplit := strings.Split(l, " ")
	if len(connectsplit) < 3 {
		inf.Println("ftl: bad connect")
		return
	}

	userid := connectsplit[1]
	connectMsg := "CONNECT " + userid + " $"
	client_hash, err := hex.DecodeString(l[len(connectMsg):])
	if err != nil {
		inf.Println(err)
		return
	}

	// endpointMapMutex.Lock()
	// sfuinfo, ok := endpointMap[userid]
	// endpointMapMutex.Unlock()
	server, key := findsvr(inf, dbg, userid)
	if server == nil {
		inf.Println("Non existent userid presented", userid)
		fmt.Fprintf(tcpconn, "%d\n", FTL_INGEST_RESP_UNAUTHORIZED)
		return
	}

	hmackey := []byte(key)

	good := validMAC(hmackey, message, client_hash)

	dbg.Println("ftl: auth is okay:", good)

	if !good {
		inf.Println("FTL authentication failed for", userid)
		fmt.Fprintf(tcpconn, "%d\n", FTL_INGEST_RESP_INVALID_STREAM_KEY)
		return
	}

	fmt.Fprintf(tcpconn, "200\n")

	kvmap := make(map[string]string)

	err = tcpconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		inf.Println(err)
	}
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
				inf.Println("ftl/bad format keyval section:", l)
				return
			}
		}
	}

	for k, v := range kvmap {
		dbg.Println("ftl: key/value", k, v)
	}

	keyvalsOK := true // todo
	//do a consistency check of the key vals
	if !keyvalsOK {
		inf.Println("ftl/issue with k/v pairs")
		return
	}

	// net.DialUDP("udp",nil,), not yet, cause we don't know remote port
	x := net.UDPAddr{IP: nil, Port: ftpUdpPort, Zone: ""}
	udprx, err := net.ListenUDP("udp", &x)
	if err != nil {
		inf.Println(err)
		return
	}
	defer udprx.Close()

	laddr := udprx.LocalAddr().(*net.UDPAddr)
	dbg.Println("bound inbound udp on", laddr)

	fmt.Fprintf(tcpconn, "200. Use UDP port %d\n", laddr.Port)

	// PING goroutine
	go func() {
		// when the ping goroutine exits, we want to shut everything down
		defer tcpconn.Close()
		defer udprx.Close()

		for {
			err = tcpconn.SetReadDeadline(time.Now().Add(8 * time.Second)) //ping period is 5sec
			if err != nil {
				inf.Println("ping GR done: ", scanner.Err()) //nil err okay
				return
			}

			ok := scanner.Scan()
			if !ok {
				dbg.Println("ping GR done: ", scanner.Err()) //nil err okay
				return
			}

			l := scanner.Text()

			if strings.HasPrefix(l, "PING ") {
				// XXX PING is sometimes followed by streamkey-id
				// but we don't validate it.
				// it is checked for Connect message
				dbg.Println("ftl: ping!")
				fmt.Fprintf(tcpconn, "201\n")
			} else if l == "" {
				//ignore blank
			} else if l == "DISCONNECT" {
				inf.Println("disconnect, ping GR done")
				return
			} else {
				inf.Println("ftl: unexpected msg:", l)
			}
		}
	}()

	buf := make([]byte, 2000)

	for {
		err = udprx.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			inf.Println(err)
			return
		}

		n, _, err := udprx.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			inf.Println("no FTL packets for a while, closing")
			return
		} else if err != nil {
			inf.Println(err)
			return
		}

		// not now: udprx, err = net.DialUDP("udp", laddr, readaddr)

		if n < 12 {
			continue
		}

		// if you don't make a copy here,
		//then every implementor of x.TakePacket()
		// needs to either: a) not touch the byte array,
		// or make their own copy
		// I think it is better to make the copy here
		// and remove that requirement upon implementors
		// if you use pion/rtp.Unmarshal, it's easy to encounter a bug
		// if you pass the original
		pktcopy := make([]byte, n)
		copy(pktcopy, buf[:n])

		ok := server.TakePacket(inf, dbg, pktcopy)
		if !ok {
			dbg.Println("indication from ftl parent to close FTL chanid:", userid)
			return
		}

		// _, err = sfuinfo.udptx.Write(buf[:n])
		// if err != nil {
		// 	if errors.Is(err, unix.ECONNREFUSED) { // or windows.WSAECONNRESET
		// 		nrefused++
		// 		if nrefused > 10 {
		// 			xlog.Println("ending session: too many ECONNREFUSED")
		// 			return
		// 		}
		// 	}
		// }
	}

}

func validMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
