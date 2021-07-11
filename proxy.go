package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

// canConnectThroughProxy uses an internet proxy to see if my ports are open
// network should be either tcp4 or tcp6, not tcp
func canConnectThroughProxy(proxyaddr string, tcpaddr *net.TCPAddr, network string) (proxyOK bool, portOpen bool) {
	const (
		baseDialerTimeout  = 3 * time.Second
		proxyDialerTimeout = 3 * time.Second
		SOCKS5PROXY        = "deadsfu.com:60000"
	)
	if network != "tcp4" && network != "tcp6" {
		checkFatal(fmt.Errorf("network not okay"))
	}

	if proxyaddr == "" {
		proxyaddr = SOCKS5PROXY
	}

	baseDialer := &net.Dialer{
		Timeout: baseDialerTimeout,
		//Deadline: time.Time{},
		//FallbackDelay: -1,
	}

	// always get to proxy using ipv4, more reliable for this test
	dialer, err := proxy.SOCKS5(network, proxyaddr, nil, baseDialer)
	if err != nil {
		return
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		log.Println("cannot deref dialer")
		//not fatal
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyDialerTimeout)
	_ = cancel

	// we ask the proxy for the given network
	conn, err := contextDialer.DialContext(ctx, network, tcpaddr.String())
	if err != nil {
		for xx := err; xx != nil; xx = errors.Unwrap(xx) {
			//fmt.Printf("%#v\n", xx)
			var operr *net.OpError
			if errors.As(xx, &operr) {
				readop := operr.Op == "read"
				dialop := operr.Op == "dial"
				iotimeout := operr.Err == os.ErrDeadlineExceeded //also errors.Is(xx, os.ErrDeadlineExceeded)

				if readop && iotimeout {
					proxyOK = true
					portOpen = false
					return
				} else if dialop && iotimeout {
					proxyOK = false
					portOpen = false
					return
				}
			} else {
				fmt.Println(err)
			}
		}
		// unexpected issue with proxy, but we stay silent
		// unless debugging is on
		// maybe Cam didn't pay proxy bill
		log.Println("unexpected proxy behavior")
		for xx := err; xx != nil; xx = errors.Unwrap(xx) {
			log.Printf("%#v\n", xx)
		}

		return
	}
	conn.Close()

	// if we got here, I got through the proxy and connected to myself (I think)

	proxyOK = true
	portOpen = true
	return
}
