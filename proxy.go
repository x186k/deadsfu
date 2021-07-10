package main

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// canConnectThroughProxy will attempt to use a socks5 proxy to see if
// my ports are open from the Internet.
// if my proxy is running, then this can provide useful information
// about when trying to run a public server
// if the proxy appears gone, this function will stay silent, and return proxyOK=false
// pass nil to use default proxy
func canConnectThroughProxy(proxyaddr string, hostport string, network string) (proxyOK bool, portOpen bool) {
	const (
		baseDialerTimeout  = 3 * time.Second
		proxyDialerTimeout = 3 * time.Second
		SOCKS5PROXY        = "deadsfu.com:60000"
	)

	if proxyaddr == "" {
		proxyaddr = SOCKS5PROXY
	}

	baseDialer := &net.Dialer{
		Timeout: baseDialerTimeout,
		//Deadline: time.Time{},
		//FallbackDelay: -1,
	}

	// always get to proxy using ipv4, more reliable for this test
	dialer, err := proxy.SOCKS5("tcp4", proxyaddr, nil, baseDialer)
	if err != nil {
		return
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		log.Println("cannot deref dialer")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyDialerTimeout)
	_ = cancel

	// we ask the proxy for the given network
	conn, err := contextDialer.DialContext(ctx, network, hostport)
	if err != nil {
		println(888, err.Error())
		readtcp := strings.Contains(err.Error(), " read tcp ")
		dialtcp := strings.Contains(err.Error(), " dial tcp ")
		iotimeout := strings.Contains(err.Error(), "i/o timeout")

		if iotimeout && readtcp {
			proxyOK = true
			portOpen = false
		} else if iotimeout && dialtcp {
			proxyOK = false
			portOpen = false
		}
		// sometime else is going on, but we are going to stay silent
		// the user isn't going to know what to do

		return
	}
	conn.Close()

	// if we got here, I got through the proxy and connected to myself

	proxyOK = true
	portOpen = true
	return
}
