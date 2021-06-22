package main

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/net/proxy"
)


func canConnectThroughProxy(proxyaddr string, server string) (ok bool, err error) {

	const (	
		baseDialerTimeout  = 5 * time.Second
		proxyDialerTimeout = 5 * time.Second
	)

	baseDialer := &net.Dialer{
		Timeout:       baseDialerTimeout,
		Deadline:      time.Time{},
		FallbackDelay: -1,
	}

	dialer, err := proxy.SOCKS5("tcp", proxyaddr, nil, baseDialer)
	if err != nil {
		return
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		err = errors.New("bad")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyDialerTimeout)
	_ = cancel
	conn, err := contextDialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return
	}

	err = conn.Close()
	if err != nil {
		return
	}

	ok = true
	return
}
