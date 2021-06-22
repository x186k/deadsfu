package main

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	//"github.com/stretchr/testify/assert"
)

func TestProxyDialInvalidOrDownProxy(t *testing.T) {
	const (
		PROXY_ADDR    = "socks5-callback-server.com:60000"
		BADPROXY_ADDR = "socks5-callback-server.com:6000"
		URL           = "http://google.com"
		SERVER        = "google.com:80"
		BADSERVER        = "google.com:80"
	)

	_, err := canConnectThroughProxy(BADPROXY_ADDR, SERVER)
	assert.Contains(t, err.Error(), "timeout")

	_, err = canConnectThroughProxy(PROXY_ADDR, SERVER)
	assert.Equal(t, true, errors.Is(err, io.EOF))

	_, err = canConnectThroughProxy(PROXY_ADDR, BADSERVER)
	assert.Equal(t, true, errors.Is(err, io.EOF))


	// this could be the test case where you get ok==true
	// to hard to test!
	// ok, err := canConnectThroughProxy(PROXY_ADDR, SERVER)
	// assert.Equal(t, err, nil)
	// assert.Equal(t, ok, true)

	// fmt.Printf("%#v\n", ok)
	// fmt.Printf("%#v\n", err)
	// fmt.Printf("%v\n", err.Error())

}
