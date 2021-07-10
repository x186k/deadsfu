package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	//"github.com/stretchr/testify/assert"
)

func TestProxyDialInvalidOrDownProxy(t *testing.T) {
	const (
		PROXYGOOD = "deadsfu.com:60000"
		PROXYBAD  = "deadsfu.com:6000"
	)

	hostportgood := getMyPublicIpV4().String() + ":80"
	hostportbad := getMyPublicIpV4().String() + ":9999"

	var proxyok, portopen bool

	// uncomment these 5 lines for testing of the working situation, AND open port 80
	// leave this commented out for commited code
	// http.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
	// 	fmt.Fprintf(w, "hello\n")
	// })
	// go func() { panic(http.ListenAndServe(":80", nil)) }()
	// proxyok, portopen = canConnectThroughProxy(PROXYGOOD, hostportgood)
	// assert.Equal(t, true, proxyok)
	// assert.Equal(t, true, portopen)

	proxyok, portopen = canConnectThroughProxy(PROXYGOOD, hostportbad, "tcp4")
	assert.Equal(t, true, proxyok)
	assert.Equal(t, false, portopen)

	proxyok, portopen = canConnectThroughProxy(PROXYBAD, hostportbad, "tcp4")
	assert.Equal(t, false, proxyok)
	assert.Equal(t, false, portopen) //this is false when proxy fails

	proxyok, portopen = canConnectThroughProxy(PROXYBAD, hostportgood, "tcp4")
	assert.Equal(t, false, proxyok)
	assert.Equal(t, false, portopen) //this is false when proxy fails
}
