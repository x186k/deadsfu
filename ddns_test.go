package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"testing"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/miekg/dns"

	//"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/require"
)

func TestDDNS5TokenMaker(t *testing.T) {

	k := ddns5com_Token()
	require.Equal(t, 32, len(k))

	kk := ddns5com_Token()
	require.Equal(t, k, kk)

	_ = os.Remove("/tmp/ddns5.txt")

	kkk := ddns5com_Token()
	require.Equal(t, 32, len(kkk))

	require.NotEqual(t, k, kkk)

}

var cloudflareToken = os.Getenv("CLOUDFLARE_TOKEN")
var libdnsProvider = &cloudflare.Provider{APIToken: cloudflareToken}

var ctx = context.Background()

// Create and seed the generator.
// Typically a non-fixed seed should be used, such as time.Now().UnixNano().
// Using a fixed seed will produce the same output on every run.

func init() {
	if cloudflareToken == "" {
		panic("no token")
	}

	//Debug = true
}

func TestARecord(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ipRaw := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipRaw, r.Uint32())
	randipaddr := net.IP(ipRaw).String()
	fmt.Println("Random IPv4 unnorm: ", randipaddr)
	fmt.Println("Random IPv4 norm: ", NormalizeIP(randipaddr, dns.TypeA))

	fqdn := "_testipv4.sfu1.com"

	err := ddnsSetRecord(ctx, libdnsProvider, fqdn, 2, randipaddr, dns.TypeA)
	checkPanic(err)

	err = ddnsWaitUntilSet(ctx, libdnsProvider, fqdn, randipaddr, dns.TypeA)
	if err != nil {
		t.Error("Wait failed", err)
	}
}
func TestAAAARecord(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ipRaw := make([]byte, 16)
	_, err := r.Read(ipRaw)
	checkPanic(err)
	ipRaw[0] = 0x00 // testing zero fill
	randipaddr := net.IP(ipRaw).String()
	fmt.Println("Random IPv6 unnorm: ", randipaddr)
	fmt.Println("Random IPv6 norm: ", NormalizeIP(randipaddr, dns.TypeAAAA))

	var dnsname = "_testipv6.sfu1.com"

	err = ddnsSetRecord(ctx, libdnsProvider, dnsname, 2, randipaddr, dns.TypeAAAA)
	checkPanic(err)

	err = ddnsWaitUntilSet(ctx, libdnsProvider, dnsname, randipaddr, dns.TypeAAAA)
	if err != nil {
		t.Error("Wait failed", err)
	}
}

func TestTXTRecord(t *testing.T) {
	var fqdn = "_testtxt.sfu1.com"
	var val = "xyzzy"

	checkPanic(ddnsRemoveAddrs(ctx, libdnsProvider, fqdn, 2, dns.TypeTXT))

	err := ddnsSetRecord(ctx, libdnsProvider, fqdn, 2, val, dns.TypeTXT)
	checkPanic(err)

	err = ddnsWaitUntilSet(ctx, libdnsProvider, fqdn, val, dns.TypeTXT)
	if err != nil {
		t.Error("Wait failed", err)
	}
}

func httpTrace(ctx context.Context) context.Context {

	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("Got Conn: %+v\n", connInfo)
		},
		PutIdleConn: func(err error) {
		},
		GotFirstResponseByte: func() {
		},
		Got100Continue: func() {
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			return nil
		},
		DNSStart: func(httptrace.DNSStartInfo) {
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			fmt.Printf("DNS Info: %+v\n", dnsInfo)
		},
		ConnectStart: func(network string, addr string) {
			fmt.Println("ConnectStart:", addr)
		},
		ConnectDone: func(network string, addr string, err error) {
			fmt.Println("ConnectDone:", addr)
		},
		TLSHandshakeStart: func() {
		},
		// TLSHandshakeDone: func(tls.ConnectionState, error) {
		// },
		WroteHeaderField: func(key string, value []string) {
			fmt.Printf("WroteHeaderField: %s %+v\n", key, value)
		},
		WroteHeaders: func() {
		},
		Wait100Continue: func() {
		},
		WroteRequest: func(xx httptrace.WroteRequestInfo) {
			fmt.Printf("WroteRequestInfo Info: %+v\n", xx)
		},
	}

	return httptrace.WithClientTrace(ctx, trace)
	//req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

func TestDel(t *testing.T) {
	var fqdn = "_testtxt.sfu1.com"

	ctx = httpTrace(ctx)

	checkPanic(ddnsRemoveAddrs(ctx, libdnsProvider, fqdn, 2, dns.TypeTXT))

}

// curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
//                 -H "Authorization: Bearer $CLOUDFLARE_TOKEN" \
//                 -H "Content-Type:application/json"
