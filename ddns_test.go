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

	//"github.com/felixge/fgprof"

	//"github.com/felixge/fgprof"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/miekg/dns"
	"github.com/x186k/ddns5libdns"
	//"github.com/stretchr/testify/require"
)

var ctx = context.Background()

//random normalized ipv4
func randIPv4() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ipRaw := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipRaw, r.Uint32())
	randipaddr := net.IP(ipRaw).String()
	return NormalizeIP(randipaddr, dns.TypeA)
}

//random normalized ipv6
func randIPv6() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ipRaw := make([]byte, 16)
	_, err := r.Read(ipRaw)
	checkPanic(err)
	ipRaw[0] = 0x00 // testing zero fill
	randipaddr := net.IP(ipRaw).String()

	return NormalizeIP(randipaddr, dns.TypeAAAA)
}

func TestDDNSCloudflare(t *testing.T) {
	ddnsutilDebug = true

	token := os.Getenv("CLOUDFLARE_TOKEN")
	if token == "" {
		println("CLOUDFLARE_TOKEN", "is unset, will skip testing cloudflare")
		return
	}
	fqdn := os.Getenv("CLOUDFLARE_TEST_FQDN")
	if fqdn == "" {
		println("CLOUDFLARE_TEST_FQDN", "is unset, will skip testing cloudflare")
		return
	}

	provider := &cloudflare.Provider{APIToken: token}

	testProvider(t, provider, fqdn)

}

func TestDDNS5API(t *testing.T) {
	ddnsutilDebug = true

	//token := strings.Repeat("a", 32)
	fqdn := "test99.ddns5.com"

	provider := &ddns5libdns.Provider{APIToken: ""}

	//ddnsutilDebug = true
	testProvider(t, provider, fqdn)

}

func TestDDNSDuckdnsAPI(t *testing.T) {

	//ctx = httpTrace(ctx)

	ddnsutilDebug = true

	token := os.Getenv("DUCKDNS_TOKEN")
	if token == "" {
		println("DUCKDNS_TOKEN", "is unset, will skip testing duckdns")
		return
	}
	fqdn := os.Getenv("DUCKDNS_TEST_FQDN")
	if fqdn == "" {
		println("DUCKDNS_TEST_FQDN", "is unset, will skip testing duckdns")
		return
	}

	provider := &duckdns.Provider{APIToken: token}

	testProvider(t, provider, fqdn)
}

func testProvider(t *testing.T, provider DDNSProvider, fqdn string) {
	_ = httpTrace // silence warnings about unused
	// turn on tracing
	//ctx = httpTrace(ctx)
	_, zone := splitFQDN(fqdn, 2)

	testRemoveSetWaitFindRemoveFind(t, provider, zone, fqdn, randIPv4(), dns.TypeA)
	testRemoveSetWaitFindRemoveFind(t, provider, zone, fqdn, randIPv6(), dns.TypeAAAA)
	testRemoveSetWaitFindRemoveFind(t, provider, zone, "_acme-challenge."+fqdn, randomHex(10), dns.TypeTXT)
}

func testRemoveSetWaitFindRemoveFind(t *testing.T, provider DDNSProvider, zone string, fqdn string, val string, dnstype uint16) {
	var err error

	err = ddnsRemoveAddrs(ctx, provider, fqdn, 2, dnstype)
	if err != nil {
		t.Error("ddnsRemoveAddrs failed", err)
	}

	err = ddnsSetRecord(ctx, provider, fqdn, 2, val, dnstype)
	if err != nil {
		t.Error("ddnsRemoveAddrs failed", err)
	}

	err = ddnsWaitUntilSet(ctx, fqdn, val, dnstype)
	if err != nil {
		t.Error("Wait failed", err)
	}

	// found, err := ddnsFindAddrs(zone, fqdn, dnstype)
	// if err != nil {
	// 	t.Error("ddnsFindAddrs failed", err)
	// }

	// require.Equal(t, val, found)

	err = ddnsRemoveAddrs(ctx, provider, fqdn, 2, dnstype)
	if err != nil {
		t.Error("ddnsRemoveAddrs failed", err)
	}

	// found, err = ddnsFindAddrs(zone, fqdn, dnstype)
	// if err != nil {
	// 	t.Error("ddnsFindAddrs failed2", err)
	// }

	// require.Equal(t, "", found)
}

func httpTrace(ctx context.Context) context.Context {

	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			//fmt.Printf("Got Conn: %+v\n", connInfo)
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
			//fmt.Printf("DNS Info: %+v\n", dnsInfo)
		},
		ConnectStart: func(network string, addr string) {
			//fmt.Println("ConnectStart:", addr)
		},
		ConnectDone: func(network string, addr string, err error) {
			//fmt.Println("ConnectDone:", addr)
		},
		TLSHandshakeStart: func() {
		},
		// TLSHandshakeDone: func(tls.ConnectionState, error) {
		// },
		WroteHeaderField: func(key string, value []string) {
			switch key {
			case ":path":
				fallthrough
			case ":method":
				fmt.Printf("trace %s %+v\n", key, value)
			}

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

// curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
//                 -H "Authorization: Bearer $CLOUDFLARE_TOKEN" \
//                 -H "Content-Type:application/json"
