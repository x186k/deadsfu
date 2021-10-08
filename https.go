package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

type DDNSUnion interface {
	libdns.RecordAppender
	libdns.RecordDeleter
	libdns.RecordSetter
}

var _ = wrap

func wrap(err error) error {
	_, fileName, fileLine, _ := runtime.Caller(1)
	return fmt.Errorf("at %s:%d %w", filepath.Base(fileName), fileLine, err)
}

func startHttpsListener(ctx context.Context, hostport string, mux *http.ServeMux) {
	var err error

	host, port, err := net.SplitHostPort(hostport)
	checkFatal(err)

	httpsHasCertificate := make(chan bool)
	go reportHttpsReadyness(httpsHasCertificate)

	ca := certmagic.LetsEncryptProductionCA
	if false {
		ca = certmagic.LetsEncryptStagingCA
	}

	mgrTemplate := certmagic.ACMEManager{
		CA:                      ca,
		Email:                   "",
		Agreed:                  true,
		DisableHTTPChallenge:    false,
		DisableTLSALPNChallenge: false,
	}
	magic := certmagic.NewDefault()

	magic.OnEvent = func(s string, i interface{}) {
		_ = i
		switch s {
		// called at time of challenge passing
		case "cert_obtained":
			// elog.Println("Let's Encrypt Certificate Aquired")
			// called every run where cert is found in cache including when the challenge passes
			// since the followed gets called for both obained and found in cache, we use that
		case "cached_managed_cert":
			close(httpsHasCertificate)
			elog.Println("HTTPS READY: Certificate Acquired")
		case "tls_handshake_started":
			//silent
		case "tls_handshake_completed":
			//silent
		default:
			elog.Println("certmagic event:", s) //, i)
		}
	}

	if log.Default().Writer() != io.Discard {
		logger, err := zap.NewDevelopment()
		checkFatal(err)
		mgrTemplate.Logger = logger
	}

	myACME := certmagic.NewACMEManager(magic, mgrTemplate)
	magic.Issuers = []certmagic.Issuer{myACME}

	err = magic.ManageSync(context.Background(), []string{host})
	checkFatal(err)
	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

	go func() {
		time.Sleep(time.Second)
		reportOpenPort(hostport, "tcp4")
	}()
	go func() {
		time.Sleep(time.Second)
		reportOpenPort(hostport, "tcp6")
	}()
	//elog.Printf("%v IS READY", httpsUrl.String())

	ln, err := net.Listen("tcp", ":"+port)
	checkFatal(err)

	if *clusterMode {
		checkFatal(fmt.Errorf("cluster mode not supported with --https-domain"))
	}

	httpsLn := tls.NewListener(ln, tlsConfig)
	checkFatal(err)

	elog.Println("SFU HTTPS IS READY ON", ln.Addr())

	// err = http.Serve(httpsLn, mux)
	// checkFatal(err)
	srv := &http.Server{Handler: mux}
	err = srv.Serve(httpsLn)
	checkFatal(err)
}

// ddnsRegisterIPAddresses will register IP addresses to hostnames
// zone might be duckdns.org
// subname might be server01
func ddnsRegisterIPAddresses(provider DDNSProvider, fqdn string, suffixCount int, addrs []net.IP) {

	//timestr := strconv.FormatInt(time.Now().UnixNano(), 10)
	// ddnsHelper.Present(nil, *ddnsDomain, timestr, dns.TypeTXT)
	// ddnsHelper.Wait(nil, *ddnsDomain, timestr, dns.TypeTXT)
	for _, v := range addrs {

		var dnstype uint16
		var network string

		if v.To4() != nil {
			dnstype = dns.TypeA
			network = "ip4"
		} else {
			dnstype = dns.TypeAAAA
			network = "ip6"
		}

		normalip := NormalizeIP(v.String(), dnstype)

		pubpriv := "Public"
		if IsPrivate(v) {
			pubpriv = "Private"
		}
		log.Printf("Registering DNS %v %v %v %v IP-addr", fqdn, dns.TypeToString[dnstype], normalip, pubpriv)

		//log.Println("DDNS setting", fqdn, suffixCount, normalip, dns.TypeToString[dnstype])
		err := ddnsSetRecord(context.Background(), provider, fqdn, suffixCount, normalip, dnstype)
		checkFatal(err)

		log.Println("DDNS waiting for propagation", fqdn, suffixCount, normalip, dns.TypeToString[dnstype])
		err = ddnsWaitUntilSet(context.Background(), fqdn, normalip, dnstype)
		checkFatal(err)

		elog.Printf("IPAddr %v DNS registered as %v", v, fqdn)

		localDNSIP, err := net.ResolveIPAddr(network, fqdn)
		checkFatal(err)

		log.Println("net.ResolveIPAddr", network, fqdn, localDNSIP.String())

		if !localDNSIP.IP.Equal(v) {
			checkFatal(fmt.Errorf("Inconsistent DNS, please use another name"))
		}

		//log.Println("DDNS propagation complete", fqdn, suffixCount, normalip)
	}
}

// remove with go 1.17 arrival
func IsPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Following RFC 4193, Section 3. Local IPv6 Unicast Addresses which says:
		//   The Internet Assigned Numbers Authority (IANA) has reserved the
		//   following three blocks of the IPv4 address space for private internets:
		//     10.0.0.0        -   10.255.255.255  (10/8 prefix)
		//     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		//     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Following RFC 4193, Section 3. Private Address Space which says:
	//   The Internet Assigned Numbers Authority (IANA) has reserved the
	//   following block of the IPv6 address space for local internets:
	//     FC00::  -  FDFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF (FC00::/7 prefix)
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

func getMyPublicIpV4() (net.IP, error) {
	var publicmyip []string = []string{"https://api.ipify.org", "http://checkip.amazonaws.com/"}

	client := http.Client{
		Timeout: 3 * time.Second,
	}
	for _, v := range publicmyip {
		res, err := client.Get(v)
		if err != nil {
			return nil, err
		}
		ipraw, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(string(ipraw))
		if ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("Unable to query the internet for my public ipv4")
}

func getDefaultRouteInterfaceAddresses() ([]net.IP, error) {

	// we don't send a single packets to these hosts
	// but we use their addresses to discover our interface to get to the Internet
	// These addresses could be almost anything

	var ipaddrs []net.IP

	addr, err := getDefRouteIntfAddrIPv4()
	if err != nil {
		return nil, err
	}
	ipaddrs = append(ipaddrs, addr)

	addr, err = getDefRouteIntfAddrIPv6()
	if err != nil {
		return nil, err
	}
	ipaddrs = append(ipaddrs, addr)

	return ipaddrs, nil
}

func reportHttpsReadyness(ready chan bool) {
	t0 := time.Now()
	ticker := time.NewTicker(time.Second * 5).C
	for {
		select {
		case t1 := <-ticker:

			n := int(t1.Sub(t0).Seconds())

			elog.Printf("HTTPS NOT READY: Waited %d seconds.", n)

			if n >= 30 {
				elog.Printf("No HTTPS certificate: Stopping status messages. Will update if aquired.")
				return
			}

		case <-ready:
			return
		}
	}
}

func reportOpenPort(hostport, network string) {

	tcpaddr, err := net.ResolveTCPAddr(network, hostport)
	if err != nil {
		// not fatal
		// if there is no ipv6 (or v4) address, continue on
		return
	}

	if IsPrivate(tcpaddr.IP) {
		elog.Printf("IPAddr %v IS PRIVATE IP, not Internet reachable. RFC 1918, 4193", tcpaddr.IP.String())
		return
	}

	// use default proxy addr
	proxyok, iamopen := canConnectThroughProxy("", tcpaddr, network)

	if !proxyok {
		//just be silent about proxy errors, Cameron didn't pay his bill
		return
	}

	if iamopen {
		elog.Printf("IPAddr %v port:%v IS OPEN from Internet", tcpaddr.IP.String(), tcpaddr.Port)
	} else {
		elog.Printf("IPAddr %v port:%v IS NOT OPEN from Internet", tcpaddr.IP.String(), tcpaddr.Port)
	}
}

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
