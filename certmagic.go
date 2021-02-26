// Copyright 2015 Matthew Holt
// Some portions: Copyright 2021 Cameron Elliott
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

var (
	httpLn, httpsLn net.Listener
	lnMu            sync.Mutex
	httpWg          sync.WaitGroup
)
var (
	HTTPPort  = 80
	HTTPSPort = 443
)

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // OK; probably had no port to begin with
	}
	return host
}

func httpRedirectHandler(w http.ResponseWriter, r *http.Request) {
	toURL := "https://"

	// since we redirect to the standard HTTPS port, we
	// do not need to include it in the redirect URL
	requestHost := hostOnly(r.Host)

	toURL += requestHost
	toURL += r.URL.RequestURI()

	// get rid of this disgusting unencrypted HTTP connection 🤢
	w.Header().Set("Connection", "close")

	http.Redirect(w, r, toURL, http.StatusMovedPermanently)
}

/*
I forget exactly why the heck I thought
I needed to copy this out of the certmagic library.
I think it may have been something about
wanting to retrieve the url/port/address bound
in order to share it with the user.
but I am not 100% on that.
figured it out!!!

Changes from original:
1. drop required TLS version in order to work with OBS studio
2. instead of dial-back http challenge, we changed to the DNS
challenge using duck dns


*/

func HTTPS(domainNames []string, mux http.Handler, obscompat bool) error {

	if mux == nil {
		mux = http.DefaultServeMux
	}

	certmagic.DefaultACME.Agreed = true
	cfg := certmagic.NewDefault()

	err := cfg.ManageSync(domainNames)
	if err != nil {
		return err
	}

	httpWg.Add(1)
	defer httpWg.Done()

	// if we haven't made listeners yet, do so now,
	// and clean them up when all servers are done
	lnMu.Lock()
	if httpLn == nil && httpsLn == nil {
		httpLn, err = net.Listen("tcp", fmt.Sprintf(":%d", HTTPPort))
		if err != nil {
			lnMu.Unlock()
			return err
		}

		tlsConfig := cfg.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
		/// XXX ro work with OBS studio for now
		if obscompat {
			tlsConfig.MinVersion = 0
		}
	

		httpsLn, err = tls.Listen("tcp", fmt.Sprintf(":%d", HTTPSPort), tlsConfig)
		if err != nil {
			httpLn.Close()
			httpLn = nil
			lnMu.Unlock()
			return err
		}

		go func() {
			httpWg.Wait()
			lnMu.Lock()
			httpLn.Close()
			httpsLn.Close()
			lnMu.Unlock()
		}()
	}
	hln, hsln := httpLn, httpsLn
	lnMu.Unlock()

	// create HTTP/S servers that are configured
	// with sane default timeouts and appropriate
	// handlers (the HTTP server solves the HTTP
	// challenge and issues redirects to HTTPS,
	// while the HTTPS server simply serves the
	// user's handler)
	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	if am, ok := cfg.Issuer.(*certmagic.ACMEManager); ok {
		httpServer.Handler = am.HTTPChallengeHandler(http.HandlerFunc(httpRedirectHandler))
	}
	httpsServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		Handler:           mux,
	}

	fmt.Printf("%v Serving HTTP->HTTPS on %s and %s\n",
		domainNames, hln.Addr(), hsln.Addr())

	go func() {
		err := httpServer.Serve(hln)
		checkPanic(err)
	}()
	return httpsServer.Serve(hsln)
}
