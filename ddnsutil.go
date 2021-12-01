package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// Copyright 2015 Matthew Holt
// Copyright 2021 Cameron Elliott

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

// DDNSProvider defines the set of operations required for
// ACME challenges. A DNS provider must be able to append and
// delete records in order to solve ACME challenges. Find one
// you can use at https://github.com/libdns. If your provider
// isn't implemented yet, feel free to contribute!
type DDNSProvider interface {
	//libdns.RecordAppender
	libdns.RecordDeleter
	libdns.RecordSetter
}

// ddnsWaitUntilSet blocks until the  record created in Present() appears in
// authoritative lookups, i.e. until it has propagated, or until
// timeout, whichever is first.
func ddnsWaitUntilSet(ctx context.Context, dnsName string, dnsVal string, dnstype uint16) error {
	// dnsName := challenge.DNS01TXTRecordName()
	// keyAuth := challenge.DNS01KeyAuthorization()

	dnsVal = NormalizeIP(dnsVal, dnstype)

	//yup yuck

	// you could change timeout here
	timeout := 2 * time.Minute

	const interval = 2 * time.Second

	// you can change the nameservers here
	resolvers := recursiveNameservers([]string{})

	dbgDdns.Println("ddnsWaitUntilSet resolvers", resolvers)

	var err error
	start := time.Now()
	for time.Since(start) < timeout {
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return ctx.Err()
		}
		var val string
		val, _ = checkDNSPropagation(dnsName, resolvers, dnstype)
		// if err != nil {
		// 	return fmt.Errorf("checking DNS propagation of %s: %w", dnsName, err)
		// }

		dbgDdns.Printf("wait()  want:%v got:%v from checkDNSPropagation()", dnsVal, val)

		if val == dnsVal {
			return nil
		}
	}

	return fmt.Errorf("timed out waiting for record to fully propagate; verify DNS provider configuration is correct - last error: %v", err)
}

// splitFQDN("foo.bar.com",2)
// will return ("foo","bar.com")
func splitFQDN(fqdn string, suffixCount int) (prefix string, zone string) {
	split := dns.SplitDomainName(fqdn)
	ix := len(split) - suffixCount
	prefix = strings.Join(split[0:ix], ".")
	zone = strings.Join(split[ix:], ".")
	return
}

// ddnsSetRecord creates the DNS  record for the given ACME challenge.
func ddnsSetRecord(ctx context.Context, provider DDNSProvider, fqdn string, suffixCount int, dnsVal string, dnstype uint16) error {
	// dnsName := challenge.DNS01TXTRecordName()
	// keyAuth := challenge.DNS01KeyAuthorization()

	prefix, zone := splitFQDN(fqdn, suffixCount)

	// NO!
	// We can take TXT also
	// dnsVal = NormalizeIP(dnsVal, dnstype)

	recstr := dnstype2String(dnstype)

	rec := libdns.Record{
		Type:  recstr,
		Name:  prefix,
		Value: dnsVal,
		TTL:   time.Second * 0,
	}

	// zone, err := findZoneByFQDN(dnsName, recursiveNameservers([]string{}))
	// if err != nil {
	// 	return fmt.Errorf("could not determine zone for domain %q: %v", dnsName, err)
	// }

	results, err := provider.SetRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		return fmt.Errorf("adding temporary record for zone %s: %w", zone, err)
	}
	if len(results) != 1 {
		return fmt.Errorf("expected one record, got %d: %v", len(results), results)
	}

	return nil
}

func dnstype2String(dnstype uint16) string {

	recstr := ""
	switch dnstype {
	case dns.TypeA:
		recstr = "A"
	case dns.TypeAAAA:
		recstr = "AAAA"
	case dns.TypeTXT:
		recstr = "TXT"
	default:
		panic("unsupported record type, easy to fix")
	}
	return recstr
}

var _ = ddnsRemoveAddrs

// ddnsRemoveAddrs deletes the DNS record created in Present().
func ddnsRemoveAddrs(ctx context.Context, provider DDNSProvider, fqdn string, suffixCount int, dnstype uint16) error {
	//dnsName := challenge.DNS01TXTRecordName()

	fqdn = strings.TrimSuffix(fqdn, ".")
	recstr := dnstype2String(dnstype)
	prefix, zone := splitFQDN(fqdn, suffixCount)

	rec := libdns.Record{
		Type: recstr,
		Name: prefix,
		//Value: dnsVal,
		TTL: time.Second * 0,
	}

	// clean up the record
	_, err := provider.DeleteRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		return fmt.Errorf("deleting temporary record for zone %s: %w", zone, err)
	}

	return nil
}

// NormalizeIP may not have been needed!
func NormalizeIP(ipstr string, dnstype uint16) string {

	switch dnstype {
	case dns.TypeA:
		ip := net.ParseIP(ipstr)
		return ip.String()
	case dns.TypeAAAA:
		ip := net.ParseIP(ipstr)
		return strings.ToLower(ip.String())
		//return strings.ToLower(fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		//	ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]))
	case dns.TypeTXT:
		return ipstr
	default:
		panic("A or AAAA only")
	}
}
