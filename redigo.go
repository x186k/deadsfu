// Copyright 2012 Gary Burd
//
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"

	"github.com/gomodule/redigo/redis"
)

// DialURL connects to a Redis server at the given URL using the Redis
// URI scheme. URLs should follow the draft IANA specification for the
// scheme (https://www.iana.org/assignments/uri-schemes/prov/redis).
func DialURLContext(ctx context.Context, rawurl string, options ...redis.DialOption) (redis.Conn, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	var pathDBRegexp = regexp.MustCompile(`/(\d*)\z`)

	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("invalid redis URL scheme: %s", u.Scheme)
	}

	if u.Opaque != "" {
		return nil, fmt.Errorf("invalid redis URL, url is opaque: %s", rawurl)
	}

	// As per the IANA draft spec, the host defaults to localhost and
	// the port defaults to 6379.
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// assume port is missing
		host = u.Host
		port = "6379"
	}
	if host == "" {
		host = "localhost"
	}
	address := net.JoinHostPort(host, port)

	if u.User != nil {
		password, isSet := u.User.Password()
		username := u.User.Username()
		if isSet {
			if username != "" {
				// ACL
				options = append(options, redis.DialUsername(username), redis.DialPassword(password))
			} else {
				// requirepass - user-info username:password with blank username
				options = append(options, redis.DialPassword(password))
			}
		} else if username != "" {
			// requirepass - redis-cli compatibility which treats as single arg in user-info as a password
			options = append(options, redis.DialPassword(username))
		}
	}

	match := pathDBRegexp.FindStringSubmatch(u.Path)
	if len(match) == 2 {
		db := 0
		if len(match[1]) > 0 {
			db, err = strconv.Atoi(match[1])
			if err != nil {
				return nil, fmt.Errorf("invalid database: %s", u.Path[1:])
			}
		}
		if db != 0 {
			options = append(options, redis.DialDatabase(db))
		}
	} else if u.Path != "" {
		return nil, fmt.Errorf("invalid database: %s", u.Path[1:])
	}

	options = append(options, redis.DialUseTLS(u.Scheme == "rediss"))

	return redis.DialContext(ctx, "tcp", address, options...)
}
