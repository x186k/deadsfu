package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"time"

	"github.com/cameronelliott/redislock"
	redislockx "github.com/cameronelliott/redislock/examples/redigo/redisclient"
	redigo "github.com/gomodule/redigo/redis"
)

var (
	redisPool   *redigo.Pool
	redisLocker *redislock.Client
)

var _ = newRedisPoolFiles

func newRedisPoolFiles() {

	crt, err := ioutil.ReadFile("tests/tls/redis.crt")
	checkFatal(err)
	key, err := ioutil.ReadFile("tests/tls/redis.key")
	checkFatal(err)
	cacrt, err := ioutil.ReadFile("tests/tls/ca.crt")
	checkFatal(err)

	newRedisPoolCerts(crt, key, cacrt, true)

}

func checkRedis() {
	rconn := redisPool.Get()
	defer rconn.Close()

	pong, err := redigo.String(rconn.Do("ping"))
	if err != nil {
		elog.Fatalln("ping fail", err)
	}

	if pong != "PONG" {
		elog.Fatalln("redis fail, expect: PONG, got:", pong)
	}

	elog.Println("redis ping is good!")
}

func newRedisPoolCerts(crt, key, cacrt []byte, redisTls bool) {

	rurl := os.Getenv("REDIS_URL")
	if rurl == "" {
		checkFatal(fmt.Errorf("REDIS_URL must be set for cluster mode"))
	}

	var do = make([]redigo.DialOption, 0)

	uu, err := url.Parse(rurl)
	checkFatal(err)
	_ = uu

	if redisTls {
		cert, err := tls.X509KeyPair(crt, key)
		checkFatal(err)

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cacrt)

		//println(99,uu.Hostname())

		tlsconf := &tls.Config{
			ServerName:         uu.Hostname(),
			Certificates:       []tls.Certificate{cert},
			RootCAs:            pool,
			InsecureSkipVerify: false,
		}

		//do = append(do, redigo.DialUseTLS(true)) //overwritten by DialUrlContext!
		//do = append(do, redigo.DialTLSSkipVerify(true)) // ignored when providing tlsconf
		do = append(do, redigo.DialTLSConfig(tlsconf))

	}

	redisPool = &redigo.Pool{
		MaxIdle:     3,
		IdleTimeout: 5 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		DialContext: func(ctx context.Context) (redigo.Conn, error) {
			//return redigo.DialContext(ctx, "tcp", uu.Hostname()+":6379", do...)
			return redigo.DialURLContext(ctx, rurl, do...)
		},
	}

	// threadsafe
	redisLocker = redislock.New(redislockx.NewRedisLockClient(redisPool))
}
