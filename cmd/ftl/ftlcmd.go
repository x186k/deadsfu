package main

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"

	"github.com/x186k/deadsfu/ftl"
)

func checkFatal(err error) {
	if err != nil {
		_, fileName, fileLine, _ := runtime.Caller(1)

		log.Fatalf("FATAL %s:%d %v", filepath.Base(fileName), fileLine, err)
	}
}

func main() {
	conn, _, err := ftl.FtlServer("", "8084","")
	checkFatal(err)
	

	i:=0
	buf := make([]byte, 2000)
	for {
		_, err := conn.Read(buf)
		checkFatal(err)
		i++
		fmt.Printf("num read %v     \r",i)
	}
}
