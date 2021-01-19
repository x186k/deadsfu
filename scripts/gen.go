// inspired
// https://blog.carlmjohnson.net/post/2016-11-27-how-to-use-go-generate/

// +build ignore

// go generate
package main

import (
	//"fmt"
	"io/ioutil"
	//"strconv"

	//"fmt"

	//"io/ioutil"

	"net/http"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

const assetsBaseUrl= "https://github.com/x186k/x186k-sfu-assets/raw/main/"

func main() {
	url:=assetsBaseUrl+"idle.screen.h264.pcapng"

	// a, err := ioutil.ReadFile("html/index.html")
	// die(err)
	// fmt.Println(len(a))

	rsp, err := http.Get(url)
	check(err)
	defer rsp.Body.Close()


	// for k,v:=range rsp.Header{
	// 	fmt.Println(k,v)
	// }
	// XXX really should check md5 and filelen, and avoid download if same

	// len,err:=strconv.Atoi(rsp.Header.Get("Content-Length"))
	// check(err)

	// if len!=

	raw, err := ioutil.ReadAll(rsp.Body)
	check(err)

	err = ioutil.WriteFile("embed/idle.screen.h264.pcapng", raw, 0777)
	check(err)

}
