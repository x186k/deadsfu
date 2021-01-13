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

func main() {
	const url = "https://github.com/x186k/x186k-sfu-assets/raw/main/waiting.h264.rtp"

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

	err = ioutil.WriteFile("downloaded/waiting.h264.rtp", raw, 0777)
	check(err)

}
