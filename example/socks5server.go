package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/pinkd/socks5"
)

func main() {
	portP := flag.Uint("p", 1080, "listen port")
	addrP := flag.String("l", "127.0.0.1", "listen addr")

	flag.Parse()

	port := int(*portP)
	addr := *addrP
	conf := &socks5.Config{
		BindIP:   net.ParseIP(addr),
		BindPort: port,
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	addr = fmt.Sprintf("%s:%d", addr, port)
	fmt.Printf("listen on %s\n", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		panic(err)
	}
}
