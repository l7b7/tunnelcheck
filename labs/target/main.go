package main

import (
	"log"
	"net"
	"os"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("lab target listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		log.Printf("accepted one local lab tunnel from %s", conn.RemoteAddr())
		go func(c net.Conn) { defer c.Close(); _, _ = c.Write([]byte("tunnelcheck lab target: connected\n")) }(conn)
	}
}

