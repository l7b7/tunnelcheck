package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestCanonicalTarget(t *testing.T) {
	got, err := canonicalTarget("127.0.0.1:8443")
	if err != nil || got != "127.0.0.1:8443" {
		t.Fatalf("canonicalTarget() = %q, %v", got, err)
	}
	for _, bad := range []string{"host", "host:0", "host:65536", "host:80/path", "user@host:80"} {
		if _, err := canonicalTarget(bad); err == nil {
			t.Errorf("canonicalTarget(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestHTTP1ConnectAcceptedWithoutTunnelPayload(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan string, 1)
	go func() {
		defer server.Close()
		line, _ := bufio.NewReader(server).ReadString('\n')
		done <- line
		_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	status, outcome, detail, err := probeH1(client, "127.0.0.1:8443")
	_ = client.Close()
	if err != nil || status != 200 || outcome != "tunnel_accepted" || !strings.Contains(detail, "no payload") {
		t.Fatalf("unexpected H1 result: %d %s %q %v", status, outcome, detail, err)
	}
	if got := <-done; got != "CONNECT 127.0.0.1:8443 HTTP/1.1\r\n" {
		t.Fatalf("request line = %q", got)
	}
}

func TestHTTP2ConnectAcceptedOnItsStream(t *testing.T) {
	client, server := net.Pipe()
	serverResult := make(chan error, 1)
	go func() {
		defer server.Close()
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			serverResult <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		fr := http2.NewFramer(server, server)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		first, err := fr.ReadFrame()
		if err != nil {
			serverResult <- err
			return
		}
		if _, ok := first.(*http2.SettingsFrame); !ok {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		if err := fr.WriteSettings(); err != nil {
			serverResult <- err
			return
		}
		ack, err := fr.ReadFrame()
		if err != nil {
			serverResult <- err
			return
		}
		if f, ok := ack.(*http2.SettingsFrame); !ok || !f.IsAck() {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		req, err := fr.ReadFrame()
		if err != nil {
			serverResult <- err
			return
		}
		h, ok := req.(*http2.MetaHeadersFrame)
		if !ok || h.StreamID != 1 {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: []byte{0x88}}); err != nil {
			serverResult <- err
			return
		}
		serverResult <- nil
	}()
	status, outcome, detail, err := probeH2(client, "127.0.0.1:8443")
	_ = client.Close()
	if err != nil || status != 200 || outcome != "tunnel_accepted" || !strings.Contains(detail, "no DATA") {
		t.Fatalf("unexpected H2 result: %d %s %q %v", status, outcome, detail, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("mock HTTP/2 proxy: %v", err)
	}
}

