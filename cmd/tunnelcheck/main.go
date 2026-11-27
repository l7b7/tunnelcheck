package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type result struct {
	Tool       string    `json:"tool"`
	Protocol   string    `json:"protocol"`
	Proxy      string    `json:"proxy"`
	Target     string    `json:"target"`
	Outcome    string    `json:"outcome"`
	Status     int       `json:"status,omitempty"`
	Detail     string    `json:"detail"`
	DurationMS int64     `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp_utc"`
}

func main() {
	proxyArg := flag.String("proxy", "", "proxy URL (http://host:port or https://host:port)")
	targetArg := flag.String("target", "", "one host:port to check")
	authorized := flag.String("authorized-target", "", "must exactly match -target; confirms this single target is in scope")
	protocol := flag.String("protocol", "h1", "CONNECT protocol: h1 or h2")
	timeout := flag.Duration("timeout", 5*time.Second, "connection and response timeout")
	caFile := flag.String("ca-file", "", "additional PEM CA certificate for a local proxy; verification remains enabled")
	jsonOut := flag.Bool("json", false, "print one JSON result")
	flag.Parse()
	if *proxyArg == "" || *targetArg == "" || *authorized == "" {
		fmt.Fprintln(os.Stderr, "Usage: tunnelcheck -proxy URL -target host:port -authorized-target host:port [-protocol h1|h2] [-json]")
		fmt.Fprintln(os.Stderr, "Safety: one target per run; -authorized-target must exactly match -target.")
		os.Exit(2)
	}

	proxyURL, err := url.Parse(*proxyArg)
	if err != nil || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") || proxyURL.Hostname() == "" || proxyURL.Port() == "" || proxyURL.User != nil || (proxyURL.Path != "" && proxyURL.Path != "/") || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		fatal("proxy must be an http(s) URL with an explicit port and no embedded credentials")
	}
	target, err := canonicalTarget(*targetArg)
	if err != nil || target != *authorized {
		fatal("target must be valid host:port and exactly match -authorized-target")
	}
	if *protocol != "h1" && *protocol != "h2" {
		fatal("-protocol must be h1 or h2")
	}
	if *protocol == "h2" && proxyURL.Scheme != "https" {
		fatal("HTTP/2 mode requires an https:// proxy with TLS ALPN h2")
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		fatal("-timeout must be between 1s and 30s")
	}

	var roots *x509.CertPool
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fatal("could not read -ca-file")
		}
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			fatal("-ca-file contains no valid PEM certificates")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	start := time.Now()
	status, outcome, detail, probeErr := probe(ctx, proxyURL, target, *protocol, roots)
	if probeErr != nil && outcome == "error" {
		detail = probeErr.Error()
	}
	r := result{Tool: "tunnelcheck", Protocol: *protocol, Proxy: proxyURL.Redacted(), Target: target, Outcome: outcome, Status: status, Detail: detail, DurationMS: time.Since(start).Milliseconds(), Timestamp: time.Now().UTC()}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(r)
	} else {
		fmt.Printf("Protocol: %s\nProxy: %s\nTarget: %s\nOutcome: %s\n", r.Protocol, r.Proxy, r.Target, r.Outcome)
		if r.Status != 0 {
			fmt.Printf("Status: %d\n", r.Status)
		}
		fmt.Printf("Detail: %s\nDuration: %d ms\n", r.Detail, r.DurationMS)
	}
	if outcome == "tunnel_accepted" {
		os.Exit(0)
	}
	if outcome == "tunnel_rejected" {
		os.Exit(1)
	}
	os.Exit(2)
}

func fatal(message string) { fmt.Fprintln(os.Stderr, "tunnelcheck:", message); os.Exit(2) }

func canonicalTarget(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return "", errors.New("expected host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("port must be 1..65535")
	}
	if strings.ContainsAny(host, " \t\r\n/\\@") {
		return "", errors.New("invalid host")
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(n)), nil
}

func probe(ctx context.Context, proxy *url.URL, target, protocol string, roots *x509.CertPool) (int, string, string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Hostname(), proxy.Port()))
	if err != nil {
		return 0, "error", "could not connect to proxy", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadlineFrom(ctx)))
	if proxy.Scheme == "https" {
		alpn := "http/1.1"
		if protocol == "h2" {
			alpn = "h2"
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxy.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{alpn}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, "error", "TLS handshake failed; certificate verification is enabled", err
		}
		if tlsConn.ConnectionState().NegotiatedProtocol != alpn {
			return 0, "error", "proxy did not negotiate the requested ALPN protocol", errors.New("ALPN mismatch")
		}
		conn = tlsConn
	}
	if protocol == "h1" {
		return probeH1(conn, target)
	}
	return probeH2(conn, target)
}

func deadlineFrom(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return 5 * time.Second
}

func probeH1(conn net.Conn, target string) (int, string, string, error) {
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", target, target); err != nil {
		return 0, "error", "failed to send CONNECT request", err
	}
	resp, err := httpReadStatus(bufio.NewReader(conn))
	if err != nil {
		return 0, "error", "invalid or missing HTTP/1 response", err
	}
	if resp >= 200 && resp < 300 {
		return resp, "tunnel_accepted", "proxy accepted CONNECT; no payload was sent", nil
	}
	return resp, "tunnel_rejected", "proxy did not accept CONNECT", nil
}

func httpReadStatus(r *bufio.Reader) (int, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return 0, errors.New("not an HTTP/1 status line")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	return status, nil
}

func probeH2(conn net.Conn, target string) (int, string, string, error) {
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return 0, "error", "failed to send HTTP/2 preface", err
	}
	if err := fr.WriteSettings(); err != nil {
		return 0, "error", "failed to send HTTP/2 SETTINGS", err
	}
	// Require the peer's initial SETTINGS and acknowledge it before opening a stream.
	settingsReceived := false
	for i := 0; i < 8; i++ {
		f, err := fr.ReadFrame()
		if err != nil {
			return 0, "error", "HTTP/2 settings handshake failed", err
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				return 0, "error", "failed to acknowledge SETTINGS", err
			}
			settingsReceived = true
			break
		}
	}
	if !settingsReceived {
		return 0, "error", "proxy did not send initial HTTP/2 SETTINGS", nil
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, hf := range []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: target}} {
		if err := enc.WriteField(hf); err != nil {
			return 0, "error", "failed to encode CONNECT headers", err
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false, BlockFragment: block.Bytes()}); err != nil {
		return 0, "error", "failed to send HTTP/2 CONNECT", err
	}
	for i := 0; i < 32; i++ {
		f, err := fr.ReadFrame()
		if err != nil {
			return 0, "error", "no usable HTTP/2 response", err
		}
		switch frame := f.(type) {
		case *http2.MetaHeadersFrame:
			if frame.StreamID != 1 {
				continue
			}
			for _, field := range frame.Fields {
				if field.Name == ":status" {
					code, _ := strconv.Atoi(field.Value)
					if code >= 200 && code < 300 {
						return code, "tunnel_accepted", "proxy accepted CONNECT; no DATA payload was sent", nil
					}
					return code, "tunnel_rejected", "proxy did not accept CONNECT", nil
				}
			}
		case *http2.RSTStreamFrame:
			if frame.StreamID == 1 {
				return 0, "tunnel_rejected", "proxy reset the CONNECT stream: " + frame.ErrCode.String(), nil
			}
		case *http2.GoAwayFrame:
			return 0, "error", "proxy closed the HTTP/2 connection with GOAWAY", nil
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return 0, "error", "failed to acknowledge SETTINGS", err
				}
			}
		}
	}
	return 0, "error", "HTTP/2 response frame limit reached", nil
}

