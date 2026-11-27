package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const userAgent = "httpcheck/0.1 (+authorized HTTP protocol posture check)"

type probeResult struct {
	Protocol  string            `json:"protocol"`
	Supported bool              `json:"supported"`
	Status    int               `json:"status,omitempty"`
	HTTP      string            `json:"http_version,omitempty"`
	TLSALPN   string            `json:"tls_alpn,omitempty"`
	Duration  int64             `json:"duration_ms"`
	Headers   map[string]string `json:"headers,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type scanReport struct {
	Tool      string      `json:"tool"`
	Mode      string      `json:"mode"`
	Target    string      `json:"target"`
	Timestamp time.Time   `json:"timestamp_utc"`
	Requests  int         `json:"requests_sent"`
	Note      string      `json:"note"`
	HTTP1     probeResult `json:"http1"`
	HTTP2     probeResult `json:"http2"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			VulnStatus   string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V40 []struct {
					CVSS struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
						Vector   string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV40"`
				V31 []struct {
					CVSS struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
						Vector   string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					CVSS struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
						Vector   string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				V2 []struct {
					CVSS struct {
						Score  float64 `json:"baseScore"`
						Vector string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type cveReport struct {
	Tool        string   `json:"tool"`
	Mode        string   `json:"mode"`
	ID          string   `json:"id"`
	Status      string   `json:"status,omitempty"`
	Description string   `json:"description,omitempty"`
	CVSSVersion string   `json:"cvss_version,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Vector      string   `json:"vector,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	References  []string `json:"references,omitempty"`
	Source      string   `json:"source"`
	Note        string   `json:"note"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "cve":
		err = runCVE(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "httpcheck:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `httpcheck — low-impact HTTP/1.1 and HTTP/2 posture checks

Usage:
  httpcheck scan -url https://example.com -authorized
  httpcheck cve -id CVE-2023-44487

scan sends one HEAD request using HTTP/1.1 and one using HTTP/2, without following redirects.
cve retrieves public advisory metadata from the NVD. Neither mode exploits vulnerabilities.`)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	target := fs.String("url", "", "one http(s) URL or hostname to check")
	authorized := fs.Bool("authorized", false, "confirm you own or are authorized to test this target")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout (1s to 30s)")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if !*authorized {
		return errors.New("pass -authorized only for a site you own or have permission to assess")
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		return errors.New("-timeout must be between 1s and 30s")
	}
	u, err := normalizeURL(*target)
	if err != nil {
		return err
	}

	requestCount := 2
	if u.Scheme != "https" {
		requestCount = 1 // HTTP/2 probe is TLS-only; h2c is intentionally not attempted.
	}
	report := scanReport{Tool: "httpcheck", Mode: "scan", Target: u.String(), Timestamp: time.Now().UTC(), Requests: requestCount,
		Note: "Two HEAD requests only. Redirects are not followed. Header observations are not vulnerability proof."}
	report.HTTP1 = probeHTTP1(u, *timeout)
	report.HTTP2 = probeHTTP2(u, *timeout)
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	fmt.Printf("Target: %s\nRequests: 2 HEAD probes (no redirects)\n\n", u)
	printProbe(report.HTTP1)
	printProbe(report.HTTP2)
	fmt.Println("Note:", report.Note)
	return nil
}

func normalizeURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("provide -url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("target must be a valid http(s) URL or hostname, without credentials or fragment")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery = "" // Avoid sending supplied query strings that could trigger stateful endpoints.
	return u, nil
}

func probeHTTP1(u *url.URL, timeout time.Duration) probeResult {
	return runProbe(u, "HTTP/1.1", timeout, func() *http.Client {
		t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
		return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	})
}

func probeHTTP2(u *url.URL, timeout time.Duration) probeResult {
	if u.Scheme != "https" {
		return probeResult{Protocol: "HTTP/2", Error: "HTTP/2 probe requires HTTPS/TLS; cleartext h2c is not tested"}
	}
	return runProbe(u, "HTTP/2", timeout, func() *http.Client {
		t := &http2.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	})
}

func runProbe(u *url.URL, name string, timeout time.Duration, makeClient func() *http.Client) (r probeResult) {
	r = probeResult{Protocol: name}
	start := time.Now()
	defer func() { r.Duration = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("User-Agent", userAgent)
	client := makeClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		r.Error = compactError(err)
		return r
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	r.HTTP = resp.Proto
	r.Supported = true
	if resp.TLS != nil {
		r.TLSALPN = resp.TLS.NegotiatedProtocol
	}
	r.Headers = map[string]string{}
	for _, key := range []string{"Server", "Via", "Alt-Svc", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		if value := resp.Header.Get(key); value != "" {
			r.Headers[key] = value
		}
	}
	return r
}

func compactError(err error) string {
	message := err.Error()
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func printProbe(p probeResult) {
	fmt.Printf("%s: ", p.Protocol)
	if p.Supported {
		fmt.Printf("supported — %s, status %d, ALPN %q, %d ms\n", p.HTTP, p.Status, p.TLSALPN, p.Duration)
	} else {
		fmt.Printf("no successful response — %s\n", p.Error)
	}
	for k, v := range p.Headers {
		fmt.Printf("  %s: %s\n", k, v)
	}
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func runCVE(args []string) error {
	fs := flag.NewFlagSet("cve", flag.ContinueOnError)
	id := fs.String("id", "", "CVE identifier, for example CVE-2023-44487")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cveID := strings.ToUpper(*id)
	if !cvePattern.MatchString(cveID) {
		return errors.New("-id must be a CVE identifier such as CVE-2023-44487")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds="+url.QueryEscape(cveID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("NVD request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var parsed nvdResponse
	if err = json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("could not parse NVD response: %w", err)
	}
	if len(parsed.Vulnerabilities) == 0 {
		return fmt.Errorf("%s was not found in the NVD", cveID)
	}
	cve := parsed.Vulnerabilities[0].CVE
	out := cveReport{Tool: "httpcheck", Mode: "cve", ID: cve.ID, Status: cve.VulnStatus, Source: "https://nvd.nist.gov/vuln/detail/" + cve.ID, Note: "Advisory metadata only. A CVE match does not establish that a target is vulnerable."}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			out.Description = d.Value
			break
		}
	}
	switch {
	case len(cve.Metrics.V40) > 0:
		m := cve.Metrics.V40[0].CVSS
		out.CVSSVersion = "4.0"
		out.CVSSScore = m.Score
		out.Severity = m.Severity
		out.Vector = m.Vector
	case len(cve.Metrics.V31) > 0:
		m := cve.Metrics.V31[0].CVSS
		out.CVSSVersion = "3.1"
		out.CVSSScore = m.Score
		out.Severity = m.Severity
		out.Vector = m.Vector
	case len(cve.Metrics.V30) > 0:
		m := cve.Metrics.V30[0].CVSS
		out.CVSSVersion = "3.0"
		out.CVSSScore = m.Score
		out.Severity = m.Severity
		out.Vector = m.Vector
	case len(cve.Metrics.V2) > 0:
		m := cve.Metrics.V2[0].CVSS
		out.CVSSVersion = "2.0"
		out.CVSSScore = m.Score
		out.Vector = m.Vector
	}
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				out.CWE = append(out.CWE, d.Value)
			}
		}
	}
	for _, ref := range cve.References {
		if ref.URL != "" && len(out.References) < 8 {
			out.References = append(out.References, ref.URL)
		}
	}
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	fmt.Printf("%s [%s]\n%s\n", out.ID, out.Status, out.Description)
	if out.CVSSVersion != "" {
		fmt.Printf("CVSS %s: %.1f %s\nVector: %s\n", out.CVSSVersion, out.CVSSScore, out.Severity, out.Vector)
	}
	if len(out.CWE) > 0 {
		fmt.Println("Weakness:", strings.Join(out.CWE, ", "))
	}
	fmt.Println("NVD:", out.Source)
	fmt.Println(out.Note)
	return nil
}

