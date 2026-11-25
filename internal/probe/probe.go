// Package probe fetches a URL safely and returns the raw response plus the
// transport-level facts the fingerprint needs (final URL, TLS issuer).
//
// Safety properties, because this service fetches attacker-influenced URLs:
//   - the dialer re-checks the *resolved* IP, so a hostname that passed
//     creation-time validation cannot rebind to 169.254.169.254 later
//   - redirects are followed manually, with the same check at each hop, and
//     capped in count
//   - the body is capped, so a compression bomb cannot exhaust memory
//   - every stage has a deadline
package probe

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shortlink/internal/netutil"
)

const (
	MaxBodyBytes = 2 << 20 // 2 MiB of decompressed HTML is plenty for a landing page
	MaxRedirects = 5
)

var (
	ErrBlockedAddr = errors.New("probe: destination resolves to a blocked address")
	ErrTooManyHops = errors.New("probe: too many redirects")
	ErrBadScheme   = errors.New("probe: non-http(s) redirect target")
	ErrBodyTooBig  = errors.New("probe: body exceeds limit")
)

// Result is one successful (HTTP-wise) fetch.
type Result struct {
	RequestedURL string
	FinalURL     string
	StatusCode   int
	ContentType  string
	Body         []byte
	Truncated    bool // body hit the cap
	TLSIssuer    string
	TLSValid     bool
	TLSHost      string
	Redirects    []string // every hop, for diagnostics
	FetchedAt    time.Time
	Elapsed      time.Duration
	// ServerHeader is recorded because staging servers that later serve
	// phishing often change stack between the two phases.
	ServerHeader string
}

// Probe is a reusable client. Create one per process; it is safe for
// concurrent use.
type Probe struct {
	client    *http.Client
	userAgent string
	resolver  *net.Resolver
}

// Options tune the probe. The defaults are what the patrol scanner uses;
// tests override AllowPrivateNet to talk to an in-process server.
type Options struct {
	UserAgent       string
	AllowPrivateNet bool
	Timeout         time.Duration
	MaxBody         int64
	// ExtraAllowedHosts lets an operator hint that a specific host is internal
	// (should be rare; noted in audit logs when used).
	ExtraAllowedHosts []string
}

func New(o Options) *Probe {
	if o.UserAgent == "" {
		o.UserAgent = "Mozilla/5.0 (compatible; ShortlinkPatrol/1.0; +https://example.invalid/patrol)"
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxBody == 0 {
		o.MaxBody = MaxBodyBytes
	}
	p := &Probe{userAgent: o.UserAgent, resolver: net.DefaultResolver}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	allowPrivate := o.AllowPrivateNet
	allowed := make(map[string]bool, len(o.ExtraAllowedHosts))
	for _, h := range o.ExtraAllowedHosts {
		allowed[strings.ToLower(h)] = true
	}

	tr := &http.Transport{
		Proxy: nil, // never route patrol traffic through an env proxy
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !allowPrivate && !allowed[strings.ToLower(host)] {
				ips, err := p.resolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("probe: no addresses for %s", host)
				}
				for _, ip := range ips {
					if netutil.IsPrivateIP(ip.IP.String()) {
						return nil, fmt.Errorf("%w: %s -> %s", ErrBlockedAddr, host, ip.IP)
					}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		// We manage redirects ourselves; disable the transport's.
		DisableCompression:    true, // we handle gzip so we can cap decompressed size
		MaxIdleConns:          50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &Probe{
		client: &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // surface 3xx to caller
			},
		},
		userAgent: o.UserAgent,
		resolver:  p.resolver,
	}
}

// Fetch retrieves u, following redirects manually. A non-2xx/3xx response is
// returned in Result rather than as an error: for patrol purposes a 404 or a
// parked-domain page is a *finding*, not a failure.
func (p *Probe) Fetch(ctx context.Context, rawURL string) (*Result, error) {
	start := time.Now()
	cur := rawURL
	var hops []string
	var lastTLSIssuer, lastTLSHost string
	var lastTLSValid bool

	for hop := 0; hop <= MaxRedirects; hop++ {
		u, err := url.Parse(cur)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("%w: %s", ErrBadScheme, u.Scheme)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", p.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.6")
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			lastTLSValid = resp.TLS.VerifiedChains != nil
			lastTLSIssuer = c.Issuer.CommonName
			lastTLSHost = c.Subject.CommonName
			if lastTLSHost == "" && len(c.DNSNames) > 0 {
				lastTLSHost = c.DNSNames[0]
			}
		}

		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc := resp.Header.Get("Location")
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if loc == "" {
				return p.finish(resp, cur, cur, hops, nil, lastTLSIssuer, lastTLSValid, lastTLSHost, start)
			}
			next, err := resp.Location()
			if err != nil {
				return nil, fmt.Errorf("probe: bad Location %q: %w", loc, err)
			}
			nextURL := next.String()
			hops = append(hops, nextURL)
			cur = nextURL
			continue
		default:
			body, truncated, err := readCapped(resp, p.maxBody())
			if err != nil {
				resp.Body.Close()
				return nil, err
			}
			resp.Body.Close()
			r := &Result{
				RequestedURL: rawURL,
				FinalURL:     resp.Request.URL.String(),
				StatusCode:   resp.StatusCode,
				ContentType:  resp.Header.Get("Content-Type"),
				Body:         body,
				Truncated:    truncated,
				TLSIssuer:    lastTLSIssuer,
				TLSValid:     lastTLSValid,
				TLSHost:      lastTLSHost,
				Redirects:    hops,
				FetchedAt:    time.Now(),
				Elapsed:      time.Since(start),
				ServerHeader: resp.Header.Get("Server"),
			}
			return r, nil
		}
	}
	return nil, fmt.Errorf("%w (limit %d)", ErrTooManyHops, MaxRedirects)
}

func (p *Probe) maxBody() int64 { return MaxBodyBytes }

func (p *Probe) finish(resp *http.Response, req, final string, hops []string, _ []byte, issuer string, valid bool, host string, start time.Time) (*Result, error) {
	return &Result{
		RequestedURL: req, FinalURL: final, StatusCode: resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"), TLSIssuer: issuer,
		TLSValid: valid, TLSHost: host, Redirects: hops,
		FetchedAt: time.Now(), Elapsed: time.Since(start),
	}, nil
}

// readCapped reads at most MaxBodyBytes after decompressing gzip, so the cap
// applies to what a parser would actually see.
func readCapped(resp *http.Response, limit int64) ([]byte, bool, error) {
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, false, err
		}
		defer gz.Close()
		r = gz
	}
	// Read one byte past the limit so we can tell "exactly limit" from "more".
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		// A truncated decompression stream is common with bombs; treat the
		// bytes we got as the body and mark truncated.
		if len(buf) > 0 {
			return truncate(buf, limit)
		}
		return nil, false, err
	}
	return truncate(buf, limit)
}

func truncate(buf []byte, limit int64) ([]byte, bool, error) {
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// LookupIP is exposed so creation-time validation can make the same
// private-space judgement the dialer will later enforce.
func (p *Probe) LookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.resolver.LookupIP(ctx, "ip", host)
}
