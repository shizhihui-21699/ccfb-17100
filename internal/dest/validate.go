// Package dest validates and normalizes destination URLs supplied at link
// creation time. Validation here is *cheap and synchronous* — it must not
// make a network call, because marketing creates thousands of links a day
// and a slow create path means people route around the service.
//
// Everything expensive (fetching the page, scoring its behaviour) happens
// asynchronously in the scanner. The split is deliberate: cheap checks are
// mandatory and cannot be skipped; deep checks are best-effort and gate
// *clickability*, not creation.
package dest

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"shortlink/internal/netutil"
)

var (
	ErrEmpty       = errors.New("dest: empty")
	ErrNotAbsolute = errors.New("dest: not an absolute http(s) URL")
	ErrScheme      = errors.New("dest: scheme not allowed")
	ErrUserinfo    = errors.New("dest: embedded credentials not allowed")
	ErrPrivateAddr = errors.New("dest: resolves to a private or reserved address")
	ErrSelf        = errors.New("dest: points at our own short-link host")
	ErrTooLong     = errors.New("dest: exceeds maximum length")
	ErrBadHost     = errors.New("dest: host is malformed")
)

const MaxURLBytes = 4096

// Parsed is a validated, normalized destination.
type Parsed struct {
	Raw         string
	URL         *url.URL
	Scheme      string
	Host        string // lowercase, no port, no brackets
	Registrable string
	IsIP        bool
}

// Options controls Normalize. The zero value is the production posture:
// self-hosts empty, no DNS resolver, private addresses rejected.
type Options struct {
	SelfHosts []string
	// AllowPrivateNet permits loopback/RFC1918 targets. ONLY for tests and
	// local demos; enabling it in production reintroduces SSRF.
	AllowPrivateNet bool
	// Resolver, when non-nil, is used to reject hostnames that resolve to
	// private space.
	Resolver func(host string) ([]net.IP, error)
}

// Normalize parses raw and applies the checks that need no network access.
func Normalize(raw string, opt Options) (*Parsed, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrEmpty
	}
	if len(raw) > MaxURLBytes {
		return nil, ErrTooLong
	}
	// Reject control characters outright; they are used to smuggle a second
	// destination past naive parsers.
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("dest: control character %U", r)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("dest: %w", err)
	}
	// Check the scheme before the host: `javascript:` and `file:` have no
	// authority, and reporting "not absolute" would hide the real reason.
	// An empty scheme is simply a relative reference.
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return nil, ErrNotAbsolute
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: %q", ErrScheme, scheme)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, ErrNotAbsolute
	}
	u.Scheme = scheme
	if u.User != nil {
		return nil, ErrUserinfo
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !validHostname(host) {
		return nil, ErrBadHost
	}
	for _, self := range opt.SelfHosts {
		if strings.EqualFold(strings.TrimSpace(self), host) {
			return nil, ErrSelf
		}
	}

	p := &Parsed{
		Raw:         raw,
		URL:         u,
		Scheme:      scheme,
		Host:        host,
		Registrable: netutil.Registrable(host),
		IsIP:        netutil.IsIP(host),
	}
	if !opt.AllowPrivateNet {
		if p.IsIP && netutil.IsPrivateIP(host) {
			return nil, ErrPrivateAddr
		}
		if opt.Resolver != nil && !p.IsIP {
			ips, err := opt.Resolver(host)
			if err != nil {
				// DNS failure at creation is not fatal: partner staging hosts
				// are often not published yet. The scanner retries. Only a
				// positive private-space finding is fatal.
				return p, nil
			}
			for _, ip := range ips {
				if netutil.IsPrivateIP(ip.String()) {
					return nil, fmt.Errorf("%w: %s -> %s", ErrPrivateAddr, host, ip)
				}
			}
		}
	}
	return p, nil
}

// validHostname accepts DNS names and IP literals, rejects things that would
// confuse parsers (spaces, slashes already excluded by url.Parse, underscores
// are tolerated because some partner hosts have them in error).
func validHostname(host string) bool {
	if netutil.IsIP(host) {
		return true
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// IsShortener reports whether host looks like a public URL shortener. Using
// one as the target defeats the whole point of the service: the customer
// would be redirected to a domain we neither control nor can inspect.
func IsShortener(host string) bool {
	h := netutil.Registrable(host)
	switch h {
	case "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
		"rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id",
		"tiny.cc", "soo.gd", "v.gd", "shorte.st", "adf.ly", "bl.ink":
		return true
	}
	return false
}

// RedirectParams lists query keys routinely used to carry an open redirect.
// Business pages that accept any of these and honour them without validation
// are the second half of the reported incident.
var RedirectParams = []string{
	"url", "u", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
	"return_url", "next", "target", "dest", "destination", "continue", "goto",
	"go", "out", "link", "to", "r", "forward", "view", "jump",
}

// FindRedirectParam returns the first query parameter that looks like an
// outbound redirect, plus its value. It is a heuristic for *flagging*; the
// authoritative fix is to stop honouring untrusted redirect params at all.
func FindRedirectParam(u *url.URL) (string, string, bool) {
	if u == nil {
		return "", "", false
	}
	q := u.Query()
	for _, k := range RedirectParams {
		if v := q.Get(k); v != "" {
			return k, v, true
		}
	}
	return "", "", false
}
