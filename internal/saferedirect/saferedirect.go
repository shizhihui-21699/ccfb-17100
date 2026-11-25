// Package saferedirect is the fix for the second half of the incident: business
// pages that accepted a `?redirect=` / `?next=` parameter and sent the user to
// whatever URL was in it.
//
// The rule is allowlist-only. A relative path or a URL on a configured
// same-site host is permitted; everything else is refused with a reason. There
// is no "looks like a URL" heuristic and no signature-less fallback, because
// every one of those has been used as an open-redirect bypass.
package saferedirect

import (
	"errors"
	"net/url"
	"strings"

	"shortlink/internal/netutil"
)

var (
	// ErrNotAllowed is returned for any destination not on the allowlist.
	ErrNotAllowed = errors.New("saferedirect: destination not allowed")
	ErrEmpty      = errors.New("saferedirect: empty destination")
)

// Policy is the set of hosts a page may redirect to, plus the hosts the page
// itself lives on (so a relative path can be resolved and checked).
type Policy struct {
	// SelfHosts are hosts that may appear as the *referring* page.
	SelfHosts []string
	// AllowedHosts are absolute destinations that are permitted.
	AllowedHosts []string
	// AllowedPrefixes are path prefixes for self-host relative redirects, so a
	// page cannot bounce to an internal admin path.
	AllowedPrefixes []string
}

func (p Policy) allowsHost(host string) bool {
	h := strings.ToLower(host)
	for _, a := range p.AllowedHosts {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(h, a[1:]) && len(h) > len(a)-1 {
				return true
			}
			continue
		}
		if h == a {
			return true
		}
	}
	return false
}

func (p Policy) allowsPath(path string) bool {
	if len(p.AllowedPrefixes) == 0 {
		// Default: only same-origin absolute paths under a safe set.
		return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") &&
			!strings.HasPrefix(strings.ToLower(path), "/\\")
	}
	for _, pre := range p.AllowedPrefixes {
		if strings.HasPrefix(path, pre) {
			return true
		}
	}
	return false
}

// Resolve validates dest against the policy and returns a safe redirect path
// or absolute URL. pageHost is the host the current request arrived on.
func (p Policy) Resolve(dest, pageHost string) (string, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", ErrEmpty
	}
	// Reject control chars and backslashes up front: browsers and proxies
	// disagree about how to normalize these, which is a classic bypass.
	for _, r := range dest {
		if r < 0x20 || r == 0x7f {
			return "", ErrNotAllowed
		}
	}
	if strings.Contains(dest, "\\") {
		return "", ErrNotAllowed
	}

	// Scheme-relative (//evil.com) must never be treated as a path.
	if strings.HasPrefix(dest, "//") || strings.HasPrefix(dest, "/\\") {
		return "", ErrNotAllowed
	}

	u, err := url.Parse(dest)
	if err != nil {
		return "", ErrNotAllowed
	}

	// Relative / absolute-path form: must stay on this page's own origin.
	if u.Scheme == "" && u.Host == "" {
		if !p.allowsPath(u.Path) {
			return "", ErrNotAllowed
		}
		return u.String(), nil
	}

	// Absolute form.
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrNotAllowed
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || netutil.IsPrivateIP(host) {
		return "", ErrNotAllowed
	}
	// Never allow redirecting into our own short-link service: that is a loop,
	// and it launders an attacker URL through our trusted domain.
	if p.allowsHost(host) && !sameHost(host, pageHost) {
		return u.String(), nil
	}
	if sameHost(host, pageHost) && p.allowsPath(u.Path) {
		return u.String(), nil
	}
	// Also permit same-site (same eTLD+1) absolute URLs, e.g. www.<site> ->
	// m.<site>, which marketing does constantly.
	if pageHost != "" && netutil.SameSite(host, pageHost) && p.allowsPath(u.Path) {
		return u.String(), nil
	}
	return "", ErrNotAllowed
}

func sameHost(a, b string) bool {
	return b != "" && strings.EqualFold(a, b)
}
