// Package netutil contains small network-name helpers with no external
// dependencies: registrable-domain (eTLD+1) resolution from an embedded
// subset of the Public Suffix List, and IP-address classification.
//
// The embedded list is deliberately small. It covers the suffixes our
// marketing partners actually use; anything unrecognised falls back to the
// last two labels, which is the safe direction for *comparison* purposes
// (two hosts sharing a fallback eTLD+1 were probably meant to share it).
// For enforcement decisions we never rely on eTLD+1 alone — see allowlist.
package netutil

import (
	"net"
	"net/url"
	"strings"
)

// multiLabelSuffixes is a curated subset of the PSL "private"/"ICANN" entries
// that require three labels to form an eTLD+1.
var multiLabelSuffixes = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {}, "me.uk": {}, "ltd.uk": {}, "plc.uk": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {}, "ac.cn": {},
	"com.hk": {}, "com.tw": {}, "com.sg": {}, "com.my": {}, "com.au": {}, "net.au": {}, "org.au": {},
	"co.jp": {}, "co.kr": {}, "co.nz": {}, "co.in": {}, "co.za": {}, "co.id": {}, "co.th": {},
	"com.br": {}, "com.mx": {}, "com.ar": {}, "com.tr": {}, "com.sa": {}, "com.ae": {},
}

// Registrable returns the eTLD+1 of host, lowercased. For IP literals it
// returns the IP itself. Returns "" for empty input.
func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	last2 := strings.Join(labels[len(labels)-2:], ".")
	if _, ok := multiLabelSuffixes[last2]; ok && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return last2
}

// IsIP reports whether host is an IP literal (v4 or v6, brackets allowed).
func IsIP(host string) bool {
	h := strings.Trim(host, "[]")
	return net.ParseIP(h) != nil
}

// IsPrivateIP reports whether the IP is in a range that must never be a
// public landing page: loopback, link-local, RFC1918, CGNAT, unique-local,
// multicast, unspecified, and the various "this network" blocks. This is the
// SSRF guard for both creation-time validation and patrol fetches.
func IsPrivateIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// Extra ranges Go's net.IP predicates do not cover.
	blocks := []string{
		"100.64.0.0/10",   // CGNAT
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"fc00::/7",        // unique local
		"fe80::/10",       // link local
		"::1/128",
		"::/128",
	}
	for _, b := range blocks {
		_, n, err := net.ParseCIDR(b)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// SameSite reports whether two hosts share an eTLD+1.
func SameSite(a, b string) bool {
	ra, rb := Registrable(a), Registrable(b)
	return ra != "" && ra == rb
}

// HostOf returns the lowercased host (no port, no userinfo) of an absolute
// URL. Returns "" when raw is not an absolute URL with a host.
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
