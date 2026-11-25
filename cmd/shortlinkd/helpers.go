package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"sync"
	"time"

	"shortlink/internal/probe"
)

// newRateLimitedFetcher wraps a probe so the patrol loop cannot turn into a
// burst that looks like an attack on partner sites. A single process scans
// serially with a small gap; the gap is the cheapest way to keep both our
// outbound reputation and the partners' servers intact.
func newRateLimitedFetcher(p *probe.Probe, gap time.Duration) func(context.Context, string) (*probe.Result, error) {
	var mu sync.Mutex
	var last time.Time
	return func(ctx context.Context, raw string) (*probe.Result, error) {
		mu.Lock()
		if d := time.Until(last.Add(gap)); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				mu.Unlock()
				return nil, ctx.Err()
			}
		}
		last = time.Now()
		mu.Unlock()
		return p.Fetch(ctx, raw)
	}
}

func parseURL(raw string) (*url.URL, error) { return url.Parse(raw) }

// lookupIPs resolves a host for creation-time private-space rejection.
func lookupIPs(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:32]
}
