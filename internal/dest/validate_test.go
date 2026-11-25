package dest

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeRejects(t *testing.T) {
	self := []string{"s.example.com"}
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", ErrEmpty},
		{"relative", "/foo/bar", ErrNotAbsolute},
		{"javascript", "javascript:alert(1)", ErrScheme},
		{"file", "file:///etc/passwd", ErrScheme},
		{"ftp", "ftp://example.com/x", ErrScheme},
		{"userinfo", "https://user:pass@example.com/", ErrUserinfo},
		{"loopback v4", "http://127.0.0.1/", ErrPrivateAddr},
		{"loopback v6", "http://[::1]/", ErrPrivateAddr},
		{"metadata", "http://169.254.169.254/latest/meta-data/", ErrPrivateAddr},
		{"rfc1918", "http://10.1.2.3/", ErrPrivateAddr},
		{"self", "https://s.example.com/abc", ErrSelf},
		{"control char", "https://example.com/\r\nHost: evil", nil}, // wrapped, not a sentinel
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Normalize(c.raw, Options{SelfHosts: self})
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("got %v, want %v", err, c.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error for %q", c.raw)
			}
		})
	}
}

func TestNormalizeAccepts(t *testing.T) {
	good := []string{
		"https://promo.partner.com/spring?x=1",
		"http://example.com.cn/a",
		"https://xn--fiqs8s.example/",
		"https://sub.deep.example.co.uk/path",
	}
	for _, raw := range good {
		p, err := Normalize(raw, Options{})
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if p.Host == "" || p.Registrable == "" {
			t.Fatalf("%s: empty host/registrable", raw)
		}
	}
}

func TestNormalizeTooLong(t *testing.T) {
	raw := "https://example.com/" + strings.Repeat("a", MaxURLBytes)
	if _, err := Normalize(raw, Options{}); !errors.Is(err, ErrTooLong) {
		t.Fatalf("got %v", err)
	}
}

func TestIsShortener(t *testing.T) {
	if !IsShortener("bit.ly") || !IsShortener("x.t.co") {
		t.Fatal("expected shortener detection")
	}
	if IsShortener("partner.com") {
		t.Fatal("false positive")
	}
}

func TestFindRedirectParam(t *testing.T) {
	p, _ := Normalize("https://partner.com/go?next=https://evil.top", Options{})
	k, v, ok := FindRedirectParam(p.URL)
	if !ok || k != "next" || !strings.Contains(v, "evil.top") {
		t.Fatalf("got %q=%q ok=%v", k, v, ok)
	}
}
