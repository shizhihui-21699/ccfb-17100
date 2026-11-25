package saferedirect

import (
	"errors"
	"testing"
)

func policy() Policy {
	return Policy{
		SelfHosts:       []string{"shop.example.com"},
		AllowedHosts:    []string{"pay.example.com", "*.partner.com"},
		AllowedPrefixes: []string{"/account/", "/orders/"},
	}
}

func TestResolveAllows(t *testing.T) {
	p := policy()
	cases := []struct{ dest, page string }{
		{"/account/profile", "shop.example.com"},
		{"/orders/123?tab=1", "shop.example.com"},
		{"https://pay.example.com/checkout", "shop.example.com"},
		{"https://m.partner.com/promo", "shop.example.com"},
		{"https://shop.example.com/account/x", "shop.example.com"},
	}
	for _, c := range cases {
		if got, err := p.Resolve(c.dest, c.page); err != nil {
			t.Errorf("%q: unexpected error %v", c.dest, err)
		} else if got == "" {
			t.Errorf("%q: empty result", c.dest)
		}
	}
}

func TestResolveBlocksOpenRedirects(t *testing.T) {
	p := policy()
	cases := []string{
		"https://evil.com/",
		"//evil.com/",
		"///evil.com",
		"/\\evil.com",
		"\\evil.com",
		"javascript:alert(1)",
		"data:text/html,x",
		"file:///etc/passwd",
		"https://pay.example.com.evil.com/", // suffix confusion
		"https://evil.com#@pay.example.com",
		"https://pay.example.com@evil.com/",
		"https://user:pw@evil.com/",
		"%0d%0aLocation:%20https://evil.com",
		"/admin/delete",                    // not an allowed prefix
		"https://shop.example.com/admin/x", // same host, disallowed path
	}
	for _, dest := range cases {
		if got, err := p.Resolve(dest, "shop.example.com"); err == nil {
			t.Errorf("%q was allowed -> %q", dest, got)
		} else if !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%q: wrong error %v", dest, err)
		}
	}
}

func TestResolveBlocksPrivateIP(t *testing.T) {
	p := Policy{AllowedHosts: []string{"*.example.com"}}
	for _, dest := range []string{
		"http://127.0.0.1/", "http://169.254.169.254/", "http://10.0.0.1/",
	} {
		if _, err := p.Resolve(dest, "shop.example.com"); err == nil {
			t.Errorf("%q allowed", dest)
		}
	}
}

func TestResolveEmpty(t *testing.T) {
	if _, err := policy().Resolve("", "shop.example.com"); !errors.Is(err, ErrEmpty) {
		t.Fatalf("got %v", err)
	}
}
