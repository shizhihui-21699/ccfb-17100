// Package risk scores a destination both at creation (structural signals
// only, no network) and at scan time (structural + live fingerprint + drift
// from the approved baseline).
//
// Design stance worth stating explicitly, because it drives everything:
//
//	The score gates *automation*, not *trust*. A low score lets a link skip
//	human review; it never lets an unknown external domain skip the
//	interstitial. Otherwise a patient attacker who waits out the review queue
//	gets exactly the "company domain, straight to a phishing page" outcome
//	the incident was about.
//
// So Decision.DirectRedirect is a separate, stricter bit than
// Decision.Level <= low.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/dest"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
)

// Thresholds map a raw score to a level. Exported so operators can see and
// tune them in one place.
type Thresholds struct {
	Low     int // >= Low is "low"
	Medium  int
	High    int
	Blocked int
}

var DefaultThresholds = Thresholds{Low: 10, Medium: 25, High: 50, Blocked: 80}

func (t Thresholds) Level(score int) model.Level {
	switch {
	case score >= t.Blocked:
		return model.LevelBlocked
	case score >= t.High:
		return model.LevelHigh
	case score >= t.Medium:
		return model.LevelMedium
	case score >= t.Low:
		return model.LevelLow
	default:
		return model.LevelTrusted
	}
}

// Domain is one entry in the partner allowlist. A domain being present means
// "we have vetted this publisher"; it does not mean "this page is safe now".
type Domain struct {
	Pattern string `json:"pattern"` // host, *.host, or registrable domain
	Owner   string `json:"owner,omitempty"`
	Note    string `json:"note,omitempty"`
	// FirstParty marks our own properties; these may skip the interstitial.
	FirstParty bool       `json:"first_party,omitempty"`
	AddedAt    time.Time  `json:"added_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	AddedBy    string     `json:"added_by,omitempty"`
}

func (d Domain) Expired(now time.Time) bool {
	return d.ExpiresAt != nil && now.After(*d.ExpiresAt)
}

// Allowlist is a locked-immutable snapshot; swap the whole slice on change so
// readers never take a lock.
type Allowlist struct {
	domains []Domain
}

func NewAllowlist(ds []Domain) *Allowlist {
	c := append([]Domain(nil), ds...)
	return &Allowlist{domains: c}
}

func (a *Allowlist) All() []Domain { return append([]Domain(nil), a.domains...) }

// Match returns the most specific matching entry for host, if any.
func (a *Allowlist) Match(host string, now time.Time) (Domain, bool) {
	host = strings.ToLower(host)
	var best Domain
	bestLen := -1
	for _, d := range a.domains {
		if d.Expired(now) {
			continue
		}
		pat := strings.ToLower(d.Pattern)
		matched := false
		switch {
		case strings.HasPrefix(pat, "*."):
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				matched = true
			}
		case strings.Contains(pat, "/"):
			continue // path patterns handled elsewhere
		default:
			if host == pat || strings.HasSuffix(host, "."+pat) {
				matched = true
			}
		}
		if matched && len(pat) > bestLen {
			best, bestLen = d, len(pat)
		}
	}
	return best, bestLen >= 0
}

// FirstParty reports whether host belongs to one of our own properties.
func (a *Allowlist) FirstParty(host string, now time.Time) bool {
	d, ok := a.Match(host, now)
	return ok && d.FirstParty
}

// CreationInput is everything the creation-time scorer may look at. All of it
// is cheap: no network access happened to produce it.
type CreationInput struct {
	Parsed  *dest.Parsed
	Creator model.Creator
	// CreatorLinksLastHour is a volume signal; a sudden burst from a normally
	// quiet account is the classic compromised-account pattern.
	CreatorLinksLastHour int
	Campaign             string
	// CampaignDomains counts distinct registrable domains already used under
	// the same campaign id. Broad domain spread under one "campaign" is odd.
	CampaignDomains int
	Now             time.Time
}

type Scorer struct {
	Allow  *Allowlist
	Thresh Thresholds
	// BrandTerms are words looked for in horse-riding punycode/lookalike hosts
	// (e.g. our own company name, "login", "pay"). Keep short.
	BrandTerms []string
	// NewCreatorDays: creators younger than this get no reputation discount.
	NewCreatorDays int
}

func NewScorer(allow *Allowlist) *Scorer {
	return &Scorer{
		Allow:          allow,
		Thresh:         DefaultThresholds,
		BrandTerms:     []string{"login", "signin", "verify", "secure", "account", "wallet", "pay", "bank", "update", "confirm"},
		NewCreatorDays: 14,
	}
}

// --- creation-time ---------------------------------------------------------

func (s *Scorer) ScoreCreation(in CreationInput) model.Risk {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	add := newAdder()
	p := in.Parsed

	if p.Scheme == "http" {
		add.add("scheme_http", 10, "destination is plain HTTP")
	}
	if p.IsIP {
		add.add("ip_literal_host", 30, "destination is a bare IP address")
	}
	if strings.HasPrefix(p.Host, "xn--") || strings.Contains(p.Host, ".xn--") {
		add.add("punycode_host", 30, "destination uses punycode (IDN) labels")
	}
	if looksLikeBrandAbuse(p.Host, s.BrandTerms) {
		add.add("brand_lookalike", 40, "host mixes brand/credential terms")
	}
	if dest.IsShortener(p.Host) {
		add.add("public_shortener", 35, "destination is a public URL shortener; target cannot be audited")
	}
	if len(strings.Split(p.Host, ".")) > 4 {
		add.add("deep_subdomain", 10, fmt.Sprintf("%d labels in host", len(strings.Split(p.Host, "."))))
	}
	if strings.HasSuffix(p.Host, ".tk") || strings.HasSuffix(p.Host, ".ml") ||
		strings.HasSuffix(p.Host, ".ga") || strings.HasSuffix(p.Host, ".cf") ||
		strings.HasSuffix(p.Host, ".gq") || strings.HasSuffix(p.Host, ".xyz") ||
		strings.HasSuffix(p.Host, ".top") || strings.HasSuffix(p.Host, ".icu") {
		add.add("high_abuse_tld", 25, "TLD has elevated phishing abuse rates")
	}
	if k, v, ok := dest.FindRedirectParam(p.URL); ok {
		// A marketing link that itself carries a redirect param is usually
		// wrapping a third party; the final destination is not knowable here.
		add.add("nested_redirect_param", 20, fmt.Sprintf("query %q=%q", k, truncate(v, 80)))
	}

	if d, ok := s.Allow.Match(p.Host, now); ok {
		if d.FirstParty {
			// Our own property: nothing external to flag, but keep the TLD /
			// punycode penalties above in case of a lookalike of us.
			add.add("first_party", -40, "destination is a first-party property")
		} else {
			add.add("allowlisted_partner", -25, "destination domain is an approved partner: "+d.Owner)
		}
	} else {
		// Not allowlisted. This alone is enough to force review + interstitial,
		// regardless of how the rest scores.
		add.add("unknown_domain", 30, "destination domain is not on the partner allowlist")
	}

	if in.CreatorLinksLastHour > 200 {
		add.add("creator_volume_high", 20, fmt.Sprintf("%d links in the last hour", in.CreatorLinksLastHour))
	} else if in.CreatorLinksLastHour > 100 {
		add.add("creator_volume_elevated", 10, fmt.Sprintf("%d links in the last hour", in.CreatorLinksLastHour))
	}
	if in.CampaignDomains > 5 {
		add.add("campaign_domain_spread", 15, fmt.Sprintf("campaign touches %d distinct domains", in.CampaignDomains))
	}

	return add.risk(now, s.Thresh)
}

// CreationDecision is the actionable output of the creation-time score.
type CreationDecision struct {
	Risk model.Risk
	// DeepScan means the link must not be clickable until an async scan has
	// produced a baseline.
	DeepScan bool
	// RequiresReview means a human must approve before activation.
	RequiresReview bool
	// ForceInterstitial is set for anything not first-party.
	ForceInterstitial bool
}

func (s *Scorer) DecideCreation(in CreationInput) CreationDecision {
	r := s.ScoreCreation(in)
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	fp := s.Allow.FirstParty(in.Parsed.Host, now)
	dec := CreationDecision{
		Risk:              r,
		ForceInterstitial: !fp,
		DeepScan:          !fp,
	}
	switch {
	case r.Level >= model.LevelBlocked:
		dec.RequiresReview = true
		dec.DeepScan = true
	case r.Level >= model.LevelHigh:
		// High but not Blocked: a human decides. This is the only band that
		// stops a link before a scan can clear it.
		dec.RequiresReview = true
		dec.DeepScan = true
	}
	// Note: Medium (e.g. merely "unknown domain") is *not* human review. The
	// async scan is the reviewer: a clean scan promotes it, and the
	// interstitial stays on for every non-first-party target either way. If
	// medium meant manual review, a new partner domain would stall the queue
	// and marketing would route around the service entirely.
	return dec
}

// --- scan-time -------------------------------------------------------------

// ScanInput is the input to the patrol-time score. It deliberately reuses the
// *structural* score as a floor: a target that was already medium-risk at
// creation does not become trustworthy just because one scan came back clean.
type ScanInput struct {
	Uncached model.Risk // the creation-time risk, unchanged
	Live     *artifact.Fingerprint
	Baseline *artifact.Fingerprint
	Allow    *Allowlist
	Now      time.Time
	// HTTPStatus and Error come from the probe.
	HTTPStatus int
	FetchErr   error
	// HopHosts are the hosts the fetch was redirected through.
	HopHosts []string
}

func (s *Scorer) ScoreScan(in ScanInput) model.Risk {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	add := newAdder()
	// Carry the creation-time *score* as a floor so a clean scan cannot erase
	// structural concerns. We do NOT also re-add each structural reason: those
	// weights are already inside the score, and adding them again would double
	// count and pin the link at the cap. The floor is capped because structural
	// findings at creation are a suspicion, not a live verdict; review resolves
	// those, and the top structural reason is named on the floor for context.
	base := in.Uncached.Score
	if base > 45 {
		base = 45
	}
	if base < 0 {
		base = 0
	}
	detail := "carried from creation-time assessment"
	if len(in.Uncached.Reasons) > 0 {
		detail += " (top: " + in.Uncached.Reasons[0].Code + ")"
	}
	add.add("structural_floor", base, detail)

	if in.FetchErr != nil {
		if artifact.IsTLSError(in.FetchErr) {
			add.add("tls_invalid", 45, truncate(in.FetchErr.Error(), 160))
		} else {
			// Unreachable is not proof of guilt, but a link that stops
			// resolving is either dead or taken down — hold it, don't block.
			add.add("fetch_failed", 10, truncate(in.FetchErr.Error(), 160))
		}
	}
	if in.HTTPStatus >= 400 {
		add.add("http_error", 10, fmt.Sprintf("status %d", in.HTTPStatus))
	}

	live := in.Live
	if live != nil {
		if !live.TLSValid && strings.HasPrefix(live.FinalURL, "https") {
			add.add("tls_unverified", 35, "TLS chain did not verify")
		}
		if live.HasPassword {
			add.add("password_form", 55, "page contains a password input")
		}
		if len(live.FormActions) > 0 {
			for _, action := range live.FormActions {
				h := artifact.HostOf(action)
				if h == "" {
					continue
				}
				if !netutil.SameSite(h, live.Host) {
					add.add("cross_site_form", 45, fmt.Sprintf("form posts to %s (page is %s)", h, live.Host))
					break
				}
			}
		}
		if len(live.JSRedirectTargets) > 0 {
			add.add("js_redirect", 25, "inline script navigates the browser")
		}
		if len(live.MetaRefreshTargets) > 0 {
			add.add("meta_refresh", 20, "meta refresh navigates the browser")
		}
		if len(live.FrameSources) > 0 {
			add.add("framed_content", 15, "page embeds third-party frames")
		}
		if s.Allow != nil {
			if _, ok := s.Allow.Match(live.Registrable, now); !ok {
				add.add("live_domain_not_allowlisted", 30, "final host "+live.Registrable+" is not allowlisted")
			}
		}
		// Third-party domains: any that are not allowlisted and not well-known
		// CDNs are worth flagging in aggregate.
		susp := 0
		for _, d := range live.ThirdPartyDomains {
			if s.Allow != nil {
				if _, ok := s.Allow.Match(d, now); ok {
					continue
				}
			}
			if isCommonInfra(d) {
				continue
			}
			susp++
		}
		if susp > 0 {
			w := 8 * int(math.Ceil(math.Log2(float64(susp+1))))
			add.add("third_party_unvetted", w, fmt.Sprintf("%d non-allowlisted third-party domains", susp))
		}
	}

	if in.Baseline != nil && live != nil {
		dr := artifact.Compare(in.Baseline, live)
		for _, d := range dr.HardDeltas {
			add.add("baseline_drift:"+d.Field, 40, d.Note)
		}
		// Third-party domain *additions* are amplified: a legitimate page
		// rarely gains a brand-new analytics/beacon origin after approval.
		if hasField(dr.HardDeltas, "third_party_domains") {
			add.add("new_third_party_domain", 25, "third-party domain set changed after approval")
		}
	} else if in.Baseline == nil && live != nil {
		// No baseline yet: this scan will become the baseline, so nothing to
		// drift against. Not itself a penalty.
		_ = live
	}

	return add.risk(now, s.Thresh)
}

func hasField(ds []artifact.Delta, f string) bool {
	for _, d := range ds {
		if d.Field == f {
			return true
		}
	}
	return false
}

// --- helpers ---------------------------------------------------------------

type adder struct {
	score   int
	reasons []model.Reason
}

func newAdder() *adder { return &adder{} }

func (a *adder) add(code string, w int, detail string) {
	a.score += w
	a.reasons = append(a.reasons, model.Reason{Code: code, Detail: detail, Weight: w})
}

func (a *adder) risk(now time.Time, t Thresholds) model.Risk {
	if a.score < 0 {
		a.score = 0
	}
	if a.score > 100 {
		a.score = 100
	}
	set := make([]model.Reason, 0, len(a.reasons))
	seen := map[string]bool{}
	for _, r := range a.reasons {
		if r.Weight == 0 || seen[r.Code] {
			continue
		}
		seen[r.Code] = true
		set = append(set, r)
	}
	sort.SliceStable(set, func(i, j int) bool { return set[i].Weight > set[j].Weight })
	return model.Risk{Level: t.Level(a.score), Score: a.score, Reasons: set, EvaluatedAt: now}
}

// Merge picks the worse of two risks (used when combining structural and
// scan views for the click decision).
func Merge(a, b model.Risk) model.Risk {
	if b.Level > a.Level || (b.Level == a.Level && b.Score > a.Score) {
		out := b
		out.Reasons = append(append([]model.Reason(nil), b.Reasons...), a.Reasons...)
		return out
	}
	out := a
	out.Reasons = append(append([]model.Reason(nil), a.Reasons...), b.Reasons...)
	return out
}

func looksLikeBrandAbuse(host string, terms []string) bool {
	labels := strings.Split(host, ".")
	for _, l := range labels {
		for _, t := range terms {
			if strings.Contains(l, t) && len(l) > len(t)+2 {
				return true
			}
		}
	}
	return false
}

func isCommonInfra(domain string) bool {
	switch domain {
	case "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
		"doubleclick.net", "facebook.com", "fbcdn.net", "cdn.jsdelivr.net", "jquery.com",
		"cloudflare.com", "cloudfront.net", "fonts.googleapis.com", "fonts.gstatic.com",
		"baidu.com", "bdstatic.com", "qq.com", "gtimg.com", "sina.com.cn", "weibo.com",
		"alicdn.com", "aliyun.com", "wx.qq.com", "weixin.qq.com", "hotjar.com",
		"segment.com", "sentry.io", "newrelic.com", "intercom.io", "zendesk.com":
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
