// Package service wires the pieces together: creation, click decisions,
// patrol scanning, and abuse response.
//
// The important architectural choice lives here: a click decision is computed
// fresh on every request from persisted state. Nothing about a click relies on
// "the link was safe when we approved it". That is what closes the
// approve-then-swap window: the swap shows up as either a quarantine (patrol
// noticed) or a still-active link that fails the click-time checks.
package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/audit"
	"shortlink/internal/dest"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
	"shortlink/internal/risk"
	"shortlink/internal/shortcode"
	"shortlink/internal/store"
)

var (
	ErrNotFound     = errors.New("service: link not found")
	ErrInvalidDest  = errors.New("service: invalid destination")
	ErrRateLimited  = errors.New("service: creator rate limit exceeded")
	ErrConflict     = errors.New("service: conflict")
	ErrNotRevocable = errors.New("service: already revoked")
)

type Config struct {
	SelfHosts           []string // short-link hosts; a target here is rejected
	ShortBaseURL        string   // e.g. "https://s.example.com"
	CodeLength          int
	CreatorLimitPerHour int
	// Patrol cadence bounds.
	MinScanInterval time.Duration
	MaxScanInterval time.Duration
	// BaselineRecheck forces a re-approval whenever the fingerprint changes at
	// all, even for soft deltas. Off by default: too noisy for real marketing.
	BaselineRecheck bool
	// AllowPrivateNet permits loopback/RFC1918 targets. Test/CI only; it
	// reintroduces SSRF if set in production.
	AllowPrivateNet bool
	// Resolver is used at creation time to reject hostnames that resolve to
	// private space. Optional.
	Resolver func(host string) ([]net.IP, error)
	Now      func() time.Time
}

func (c *Config) normalize() {
	if c.CodeLength == 0 {
		c.CodeLength = shortcode.DefaultLen
	}
	if c.CreatorLimitPerHour == 0 {
		c.CreatorLimitPerHour = 5000
	}
	if c.MinScanInterval == 0 {
		c.MinScanInterval = 1 * time.Hour
	}
	if c.MaxScanInterval == 0 {
		c.MaxScanInterval = 72 * time.Hour
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// SealKey signs approved fingerprints.
type SealKey struct{ key []byte }

func NewSealKey(key []byte) *SealKey { return &SealKey{key: key} }

func RandomSealKey() (*SealKey, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &SealKey{key: b}, nil
}

func (k *SealKey) sign(f *artifact.Fingerprint) string {
	m := hmac.New(sha256.New, k.key)
	m.Write(f.CanonicalJSON())
	return hex.EncodeToString(m.Sum(nil))
}

func (k *SealKey) Seal(f *artifact.Fingerprint) *artifact.Sealed {
	return &artifact.Sealed{Fingerprint: *f.Clone(), MAC: k.sign(f)}
}

func (k *SealKey) Verify(s *artifact.Sealed) bool {
	if s == nil {
		return false
	}
	want := k.sign(&s.Fingerprint)
	return hmac.Equal([]byte(want), []byte(s.MAC))
}

// ProbeResult mirrors the fields of probe.Result we use. Declared here to keep
// the service testable without pulling probe's transport into unit tests.
type ProbeResult struct {
	FinalURL   string
	StatusCode int
	Body       []byte
	TLSValid   bool
	TLSIssuer  string
	Redirects  []string
}

// Service is the application core.
type Service struct {
	cfg    Config
	store  store.Store
	scorer *risk.Scorer
	allow  atomic.Pointer[risk.Allowlist]
	codes  *shortcode.Generator
	seals  *SealKey
	audit  *audit.Log

	fetch   func(ctx context.Context, raw string) (*ProbeResult, error)
	analyze func(rawURL string, res *ProbeResult) *artifact.Fingerprint

	// baseline store for approved fingerprints (separate from link rows so a
	// sealed blob is not carried on every list query).
	baselines sync.Map // linkID -> *artifact.Sealed

	// ops counters
	clicks  atomic.Int64
	blocked atomic.Int64

	indexes struct {
		byDomain sync.Map // registrable -> *sync.Map(linkID -> struct{})
	}

	// nowFn is overridable for tests.
	nowFn func() time.Time
}

func New(cfg Config, st store.Store, sc *risk.Scorer, allow *risk.Allowlist, seals *SealKey, log *audit.Log) *Service {
	cfg.normalize()
	s := &Service{
		cfg:    cfg,
		store:  st,
		scorer: sc,
		codes:  shortcode.New(cfg.CodeLength),
		seals:  seals,
		audit:  log,
		nowFn:  cfg.Now,
	}
	s.allow.Store(allow)
	return s
}

// SetFetcher installs the probe-backed fetch/analyze pair. Kept as a setter so
// the HTTP tests can run without network access.
func (s *Service) SetFetcher(fetch func(ctx context.Context, raw string) (*ProbeResult, error),
	analyze func(rawURL string, res *ProbeResult) *artifact.Fingerprint) {
	s.fetch = fetch
	s.analyze = analyze
}

func (s *Service) SetAllowlist(a *risk.Allowlist) { s.allow.Store(a) }
func (s *Service) Allowlist() *risk.Allowlist     { return s.allow.Load() }
func (s *Service) Now() time.Time                 { return s.nowFn() }
func (s *Service) Audit() *audit.Log              { return s.audit }
func (s *Service) Store() store.Store             { return s.store }
func (s *Service) Clicks() int64                  { return s.clicks.Load() }
func (s *Service) BlockedClicks() int64           { return s.blocked.Load() }
func (s *Service) ShortBaseURL() string           { return s.cfg.ShortBaseURL }
func (s *Service) Config() Config                 { return s.cfg }

// --- creation --------------------------------------------------------------

type CreateRequest struct {
	Target    string
	Creator   model.Creator
	Campaign  string
	Tags      []string
	OriginIP  string
	RequestID string
}

type CreateResult struct {
	Link *model.Link `json:"link"`
	// ShortURL is what the user copies.
	ShortURL string `json:"short_url"`
	// Warning is shown in the UI when the link needs review or will show an
	// interstitial to recipients.
	Warning string `json:"warning,omitempty"`
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	now := s.nowFn()
	if strings.TrimSpace(req.Creator.ID) == "" {
		return nil, fmt.Errorf("%w: creator id required", ErrInvalidDest)
	}

	parsed, err := dest.Normalize(req.Target, dest.Options{
		SelfHosts:       s.cfg.SelfHosts,
		AllowPrivateNet: s.cfg.AllowPrivateNet,
		Resolver:        s.cfg.Resolver,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDest, err)
	}

	// Volume guard before anything else, so a compromised account cannot fill
	// the store while we compute scores.
	lastHour, err := s.store.CountByCreatorSince(req.Creator.ID, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	if lastHour >= s.cfg.CreatorLimitPerHour {
		s.logEvent("create_rate_limited", req.Creator, "", "", req.Target, map[string]string{
			"last_hour": strconv.Itoa(lastHour),
		})
		return nil, fmt.Errorf("%w (%d/hour)", ErrRateLimited, lastHour)
	}

	campaignDomains := 0
	if req.Campaign != "" {
		campaignDomains, _ = s.store.CountDistinctDomainsByCampaign(req.Campaign)
	}

	allow := s.allow.Load()
	sc := *s.scorer
	sc.Allow = allow
	dec := sc.DecideCreation(risk.CreationInput{
		Parsed:               parsed,
		Creator:              req.Creator,
		CreatorLinksLastHour: lastHour + 1,
		Campaign:             req.Campaign,
		CampaignDomains:      campaignDomains,
		Now:                  now,
	})

	code, err := s.newCode()
	if err != nil {
		return nil, err
	}
	id := newID()

	status := model.StatusPending
	warn := ""
	switch {
	case dec.Risk.Level >= model.LevelBlocked:
		// Do not even create a clickable row for an obviously hostile target.
		// Record the attempt (a repeated pattern from one account is itself
		// the signal) and refuse.
		s.logEvent("create_refused", req.Creator, "", "", req.Target, map[string]string{
			"risk": dec.Risk.Level.String(), "score": strconv.Itoa(dec.Risk.Score),
		})
		return nil, fmt.Errorf("%w: destination scored %s (%d): %s", ErrInvalidDest,
			dec.Risk.Level, dec.Risk.Score, topReason(dec.Risk))
	case dec.RequiresReview:
		status = model.StatusQuarantined
		warn = "该链接需要人工审核后才能对外投放"
	default:
		status = model.StatusPending
		if dec.ForceInterstitial {
			warn = "链接正在做安全检测;外部落地页在检测通过后仍会向收件人显示安全提示页"
		}
	}

	interval := s.scanInterval(dec.Risk.Level)
	l := &model.Link{
		ID:                id,
		Code:              code,
		Target:            parsed.Raw,
		Creator:           req.Creator,
		Campaign:          req.Campaign,
		Tags:              req.Tags,
		Status:            status,
		StructuralRisk:    dec.Risk,
		Risk:              dec.Risk,
		ForceInterstitial: dec.ForceInterstitial,
		CreatedAt:         now,
		UpdatedAt:         now,
		NextScanAt:        now, // due immediately for the async deep scan
		OriginIP:          req.OriginIP,
		RequestID:         req.RequestID,
		QuarantineReason: func() string {
			if dec.RequiresReview {
				return "creation_requires_review"
			}
			return ""
		}(),
	}
	_ = interval

	if err := s.store.Create(l); err != nil {
		return nil, err
	}
	s.indexAdd(l)

	s.logEvent("create", req.Creator, l.ID, l.Code, l.Target, map[string]string{
		"risk": dec.Risk.Level.String(), "score": strconv.Itoa(dec.Risk.Score),
		"status": string(status), "campaign": req.Campaign, "origin_ip": req.OriginIP,
	})

	return &CreateResult{
		Link:     l,
		ShortURL: strings.TrimRight(s.cfg.ShortBaseURL, "/") + "/" + l.Code,
		Warning:  warn,
	}, nil
}

func (s *Service) newCode() (string, error) {
	for i := 0; i < 8; i++ {
		c, err := s.codes.New()
		if err != nil {
			return "", err
		}
		if _, err := s.store.GetByCode(c); err == store.ErrNotFound {
			return c, nil
		}
	}
	return "", errors.New("service: could not allocate a unique code")
}

// --- click decision --------------------------------------------------------

// Decision is the outcome of a click. The caller (HTTP handler) renders one of
// three things based on it.
type Decision struct {
	Kind     DecisionKind `json:"kind"`
	Location string       `json:"location,omitempty"`
	Link     *model.Link  `json:"-"`
	Reason   string       `json:"reason,omitempty"`
	Level    model.Level  `json:"level"`
	// Token signs the interstitial "continue" so the user cannot hand-edit the
	// destination, and so the skip cannot be replayed to another link.
	Token    string    `json:"token,omitempty"`
	TokenExp time.Time `json:"token_exp,omitempty"`
}

type DecisionKind string

const (
	DecisionRedirect     DecisionKind = "redirect" // straight to target
	DecisionInterstitial DecisionKind = "interstitial"
	DecisionBlocked      DecisionKind = "blocked"
	DecisionRevoked      DecisionKind = "revoked"
	DecisionExpired      DecisionKind = "expired"
	DecisionNotFound     DecisionKind = "not_found"
)

// Resolve computes the decision for a code. It is deliberately pure with
// respect to the *stored risk*: it re-derives the effective level from the
// link's status, its two risk views, and the allowlist as of now.
func (s *Service) Resolve(code string) (*Decision, error) {
	now := s.nowFn()
	c, ok := shortcode.Normalize(code)
	if !ok {
		return &Decision{Kind: DecisionNotFound}, nil
	}
	l, err := s.store.GetByCode(c)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &Decision{Kind: DecisionNotFound}, nil
		}
		return nil, err
	}
	s.clicks.Add(1)

	switch l.Status {
	case model.StatusRevoked:
		return &Decision{Kind: DecisionRevoked, Link: l, Reason: l.RevokeReason, Level: model.LevelBlocked}, nil
	case model.StatusExpired:
		return &Decision{Kind: DecisionExpired, Link: l}, nil
	}

	effective := risk.Merge(l.StructuralRisk, l.ScanRisk)
	if l.Status == model.StatusQuarantined {
		// Quarantined beats everything: even a "clean" re-scan does not lift
		// it. A human must re-baseline.
		s.blocked.Add(1)
		return &Decision{
			Kind: DecisionBlocked, Link: l, Level: model.LevelHigh,
			Reason: firstNonEmpty(l.QuarantineReason, "quarantined"),
		}, nil
	}
	if effective.Level >= model.LevelBlocked {
		s.blocked.Add(1)
		return &Decision{Kind: DecisionBlocked, Link: l, Level: effective.Level, Reason: topReason(effective)}, nil
	}

	allow := s.allow.Load()
	firstParty := allow.FirstParty(netutil.HostOf(l.Target), now)
	_, hasBase := s.baseline(l.ID)

	// A link needs the warning wall unless it is first-party AND nobody forced
	// the wall on. An external link that a human cleared may still redirect
	// directly, but only while it is active and its live risk stays low.
	needsWall := true
	switch {
	case firstParty && !l.ForceInterstitial:
		needsWall = false
	case l.ForceInterstitial:
		needsWall = true
	case !hasBase || l.Baseline == nil:
		needsWall = true
	case l.Status == model.StatusActive && effective.Level <= model.LevelLow:
		needsWall = false
	}

	if needsWall {
		tok, exp := s.mintToken(l)
		return &Decision{
			Kind: DecisionInterstitial, Link: l, Level: effective.Level,
			Reason: interstitialReason(firstParty, hasBase, l.Status),
			Token:  tok, TokenExp: exp,
		}, nil
	}

	s.logEvent("click_redirect", model.Creator{ID: "system"}, l.ID, l.Code, l.Target, map[string]string{
		"level": effective.Level.String(),
	})
	return &Decision{Kind: DecisionRedirect, Link: l, Location: l.Target, Level: effective.Level}, nil
}

func interstitialReason(firstParty, hasBaseline bool, st model.Status) string {
	switch {
	case !firstParty && !hasBaseline:
		return "external_target_unscanned"
	case !firstParty:
		return "external_target"
	case st == model.StatusPending:
		return "scan_pending"
	default:
		return "review_pending"
	}
}

// Consent redeems an interstitial token and returns the destination. The token
// binds code + target + expiry, so it cannot be reused for a different link
// and cannot outlive a short window.
func (s *Service) Consent(code, token string) (*Decision, error) {
	l, err := s.store.GetByCode(strings.ToLower(strings.TrimSpace(code)))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &Decision{Kind: DecisionNotFound}, nil
		}
		return nil, err
	}
	if !s.verifyToken(l, token, s.nowFn()) {
		return &Decision{Kind: DecisionBlocked, Link: l, Reason: "invalid_consent_token"}, nil
	}
	// Re-check state: the link may have been quarantined in the seconds
	// between showing the warning and the user clicking through.
	if l.Status == model.StatusRevoked {
		return &Decision{Kind: DecisionRevoked, Link: l, Reason: l.RevokeReason}, nil
	}
	if l.Status == model.StatusQuarantined {
		return &Decision{Kind: DecisionBlocked, Link: l, Reason: firstNonEmpty(l.QuarantineReason, "quarantined")}, nil
	}
	eff := risk.Merge(l.StructuralRisk, l.ScanRisk)
	if eff.Level >= model.LevelBlocked {
		return &Decision{Kind: DecisionBlocked, Link: l, Reason: topReason(eff)}, nil
	}
	s.logEvent("click_consent", model.Creator{ID: "system"}, l.ID, l.Code, l.Target, map[string]string{
		"level": eff.Level.String(),
	})
	return &Decision{Kind: DecisionRedirect, Link: l, Location: l.Target, Level: eff.Level}, nil
}

// --- token ---------------------------------------------------------------

const tokenTTL = 10 * time.Minute

func (s *Service) mintToken(l *model.Link) (string, time.Time) {
	exp := s.nowFn().Add(tokenTTL)
	payload := l.Code + "\x00" + l.Target + "\x00" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, s.seals.key)
	mac.Write([]byte(payload))
	raw := payload + "\x00" + hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), exp
}

func (s *Service) verifyToken(l *model.Link, token string, now time.Time) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) != 4 {
		return false
	}
	code, target, expStr, sig := parts[0], parts[1], parts[2], parts[3]
	if code != l.Code || target != l.Target {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, s.seals.key)
	mac.Write([]byte(code + "\x00" + target + "\x00" + expStr))
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
}

// --- baselines -----------------------------------------------------------

func (s *Service) baseline(linkID string) (*artifact.Sealed, bool) {
	v, ok := s.baselines.Load(linkID)
	if !ok {
		return nil, false
	}
	sealed := v.(*artifact.Sealed)
	if !s.seals.Verify(sealed) {
		// A tampered baseline is worthless; treat as absent.
		return nil, false
	}
	return sealed, true
}

// --- scanning ------------------------------------------------------------

// ScanOutcome summarizes one patrol pass over a link.
type ScanOutcome struct {
	LinkID         string         `json:"link_id"`
	Code           string         `json:"code"`
	Status         model.Status   `json:"status"`
	Risk           model.Risk     `json:"risk"`
	Drift          artifact.Drift `json:"drift"`
	BecameBaseline bool           `json:"became_baseline"`
	Quarantined    bool           `json:"quarantined"`
	Err            string         `json:"err,omitempty"`
}

// ScanLink fetches the target, fingerprints it, compares against the approved
// baseline, scores, and persists the resulting state.
func (s *Service) ScanLink(ctx context.Context, linkID string) (*ScanOutcome, error) {
	if s.fetch == nil || s.analyze == nil {
		return nil, errors.New("service: no fetcher configured")
	}
	l, err := s.store.Get(linkID)
	if err != nil {
		return nil, err
	}
	now := s.nowFn()
	out := &ScanOutcome{LinkID: l.ID, Code: l.Code}

	if l.Status == model.StatusRevoked || l.Status == model.StatusExpired {
		return out, nil
	}

	res, ferr := s.fetch(ctx, l.Target)
	var fp *artifact.Fingerprint
	status := 0
	if ferr == nil && res != nil {
		fp = s.analyze(l.Target, res)
		status = res.StatusCode
	}

	allow := s.allow.Load()
	sc := *s.scorer
	sc.Allow = allow

	oldBaseline := l.Baseline
	var dr artifact.Drift
	if oldBaseline != nil && fp != nil {
		dr = artifact.Compare(oldBaseline, fp)
	}

	scanRisk := sc.ScoreScan(risk.ScanInput{
		Uncached:   l.StructuralRisk,
		Live:       fp,
		Baseline:   oldBaseline,
		Allow:      allow,
		Now:        now,
		HTTPStatus: status,
		FetchErr:   ferr,
	})

	l.ScanRisk = scanRisk
	l.Risk = risk.Merge(l.StructuralRisk, scanRisk)
	l.LastScanAt = now
	l.UpdatedAt = now
	out.Drift = dr
	out.Risk = l.Risk

	if ferr != nil {
		l.ScanFailures++
		out.Err = ferr.Error()
		// Back off, but never let a link stay unscanned for more than the max
		// interval: an attacker could otherwise DDoS the target's DNS to keep
		// the link on a stale baseline.
		l.NextScanAt = now.Add(s.backoff(l.ScanFailures))
		if l.Status == model.StatusPending && l.ScanFailures >= 3 {
			l.Status = model.StatusQuarantined
			l.QuarantineReason = "unreachable_during_review"
			out.Status = l.Status
			out.Quarantined = true
		}
		if err := s.store.Update(l); err != nil {
			return nil, err
		}
		return out, nil
	}

	l.ScanFailures = 0

	// Promotion path: a pending link that scans clean under the bar becomes
	// active and the first clean fingerprint becomes its baseline.
	switch {
	case l.Status == model.StatusPending:
		if l.Risk.Level <= model.LevelLow && fp != nil {
			l.Status = model.StatusActive
			l.Baseline = fp.Clone()
			s.storeBaseline(l.ID, fp)
			out.BecameBaseline = true
			s.logEvent("scan_promoted", model.Creator{ID: "patrol"}, l.ID, l.Code, l.Target, map[string]string{
				"score": strconv.Itoa(l.Risk.Score),
			})
		} else if l.Risk.Level >= model.LevelHigh {
			l.Status = model.StatusQuarantined
			l.QuarantineReason = "scan_failed_review:" + topReason(l.Risk)
			out.Quarantined = true
			s.logEvent("scan_quarantined", model.Creator{ID: "patrol"}, l.ID, l.Code, l.Target, map[string]string{
				"reason": l.QuarantineReason,
			})
		}
		// Medium stays pending with a shorter retry.

	case l.Status == model.StatusActive:
		if !dr.IsClean() {
			// Hard drift on an active, human-cleared link: this is exactly the
			// approve-then-swap attack. Quarantine immediately, do not wait for
			// the next scan.
			l.Status = model.StatusQuarantined
			l.QuarantineReason = "baseline_drift:" + driftSummary(dr)
			out.Quarantined = true
			s.logEvent("scan_quarantined", model.Creator{ID: "patrol"}, l.ID, l.Code, l.Target, map[string]string{
				"reason": l.QuarantineReason,
			})
		} else if l.Risk.Level >= model.LevelHigh {
			l.Status = model.StatusQuarantined
			l.QuarantineReason = "scan_high_risk:" + topReason(l.Risk)
			out.Quarantined = true
			s.logEvent("scan_quarantined", model.Creator{ID: "patrol"}, l.ID, l.Code, l.Target, map[string]string{
				"reason": l.QuarantineReason,
			})
		}
	}
	out.Status = l.Status

	// Adaptive cadence: risky links get watched more often. Cheap insurance.
	l.NextScanAt = now.Add(s.scanInterval(l.Risk.Level))
	if l.Status == model.StatusQuarantined {
		// Quarantined links still get scanned (to see if the page reverts),
		// but slowly.
		l.NextScanAt = now.Add(s.cfg.MaxScanInterval)
	}

	if err := s.store.Update(l); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) storeBaseline(linkID string, fp *artifact.Fingerprint) {
	s.baselines.Store(linkID, s.seals.Seal(fp))
}

func (s *Service) scanInterval(lvl model.Level) time.Duration {
	base := s.cfg.MaxScanInterval
	switch lvl {
	case model.LevelTrusted:
		base = 24 * time.Hour
	case model.LevelLow:
		base = 12 * time.Hour
	case model.LevelMedium:
		base = 4 * time.Hour
	case model.LevelHigh, model.LevelBlocked:
		base = s.cfg.MinScanInterval
	}
	if base < s.cfg.MinScanInterval {
		base = s.cfg.MinScanInterval
	}
	if base > s.cfg.MaxScanInterval {
		base = s.cfg.MaxScanInterval
	}
	return base
}

func (s *Service) backoff(failures int) time.Duration {
	d := time.Duration(failures*failures) * 15 * time.Minute
	if d > s.cfg.MaxScanInterval {
		d = s.cfg.MaxScanInterval
	}
	return d
}

// ScanDue scans every link whose next scan time has passed (bounded by limit).
func (s *Service) ScanDue(ctx context.Context, limit int) ([]*ScanOutcome, error) {
	now := s.nowFn()
	links, _, err := s.store.List(store.Query{DueBefore: now, Limit: limit})
	if err != nil {
		return nil, err
	}
	var out []*ScanOutcome
	for _, l := range links {
		if ctx.Err() != nil {
			break
		}
		o, err := s.ScanLink(ctx, l.ID)
		if err != nil {
			out = append(out, &ScanOutcome{LinkID: l.ID, Code: l.Code, Err: err.Error()})
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

// --- abuse response ------------------------------------------------------

// Revoke bans one link. Bans are immediate (click path checks status) and
// audited with the operator's identity.
func (s *Service) Revoke(linkID, actor, reason string) (*model.Link, error) {
	l, err := s.store.Get(linkID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if l.Status == model.StatusRevoked {
		return l, ErrNotRevocable
	}
	now := s.nowFn()
	l.Status = model.StatusRevoked
	l.RevokedAt = &now
	l.RevokedBy = actor
	l.RevokeReason = reason
	l.UpdatedAt = now
	if err := s.store.Update(l); err != nil {
		return nil, err
	}
	s.logEvent("revoke", model.Creator{ID: actor}, l.ID, l.Code, l.Target, map[string]string{
		"reason": reason, "creator_id": l.Creator.ID,
	})
	return l, nil
}

// CascadeResult reports a bulk takedown.
type CascadeResult struct {
	Revoked []string          `json:"revoked"`
	Skipped map[string]string `json:"skipped,omitempty"`
}

// RevokeCampaign bans every link under a campaign id.
func (s *Service) RevokeCampaign(campaign, actor, reason string) (*CascadeResult, error) {
	links, _, err := s.store.List(store.Query{Campaign: campaign})
	if err != nil {
		return nil, err
	}
	res := &CascadeResult{Skipped: map[string]string{}}
	for _, l := range links {
		if l.Status == model.StatusRevoked {
			res.Skipped[l.ID] = "already_revoked"
			continue
		}
		if _, err := s.Revoke(l.ID, actor, reason+" [campaign "+campaign+"]"); err != nil {
			res.Skipped[l.ID] = err.Error()
			continue
		}
		res.Revoked = append(res.Revoked, l.ID)
	}
	return res, nil
}

// RevokeCreator bans every live link from one creator. Used when an account is
// believed compromised; it is loud and audited for that reason.
func (s *Service) RevokeCreator(creatorID, actor, reason string) (*CascadeResult, error) {
	links, _, err := s.store.List(store.Query{CreatorID: creatorID})
	if err != nil {
		return nil, err
	}
	res := &CascadeResult{Skipped: map[string]string{}}
	for _, l := range links {
		if l.Status == model.StatusRevoked {
			res.Skipped[l.ID] = "already_revoked"
			continue
		}
		if _, err := s.Revoke(l.ID, actor, reason+" [creator "+creatorID+"]"); err != nil {
			res.Skipped[l.ID] = err.Error()
			continue
		}
		res.Revoked = append(res.Revoked, l.ID)
	}
	s.logEvent("revoke_creator", model.Creator{ID: actor}, "", "", "", map[string]string{
		"creator_id": creatorID, "count": strconv.Itoa(len(res.Revoked)), "reason": reason,
	})
	return res, nil
}

// RevokeDomain bans every live link whose registrable target domain matches.
// This is the fastest containment for a partner domain that got compromised:
// every link pointing at it goes dark at once.
func (s *Service) RevokeDomain(domain, actor, reason string) (*CascadeResult, error) {
	reg := netutil.Registrable(domain)
	links, _, err := s.store.List(store.Query{Domain: reg})
	if err != nil {
		return nil, err
	}
	res := &CascadeResult{Skipped: map[string]string{}}
	for _, l := range links {
		if l.Status == model.StatusRevoked {
			res.Skipped[l.ID] = "already_revoked"
			continue
		}
		if _, err := s.Revoke(l.ID, actor, reason+" [domain "+reg+"]"); err != nil {
			res.Skipped[l.ID] = err.Error()
			continue
		}
		res.Revoked = append(res.Revoked, l.ID)
	}
	s.logEvent("revoke_domain", model.Creator{ID: actor}, "", "", "", map[string]string{
		"domain": reg, "count": strconv.Itoa(len(res.Revoked)), "reason": reason,
	})
	return res, nil
}

// Report records a recipient-side abuse report. Three independent reports on
// one link auto-quarantine it pending review.
func (s *Service) Report(code, reason string) (*model.Link, error) {
	c, ok := shortcode.Normalize(code)
	if !ok {
		return nil, ErrNotFound
	}
	l, err := s.store.GetByCode(c)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	now := s.nowFn()
	l.Reports = append(l.Reports, model.Report{At: now, Reason: reason})
	l.ReportCount++
	l.UpdatedAt = now
	if l.Status == model.StatusActive && l.ReportCount >= 3 {
		l.Status = model.StatusQuarantined
		l.QuarantineReason = "recipient_reports"
	}
	if err := s.store.Update(l); err != nil {
		return nil, err
	}
	s.logEvent("report", model.Creator{ID: "public"}, l.ID, l.Code, l.Target, map[string]string{
		"reason": reason, "count": strconv.Itoa(l.ReportCount),
	})
	return l, nil
}

// Approve lets a reviewer clear a quarantined/pending link. If withBaseline is
// true, the current live fingerprint is captured as the new baseline; it must
// have been fetched by the scanner, not supplied by the caller, or the whole
// point is lost.
func (s *Service) Approve(ctx context.Context, linkID, actor, note string, withBaseline bool) (*model.Link, error) {
	l, err := s.store.Get(linkID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if s.fetch == nil || s.analyze == nil {
		return nil, errors.New("service: no fetcher configured; cannot approve without a live fingerprint")
	}
	// Re-fetch at approval time: approving means "what is live right now is
	// acceptable", never "what was live when the ticket was opened".
	res, ferr := s.fetch(ctx, l.Target)
	if ferr != nil {
		return nil, fmt.Errorf("approve: live fetch failed: %w", ferr)
	}
	fp := s.analyze(l.Target, res)
	allow := s.allow.Load()
	sc := *s.scorer
	sc.Allow = allow
	r := sc.ScoreScan(risk.ScanInput{
		Uncached: l.StructuralRisk, Live: fp, Baseline: nil, Allow: allow,
		Now: s.nowFn(), HTTPStatus: res.StatusCode,
	})
	if r.Level >= model.LevelBlocked {
		return nil, fmt.Errorf("%w: live page still scores %s: %s", ErrInvalidDest, r.Level, topReason(r))
	}
	now := s.nowFn()
	l.ScanRisk = r
	l.Risk = risk.Merge(l.StructuralRisk, r)
	l.Status = model.StatusActive
	l.QuarantineReason = ""
	l.LastScanAt = now
	l.UpdatedAt = now
	l.NextScanAt = now.Add(s.scanInterval(l.Risk.Level))
	l.Baseline = fp.Clone()
	l.ForceInterstitial = !allow.FirstParty(netutil.HostOf(l.Target), now)
	s.storeBaseline(l.ID, fp)
	if err := s.store.Update(l); err != nil {
		return nil, err
	}
	s.logEvent("approve", model.Creator{ID: actor}, l.ID, l.Code, l.Target, map[string]string{
		"note": note, "score": strconv.Itoa(l.Risk.Score), "baseline": l.Baseline.ContentHash,
	})
	return l, nil
}

// --- misc ----------------------------------------------------------------

func (s *Service) indexAdd(l *model.Link) {
	reg := netutil.Registrable(netutil.HostOf(l.Target))
	if reg == "" {
		return
	}
	v, _ := s.indexes.byDomain.LoadOrStore(reg, &sync.Map{})
	v.(*sync.Map).Store(l.ID, struct{}{})
}

func (s *Service) logEvent(action string, actor model.Creator, linkID, code, target string, meta map[string]string) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Append(audit.Event{
		Action: action, Actor: actor.ID, ActorDept: actor.Dept,
		LinkID: linkID, Code: code, Target: target, Meta: meta,
	})
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not recoverable in a useful way here
		panic(err)
	}
	return hex.EncodeToString(b)
}

func topReason(r model.Risk) string {
	if len(r.Reasons) == 0 {
		return r.Level.String()
	}
	return r.Reasons[0].Code
}

func driftSummary(d artifact.Drift) string {
	if len(d.HardDeltas) == 0 {
		return "soft"
	}
	return d.HardDeltas[0].Field
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
