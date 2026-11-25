package risk

import (
	"net/url"
	"testing"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/dest"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
)

func scorerWith(doms ...Domain) *Scorer {
	return NewScorer(NewAllowlist(doms))
}

func parsed(host, scheme string) *dest.Parsed {
	u, _ := url.Parse(scheme + "://" + host + "/")
	return &dest.Parsed{
		Raw: scheme + "://" + host + "/", URL: u, Scheme: scheme,
		Host: host, Registrable: host, IsIP: netutil.IsIP(host),
	}
}

func TestCreationUnknownDomainIsLowMediumNotBlocked(t *testing.T) {
	s := scorerWith()
	r := s.ScoreCreation(CreationInput{
		Parsed: parsed("brand-new.example", "https"),
		Now:    time.Now(),
	})
	// unknown_domain (30) only.
	if r.Score != 30 || r.Level != model.LevelMedium {
		t.Fatalf("got %d %s, want 30 medium", r.Score, r.Level)
	}
}

func TestCreationMixedSignalsAccumulate(t *testing.T) {
	s := scorerWith()
	r := s.ScoreCreation(CreationInput{
		// http + unknown + ip literal
		Parsed: parsed("198.51.100.7", "http"),
		Now:    time.Now(),
	})
	if r.Level < model.LevelHigh {
		t.Fatalf("expected high+, got %d %s: %+v", r.Score, r.Level, r.Reasons)
	}
}

// Regression: the scan score must not double-count the structural floor.
func TestScanDoesNotDoubleCountStructural(t *testing.T) {
	s := scorerWith(Domain{Pattern: "partner.com"})
	structural := model.Risk{Level: model.LevelMedium, Score: 30, Reasons: []model.Reason{
		{Code: "unknown_domain", Weight: 30},
	}}
	live := &artifact.Fingerprint{
		FinalURL: "https://promo.partner.com/x", Host: "promo.partner.com",
		Registrable: "partner.com", TLSValid: true,
	}
	r := s.ScoreScan(ScanInput{
		Uncached: structural, Live: live, Allow: s.Allow, Now: time.Now(), HTTPStatus: 200,
	})
	// Floor is 30; a clean page adds nothing. Must be 30, not 60+.
	if r.Score != 30 {
		t.Fatalf("double counted: got %d, want 30 (%+v)", r.Score, r.Reasons)
	}
	if r.Level != model.LevelMedium {
		t.Fatalf("level %s", r.Level)
	}
}

func TestScanCleanPartnershipIsLow(t *testing.T) {
	s := scorerWith(Domain{Pattern: "partner.com"})
	structural := model.Risk{Level: model.LevelLow, Score: 10, Reasons: []model.Reason{
		{Code: "scheme_http", Weight: 10},
	}}
	live := &artifact.Fingerprint{
		FinalURL: "https://promo.partner.com/x", Host: "promo.partner.com",
		Registrable: "partner.com", TLSValid: true,
	}
	r := s.ScoreScan(ScanInput{Uncached: structural, Live: live, Allow: s.Allow, Now: time.Now(), HTTPStatus: 200})
	if r.Level > model.LevelLow {
		t.Fatalf("clean partner page should be low, got %s (%d): %+v", r.Level, r.Score, r.Reasons)
	}
}

func TestScanPasswordFormBlocks(t *testing.T) {
	s := scorerWith(Domain{Pattern: "partner.com"})
	live := &artifact.Fingerprint{
		FinalURL: "https://promo.partner.com/x", Host: "promo.partner.com",
		Registrable: "partner.com", TLSValid: true,
		HasPassword: true, PasswordForms: 1,
		FormActionHosts: []string{"evil.top"}, FormActions: []string{"https://evil.top/p"},
	}
	r := s.ScoreScan(ScanInput{Live: live, Allow: s.Allow, Now: time.Now(), HTTPStatus: 200})
	if r.Level < model.LevelHigh {
		t.Fatalf("password form should be high+, got %s (%d)", r.Level, r.Score)
	}
	codes := r.ReasonCodes()
	found := false
	for _, c := range codes {
		if c == "password_form" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing password_form reason: %v", codes)
	}
}

func TestDriftAddsOnTop(t *testing.T) {
	s := scorerWith(Domain{Pattern: "partner.com"})
	base := &artifact.Fingerprint{
		FinalURL: "https://promo.partner.com/x", Host: "promo.partner.com",
		Registrable: "partner.com", TLSValid: true,
	}
	live := &artifact.Fingerprint{
		FinalURL: "https://promo.partner.com/x", Host: "promo.partner.com",
		Registrable: "partner.com", TLSValid: true,
		HasPassword: true, FormActionHosts: []string{"evil.top"},
	}
	r := s.ScoreScan(ScanInput{Baseline: base, Live: live, Allow: s.Allow, Now: time.Now(), HTTPStatus: 200})
	if r.Level < model.LevelHigh {
		t.Fatalf("drift should escalate, got %s (%d)", r.Level, r.Score)
	}
}
