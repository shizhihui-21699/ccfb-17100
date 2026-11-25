package artifact

import (
	"testing"
)

func fp(mod func(*Fingerprint)) *Fingerprint {
	f := &Fingerprint{
		FinalURL:    "https://promo.partner.com/landing",
		Host:        "promo.partner.com",
		Registrable: "partner.com",
		Title:       "春季促销",
		TLSValid:    true,
	}
	if mod != nil {
		mod(f)
	}
	Stamp(f)
	return f
}

func TestCompareIdentical(t *testing.T) {
	a := fp(nil)
	b := fp(nil)
	b.Title = "春季促销 2026" // cosmetic
	d := Compare(a, b)
	if !d.IsClean() {
		t.Fatalf("expected clean, got hard deltas %+v", d.HardDeltas)
	}
	if len(d.SoftDeltas) == 0 {
		t.Fatal("expected a soft delta for title change")
	}
}

func TestCompareOrderInsensitive(t *testing.T) {
	a := fp(func(f *Fingerprint) {
		f.ThirdPartyDomains = []string{"a.com", "b.com"}
		f.FormActionHosts = []string{"x.com", "y.com"}
	})
	b := fp(func(f *Fingerprint) {
		f.ThirdPartyDomains = []string{"b.com", "a.com"}
		f.FormActionHosts = []string{"y.com", "x.com"}
	})
	if d := Compare(a, b); !d.IsClean() {
		t.Fatalf("reordering produced hard drift: %+v", d.HardDeltas)
	}
}

// The headline scenario: benign landing page approved, then swapped for a
// credential form posting to an attacker host.
func TestCompareDetectsPhishingSwap(t *testing.T) {
	baseline := fp(func(f *Fingerprint) {
		f.FormActionHosts = []string{"partner.com"}
		f.ThirdPartyDomains = []string{"google-analytics.com"}
	})
	swapped := fp(func(f *Fingerprint) {
		f.HasPassword = true
		f.PasswordForms = 1
		f.FormActionHosts = []string{"evil-collect.top"}
		f.ThirdPartyDomains = []string{"evil-collect.top"}
	})
	d := Compare(baseline, swapped)
	if d.IsClean() {
		t.Fatal("phishing swap not detected")
	}
	fields := map[string]bool{}
	for _, x := range d.HardDeltas {
		fields[x.Field] = true
	}
	for _, want := range []string{"has_password", "form_action_hosts", "third_party_domains"} {
		if !fields[want] {
			t.Errorf("missing hard delta %q; got %v", want, fields)
		}
	}
}

func TestCompareDetectsNewScriptOrigin(t *testing.T) {
	a := fp(func(f *Fingerprint) { f.ExternalScripts = []string{"https://cdn.partner.com/a.js"} })
	b := fp(func(f *Fingerprint) {
		f.ExternalScripts = []string{"https://cdn.partner.com/a.js", "https://x.evil.top/b.js"}
	})
	d := Compare(a, b)
	// Script origins are a soft delta by design...
	if len(d.SoftDeltas) == 0 {
		t.Fatal("expected soft delta for new script origin")
	}
	// ...but the third-party domain set is hard, and the scorer amplifies it.
}

func TestCompareTLSFlipIsHard(t *testing.T) {
	a := fp(nil)
	b := fp(func(f *Fingerprint) { f.TLSValid = false })
	d := Compare(a, b)
	if d.IsClean() {
		t.Fatal("TLS validity flip must be hard drift")
	}
}

func TestCompareNil(t *testing.T) {
	if Compare(nil, fp(nil)).IsClean() {
		t.Fatal("nil baseline must not compare clean")
	}
}
