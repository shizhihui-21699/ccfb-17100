// Package artifact fingerprints remote pages at the *structural* level.
//
// The threat we care about is a target that serves benign content to pass
// review and then swaps in a phishing page for real customers. Byte hashes
// of the whole body are useless here (rotating ads, session tokens, A/B
// tests), so we extract the features that actually distinguish "a marketing
// landing page" from "a credential-harvesting kit": where credentials are
// posted, whether the page can navigate the browser elsewhere, which
// registrable domains it talks to, and whether TLS is genuine.
package artifact

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Fingerprint is a comparable structural snapshot of one page.
type Fingerprint struct {
	FinalURL    string `json:"final_url"`
	Host        string `json:"host"`
	Registrable string `json:"registrable"`
	Title       string `json:"title,omitempty"`

	FormActionHosts []string `json:"form_action_hosts,omitempty"`
	FormActions     []string `json:"form_actions,omitempty"`
	HasPassword     bool     `json:"has_password"`
	PasswordForms   int      `json:"password_forms"`

	MetaRefreshTargets []string `json:"meta_refresh_targets,omitempty"`
	JSRedirectTargets  []string `json:"js_redirect_targets,omitempty"`
	FrameSources       []string `json:"frame_sources,omitempty"`
	ExternalScripts    []string `json:"external_scripts,omitempty"`

	// LinkHosts are hosts the page links out to (navigational surface).
	LinkHosts []string `json:"link_hosts,omitempty"`

	// ThirdPartyDomains is every non-first-party registrable domain the page
	// touches, deduplicated. This is the main "who does it phone home to" set.
	ThirdPartyDomains []string `json:"third_party_domains,omitempty"`

	TLSValid  bool   `json:"tls_valid"`
	TLSIssuer string `json:"tls_issuer,omitempty"`
	TLSHost   string `json:"tls_host,omitempty"`

	// ContentHash covers the extracted structure only, so it is stable across
	// cosmetic churn but changes when the page's behaviour changes.
	ContentHash string `json:"content_hash"`
	// PageHash is a coarse hash of normalized body text; a cheap drift signal.
	PageHash string `json:"page_hash"`
	BodySize int    `json:"body_size"`
}

func (f *Fingerprint) Clone() *Fingerprint {
	if f == nil {
		return nil
	}
	c := *f
	c.FormActionHosts = append([]string(nil), f.FormActionHosts...)
	c.FormActions = append([]string(nil), f.FormActions...)
	c.MetaRefreshTargets = append([]string(nil), f.MetaRefreshTargets...)
	c.JSRedirectTargets = append([]string(nil), f.JSRedirectTargets...)
	c.FrameSources = append([]string(nil), f.FrameSources...)
	c.ExternalScripts = append([]string(nil), f.ExternalScripts...)
	c.LinkHosts = append([]string(nil), f.LinkHosts...)
	c.ThirdPartyDomains = append([]string(nil), f.ThirdPartyDomains...)
	return &c
}

// Sealed is a fingerprint plus an HMAC over its canonical encoding. A page
// cannot claim "this is what was approved" without the server's key.
type Sealed struct {
	Fingerprint
	MAC string `json:"mac"`
}

// Store is where baselines live. Approving a link pins the sealed fingerprint;
// patrol re-seals before comparing.
type Store interface {
	Get(linkID string) (*Sealed, error)
	Put(linkID string, s *Sealed) error
	Delete(linkID string) error
}

// Drift describes the meaningful difference between an approved baseline and
// what the page is serving now.
type Drift struct {
	// HardDeltas are things that should always be treated as suspicious change.
	HardDeltas []Delta `json:"hard_deltas,omitempty"`
	// SoftDeltas are cosmetic/informational.
	SoftDeltas []Delta `json:"soft_deltas,omitempty"`
}

type Delta struct {
	Field  string   `json:"field"`
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
	Note   string   `json:"note,omitempty"`
}

func (d Drift) IsClean() bool { return len(d.HardDeltas) == 0 }

// Compare produces the drift between two fingerprints. Order is irrelevant.
func Compare(baseline, live *Fingerprint) Drift {
	if baseline == nil || live == nil {
		return Drift{HardDeltas: []Delta{{Field: "fingerprint", Note: "missing"}}}
	}
	var dr Drift

	// Credential capture appearing or moving is the single most important
	// signal; a landing page that grows a password form is not a landing page.
	if live.HasPassword != baseline.HasPassword {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "has_password",
			Note:  fmt.Sprintf("password form presence changed %v -> %v", baseline.HasPassword, live.HasPassword),
		})
	} else if live.PasswordForms != baseline.PasswordForms {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "password_forms",
			Note:  fmt.Sprintf("password form count %d -> %d", baseline.PasswordForms, live.PasswordForms),
		})
	}
	if b, a := setOf(baseline.FormActionHosts), setOf(live.FormActionHosts); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "form_action_hosts", Before: keysSorted(b), After: keysSorted(a),
			Note: "form submission target host changed",
		})
	} else if b, a := setOf(baseline.FormActions), setOf(live.FormActions); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "form_actions", Before: keysSorted(b), After: keysSorted(a),
			Note: "form submission path changed",
		})
	}
	if b, a := setOf(baseline.JSRedirectTargets), setOf(live.JSRedirectTargets); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "js_redirect_targets", Before: keysSorted(b), After: keysSorted(a),
			Note: "script-driven navigation changed",
		})
	}
	if b, a := setOf(baseline.MetaRefreshTargets), setOf(live.MetaRefreshTargets); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "meta_refresh_targets", Before: keysSorted(b), After: keysSorted(a),
			Note: "meta refresh target changed",
		})
	}
	if b, a := setOf(baseline.FrameSources), setOf(live.FrameSources); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "frame_sources", Before: keysSorted(b), After: keysSorted(a),
			Note: "embedded frame source changed",
		})
	}
	if b, a := setOf(baseline.ThirdPartyDomains), setOf(live.ThirdPartyDomains); !sameSet(b, a) {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "third_party_domains", Before: keysSorted(b), After: keysSorted(a),
			Note: "third-party domain set changed",
		})
	}
	if baseline.TLSValid != live.TLSValid {
		dr.HardDeltas = append(dr.HardDeltas, Delta{
			Field: "tls_valid",
			Note:  fmt.Sprintf("TLS validity changed %v -> %v", baseline.TLSValid, live.TLSValid),
		})
	}

	// Cosmetic.
	if baseline.FinalURL != live.FinalURL {
		dr.SoftDeltas = append(dr.SoftDeltas, Delta{Field: "final_url", Before: []string{baseline.FinalURL}, After: []string{live.FinalURL}})
	}
	if baseline.Title != live.Title {
		dr.SoftDeltas = append(dr.SoftDeltas, Delta{Field: "title", Before: []string{baseline.Title}, After: []string{live.Title}})
	}
	if baseline.PageHash != live.PageHash {
		dr.SoftDeltas = append(dr.SoftDeltas, Delta{Field: "page_hash", Note: "normalized body text differs"})
	}
	if b, a := setOf(baseline.ExternalScripts), setOf(live.ExternalScripts); !sameSet(b, a) {
		// New script origins are a common injection vector but also routine
		// analytics churn; treat as soft and let the scorer decide by origin.
		dr.SoftDeltas = append(dr.SoftDeltas, Delta{
			Field: "external_scripts", Before: keysSorted(b), After: keysSorted(a),
			Note: "external script sources changed",
		})
	}
	return dr
}

// CanonicalJSON is the byte form the MAC is computed over.
func (f *Fingerprint) CanonicalJSON() []byte {
	// Only fields that participate in drift detection matter, and they are
	// already sorted slices, so plain marshalling is deterministic.
	b, _ := json.Marshal(f)
	return b
}

func Stamp(f *Fingerprint) {
	h := sha256.New()
	h.Write([]byte(f.FinalURL))
	h.Write([]byte(f.Registrable))
	h.Write([]byte(joinSorted(f.FormActionHosts)))
	h.Write([]byte(joinSorted(f.FormActions)))
	h.Write([]byte(fmt.Sprintf("|pw=%v|n=%d|tls=%v", f.HasPassword, f.PasswordForms, f.TLSValid)))
	h.Write([]byte(joinSorted(f.JSRedirectTargets)))
	h.Write([]byte(joinSorted(f.MetaRefreshTargets)))
	h.Write([]byte(joinSorted(f.FrameSources)))
	h.Write([]byte(joinSorted(f.ThirdPartyDomains)))
	f.ContentHash = hex.EncodeToString(h.Sum(nil))[:32]
}

func joinSorted(xs []string) string {
	c := append([]string(nil), xs...)
	sort.Strings(c)
	return strings.Join(c, "\x1f")
}

func setOf(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// HostOf returns the lowercased host (no port) of an absolute URL, or "".
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// IsTLSError reports whether err came from certificate verification.
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	var ve *tls.CertificateVerificationError
	if ok := asErr(err, &ve); ok {
		return true
	}
	var uv tls.CertificateVerificationError
	_ = uv
	return strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate")
}

func asErr[T any](err error, target *T) bool {
	for err != nil {
		if e, ok := err.(T); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
