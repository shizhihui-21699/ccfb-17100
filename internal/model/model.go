// Package model defines the core domain objects shared by the short-link
// service, the risk engine, the patrol scanner and the HTTP layer.
package model

import (
	"strconv"
	"time"

	"shortlink/internal/artifact"
)

// Level is an ordered risk level. Ordering is significant: higher means
// riskier, so callers can compare with >= / <=.
type Level int

const (
	LevelUnknown Level = iota
	LevelTrusted
	LevelLow
	LevelMedium
	LevelHigh
	LevelBlocked
)

func (l Level) String() string {
	switch l {
	case LevelTrusted:
		return "trusted"
	case LevelLow:
		return "low"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	case LevelBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

func (l Level) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(l.String())), nil }

func (l Level) AtLeast(o Level) bool { return l >= o }

type Reason struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"weight"`
}

// Risk is a scored verdict plus the human-readable reasons behind it.
type Risk struct {
	Level       Level     `json:"level"`
	Score       int       `json:"score"`
	Reasons     []Reason  `json:"reasons,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type Status string

const (
	// StatusPending: created, deep scan has not finished yet. Clicks go
	// through the interstitial, never straight to the destination.
	StatusPending Status = "pending"
	// StatusActive: cleared for normal redirect (subject to per-click rules).
	StatusActive Status = "active"
	// StatusQuarantined: a scan found something, or an operator flagged it.
	// Blocked until a human reviews and re-baselines.
	StatusQuarantined Status = "quarantined"
	StatusRevoked     Status = "revoked"
	StatusExpired     Status = "expired"
)

type Creator struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Dept string `json:"dept,omitempty"`
}

type Report struct {
	At         time.Time `json:"at"`
	SourceHash string    `json:"source_hash"`
	Reason     string    `json:"reason,omitempty"`
}

// Link is one short link. The target is immutable: "editing" a link means
// creating a new one, which removes a whole class of post-approval TOCTOU.
type Link struct {
	ID       string   `json:"id"`
	Code     string   `json:"code"`
	Target   string   `json:"target"`
	Creator  Creator  `json:"creator"`
	Campaign string   `json:"campaign,omitempty"`
	Tags     []string `json:"tags,omitempty"`

	Status Status `json:"status"`
	// StructuralRisk is the cheap creation-time assessment. It never decays.
	StructuralRisk Risk `json:"structural_risk"`
	// ScanRisk is recomputed from scratch on every patrol scan.
	ScanRisk Risk `json:"scan_risk"`
	// Risk is the merged view that click decisions use.
	Risk Risk `json:"risk"`

	// Baseline is the fingerprint a human (or the first clean scan) approved.
	// Patrol compares live fingerprints against it. Nil means "not yet
	// approved" and the link stays in the interstitial path.
	Baseline *artifact.Fingerprint `json:"baseline,omitempty"`

	ForceInterstitial bool `json:"force_interstitial,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	NextScanAt   time.Time `json:"next_scan_at,omitempty"`
	LastScanAt   time.Time `json:"last_scan_at,omitempty"`
	ScanFailures int       `json:"scan_failures"`

	QuarantineReason string   `json:"quarantine_reason,omitempty"`
	Reports          []Report `json:"reports,omitempty"`
	ReportCount      int      `json:"report_count"`

	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`

	// Creation provenance, kept for tracing abuse back to a person/session.
	OriginIP  string `json:"origin_ip,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Clone returns a deep-enough copy for handing out of the store without
// letting callers race on shared slices.
func (l *Link) Clone() *Link {
	if l == nil {
		return nil
	}
	c := *l
	c.Tags = append([]string(nil), l.Tags...)
	c.Reports = append([]Report(nil), l.Reports...)
	c.StructuralRisk.Reasons = append([]Reason(nil), l.StructuralRisk.Reasons...)
	c.ScanRisk.Reasons = append([]Reason(nil), l.ScanRisk.Reasons...)
	c.Risk.Reasons = append([]Reason(nil), l.Risk.Reasons...)
	c.Baseline = l.Baseline.Clone()
	return &c
}

// ReasonCodes returns the distinct reason codes for compact logging.
func (r Risk) ReasonCodes() []string {
	seen := make(map[string]bool, len(r.Reasons))
	out := make([]string, 0, len(r.Reasons))
	for _, x := range r.Reasons {
		if seen[x.Code] {
			continue
		}
		seen[x.Code] = true
		out = append(out, x.Code)
	}
	return out
}
