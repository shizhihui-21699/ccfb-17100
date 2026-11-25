// Package httpapi is the HTTP surface: the public redirect endpoint, the
// interstitial, and the internal admin API.
package httpapi

import (
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shortlink/internal/audit"
	"shortlink/internal/model"
	"shortlink/internal/risk"
	"shortlink/internal/service"
	"shortlink/internal/store"
)

// Server builds the muxes. Two separate muxes on purpose: the public one is
// reachable from the internet, the admin one is mounted behind SSO/mTLS by the
// deployment and must never share middleware with the public one.
type Server struct {
	svc  *service.Service
	log  *slog.Logger
	pub  *http.ServeMux
	adm  *http.ServeMux
	tmpl *template.Template
}

func New(svc *service.Service, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{svc: svc, log: logger, pub: http.NewServeMux(), adm: http.NewServeMux(), tmpl: parseTemplates()}
	s.routes()
	return s
}

func (s *Server) PublicHandler() http.Handler { return s.pub }
func (s *Server) AdminHandler() http.Handler  { return s.adm }

func (s *Server) routes() {
	// Public.
	s.pub.HandleFunc("GET /{code}", s.handleResolve)
	s.pub.HandleFunc("GET /{code}/go", s.handleConsent)
	s.pub.HandleFunc("POST /{code}/report", s.handleReport)
	s.pub.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	// Admin.
	s.adm.HandleFunc("POST /api/links", s.handleCreate)
	s.adm.HandleFunc("GET /api/links", s.handleList)
	s.adm.HandleFunc("GET /api/links/{id}", s.handleGet)
	s.adm.HandleFunc("POST /api/links/{id}/revoke", s.handleRevoke)
	s.adm.HandleFunc("POST /api/links/{id}/approve", s.handleApprove)
	s.adm.HandleFunc("POST /api/links/{id}/scan", s.handleScan)
	s.adm.HandleFunc("POST /api/revoke/domain", s.handleRevokeDomain)
	s.adm.HandleFunc("POST /api/revoke/campaign", s.handleRevokeCampaign)
	s.adm.HandleFunc("POST /api/revoke/creator", s.handleRevokeCreator)
	s.adm.HandleFunc("GET /api/links/{id}/audit", s.handleAudit)
	s.adm.HandleFunc("GET /api/audit/verify", s.handleAuditVerify)
	s.adm.HandleFunc("GET /api/allowlist", s.handleAllowlist)
	s.adm.HandleFunc("POST /api/allowlist", s.handleAllowlistAdd)
	s.adm.HandleFunc("GET /api/stats", s.handleStats)
}

// --- public ----------------------------------------------------------------

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	d, err := s.svc.Resolve(code)
	if err != nil {
		s.log.Error("resolve failed", "code", code, "err", err)
		http.Error(w, "internal error", 500)
		return
	}
	switch d.Kind {
	case service.DecisionRedirect:
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, d.Location, http.StatusFound)
	case service.DecisionInterstitial:
		s.renderInterstitial(w, r, d)
	case service.DecisionBlocked:
		s.renderBlocked(w, r, d)
	case service.DecisionRevoked:
		s.renderBlocked(w, r, d)
	case service.DecisionExpired, service.DecisionNotFound:
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "链接不存在或已失效", http.StatusNotFound)
	default:
		http.Error(w, "unexpected", 500)
	}
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	token := r.URL.Query().Get("t")
	d, err := s.svc.Consent(code, token)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	if d.Kind == service.DecisionRedirect {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, d.Location, http.StatusFound)
		return
	}
	s.renderBlocked(w, r, d)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	reason := r.FormValue("reason")
	if len(reason) > 500 {
		reason = reason[:500]
	}
	if _, err := s.svc.Report(code, reason); err != nil {
		http.Error(w, "上报失败", http.StatusBadRequest)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "received"})
}

func (s *Server) renderInterstitial(w http.ResponseWriter, r *http.Request, d *service.Decision) {
	if d.Link == nil {
		http.Error(w, "bad state", 500)
		return
	}
	dest, err := url.Parse(d.Link.Target)
	if err != nil {
		http.Error(w, "bad state", 500)
		return
	}
	rawHost := d.Link.Target
	host := dest.Hostname()

	data := map[string]any{
		"Code":        d.Link.Code,
		"Host":        host,
		"Registrable": registrableOrHost(host),
		"Target":      d.Link.Target,
		"Reason":      d.Reason,
		"ReasonText":  interstitialText(d.Reason),
		"Token":       d.Token,
		"Expires":     d.TokenExp.Format(time.RFC3339),
		"HTTPS":       strings.HasPrefix(d.Link.Target, "https://"),
		"Raw":         rawHost,
	}
	// The interstitial is a strong anti-phishing control only if it cannot be
	// framed or cached, and if it does not leak the target as a referrer.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	if err := s.tmpl.ExecuteTemplate(w, "interstitial", data); err != nil {
		s.log.Error("render interstitial", "err", err)
	}
}

func (s *Server) renderBlocked(w http.ResponseWriter, r *http.Request, d *service.Decision) {
	code := r.PathValue("code")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusGone)
	reason := ""
	if d.Link != nil {
		reason = d.Reason
	}
	_ = s.tmpl.ExecuteTemplate(w, "blocked", map[string]any{
		"Code":   code,
		"Reason": reasonText(reason),
	})
}

func interstitialText(reason string) string {
	switch reason {
	case "external_target_unscanned":
		return "该链接指向一个尚未完成安全检测的外部网站。"
	case "external_target":
		return "该链接将离开本公司域名,前往外部合作方网站。"
	case "scan_pending":
		return "该链接正在进行安全检测,请谨慎访问。"
	default:
		return "该链接将前往外部网站。"
	}
}

func reasonText(reason string) string {
	switch {
	case strings.HasPrefix(reason, "baseline_drift"):
		return "链接目标页面在审核通过后发生了实质变化,系统已自动拦截。"
	case reason == "recipient_reports":
		return "该链接已收到多个用户举报,已被暂停使用。"
	case strings.HasPrefix(reason, "scan_"):
		return "安全检测发现该链接目标页存在风险,已被自动拦截。"
	case reason == "unreachable_during_review":
		return "链接目标页在审核期间无法访问,已被暂停。"
	case reason != "":
		return "该链接已被安全团队暂停使用。"
	default:
		return "该链接已被暂停使用。"
	}
}

// --- admin: creation & listing ---------------------------------------------

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target      string   `json:"target"`
		CreatorID   string   `json:"creator_id"`
		CreatorName string   `json:"creator_name"`
		Dept        string   `json:"dept"`
		Campaign    string   `json:"campaign"`
		Tags        []string `json:"tags"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, 400, "bad_json", err.Error())
		return
	}
	creator := model.Creator{ID: req.CreatorID, Name: req.CreatorName, Dept: req.Dept}
	res, err := s.svc.Create(r.Context(), service.CreateRequest{
		Target: req.Target, Creator: creator, Campaign: req.Campaign, Tags: req.Tags,
		OriginIP: clientIP(r), RequestID: r.Header.Get("X-Request-Id"),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRateLimited):
			writeErr(w, 429, "rate_limited", err.Error())
		case errors.Is(err, service.ErrInvalidDest):
			writeErr(w, 422, "invalid_target", err.Error())
		default:
			writeErr(w, 500, "internal", err.Error())
		}
		return
	}
	writeJSON(w, 201, res)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := store.Query{
		CreatorID: r.URL.Query().Get("creator_id"),
		Campaign:  r.URL.Query().Get("campaign"),
		Status:    model.Status(r.URL.Query().Get("status")),
		Domain:    r.URL.Query().Get("domain"),
		Code:      r.URL.Query().Get("code"),
	}
	q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	q.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	links, total, err := s.svc.Store().List(q)
	if err != nil {
		writeErr(w, 500, "internal", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": links, "total": total})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	l, err := s.svc.Store().Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "not_found", "link not found")
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	if req.Reason == "" {
		writeErr(w, 400, "reason_required", "a revoke reason is required for the audit trail")
		return
	}
	l, err := s.svc.Revoke(r.PathValue("id"), actorOr(req.Actor), req.Reason)
	if err != nil {
		if errors.Is(err, service.ErrNotRevocable) {
			writeJSON(w, 200, map[string]any{"link": l, "note": "already revoked"})
			return
		}
		writeErr(w, 404, "not_found", "link not found")
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actor string `json:"actor"`
		Note  string `json:"note"`
	}
	_ = decodeJSON(r, &req)
	l, err := s.svc.Approve(r.Context(), r.PathValue("id"), actorOr(req.Actor), req.Note, true)
	if err != nil {
		writeErr(w, 422, "approve_failed", err.Error())
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.ScanLink(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, "scan_failed", err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleRevokeDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Domain == "" || req.Reason == "" {
		writeErr(w, 400, "bad_request", "domain and reason are required")
		return
	}
	res, err := s.svc.RevokeDomain(req.Domain, actorOr(req.Actor), req.Reason)
	if err != nil {
		writeErr(w, 500, "internal", err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleRevokeCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Campaign string `json:"campaign"`
		Actor    string `json:"actor"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Campaign == "" || req.Reason == "" {
		writeErr(w, 400, "bad_request", "campaign and reason are required")
		return
	}
	res, err := s.svc.RevokeCampaign(req.Campaign, actorOr(req.Actor), req.Reason)
	if err != nil {
		writeErr(w, 500, "internal", err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleRevokeCreator(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CreatorID string `json:"creator_id"`
		Actor     string `json:"actor"`
		Reason    string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil || req.CreatorID == "" || req.Reason == "" {
		writeErr(w, 400, "bad_request", "creator_id and reason are required")
		return
	}
	res, err := s.svc.RevokeCreator(req.CreatorID, actorOr(req.Actor), req.Reason)
	if err != nil {
		writeErr(w, 500, "internal", err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events := s.svc.Audit().ForLink(r.PathValue("id"))
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Audit().Verify(); err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	entries := s.svc.Audit().Entries()
	writeJSON(w, 200, map[string]any{"ok": true, "entries": len(entries)})
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"domains": s.svc.Allowlist().All()})
}

func (s *Server) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern    string `json:"pattern"`
		Owner      string `json:"owner"`
		Note       string `json:"note"`
		FirstParty bool   `json:"first_party"`
		Actor      string `json:"actor"`
		TTLHours   int    `json:"ttl_hours"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Pattern == "" {
		writeErr(w, 400, "bad_request", "pattern is required")
		return
	}
	now := s.svc.Now()
	d := risk.Domain{Pattern: req.Pattern, Owner: req.Owner, Note: req.Note, FirstParty: req.FirstParty, AddedAt: now, AddedBy: actorOr(req.Actor)}
	if req.TTLHours > 0 {
		exp := now.Add(time.Duration(req.TTLHours) * time.Hour)
		d.ExpiresAt = &exp
	}
	cur := s.svc.Allowlist().All()
	cur = append(cur, d)
	s.svc.SetAllowlist(risk.NewAllowlist(cur))
	writeJSON(w, 201, d)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"clicks":         s.svc.Clicks(),
		"blocked_clicks": s.svc.BlockedClicks(),
	})
}

// --- helpers ---------------------------------------------------------------

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func actorOr(actor string) string {
	if strings.TrimSpace(actor) == "" {
		return "unknown"
	}
	return actor
}

func clientIP(r *http.Request) string {
	// Only trust XFF if a trusted proxy set it; here we record the socket peer
	// and leave XFF to the gateway. Kept explicit so nobody "helpfully" starts
	// trusting a client-supplied header.
	if host, _, err := splitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, "", nil
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

func registrableOrHost(host string) string { return host }

// Unused import guard for audit (kept for the compile-time link to that pkg).
var _ = audit.Event{}
