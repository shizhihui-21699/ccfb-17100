// Command shortlinkd runs the short-link service: public redirect +
// interstitial, the internal admin API, and the patrol scanner loop.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shortlink/internal/artifact"
	"shortlink/internal/audit"
	"shortlink/internal/htmlx"
	"shortlink/internal/httpapi"
	"shortlink/internal/model"
	"shortlink/internal/netutil"
	"shortlink/internal/probe"
	"shortlink/internal/risk"
	"shortlink/internal/service"
	"shortlink/internal/store"
)

func main() {
	var (
		publicAddr   = flag.String("public-addr", ":8080", "public listen address (redirect + interstitial)")
		adminAddr    = flag.String("admin-addr", "127.0.0.1:8081", "admin API listen address (put behind SSO/mTLS)")
		baseURL      = flag.String("base-url", "http://localhost:8080", "public base URL used to build short links")
		selfHosts    = flag.String("self-hosts", "localhost", "comma-separated short-link hosts")
		allowlist    = flag.String("allowlist", "", "comma-separated partner domains seed (host or *.host)")
		firstParty   = flag.String("first-party", "", "comma-separated first-party domains")
		auditPath    = flag.String("audit-log", "", "path to the append-only audit log (empty = memory only)")
		sealKeyB64   = flag.String("seal-key", "", "base64 32-byte key for sealing baselines (empty = random per run)")
		scanEvery    = flag.Duration("scan-tick", 30*time.Second, "how often the patrol loop wakes up")
		scanBatch    = flag.Int("scan-batch", 50, "links per patrol tick")
		creatorCap   = flag.Int("creator-hourly-cap", 2000, "links a single creator may make per hour")
		allowPrivNet = flag.Bool("allow-private-net", false, "allow scanning private IPs (test/CI only)")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// --- wiring -----------------------------------------------------------
	mem := store.NewMemory()

	var domains []risk.Domain
	now := time.Now()
	for _, p := range splitCSV(*allowlist) {
		domains = append(domains, risk.Domain{Pattern: p, AddedAt: now, AddedBy: "bootstrap"})
	}
	for _, p := range splitCSV(*firstParty) {
		domains = append(domains, risk.Domain{Pattern: p, AddedAt: now, AddedBy: "bootstrap", FirstParty: true})
	}
	allow := risk.NewAllowlist(domains)
	scorer := risk.NewScorer(allow)

	var seals *service.SealKey
	if *sealKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(*sealKeyB64)
		if err != nil || len(key) < 16 {
			logger.Error("invalid -seal-key: want base64 of at least 16 bytes", "err", err)
			os.Exit(2)
		}
		seals = service.NewSealKey(key)
	} else {
		k, err := service.RandomSealKey()
		if err != nil {
			logger.Error("seal key", "err", err)
			os.Exit(2)
		}
		seals = k
		logger.Warn("using an ephemeral seal key; baselines will not survive a restart. Set -seal-key in production.")
	}

	var alog *audit.Log
	if *auditPath != "" {
		l, err := audit.Open(*auditPath)
		if err != nil {
			logger.Error("open audit log", "err", err)
			os.Exit(2)
		}
		alog = l
		defer alog.Close()
	} else {
		alog = audit.New()
		logger.Warn("audit log is in-memory; the tamper-evident trail will be lost on exit")
	}

	svc := service.New(service.Config{
		SelfHosts:           splitCSV(*selfHosts),
		ShortBaseURL:        *baseURL,
		CreatorLimitPerHour: *creatorCap,
		AllowPrivateNet:     *allowPrivNet,
		Resolver:            lookupIPs,
	}, mem, scorer, allow, seals, alog)

	// Scanner: probe + analyzer. User agents rotate so a target that sniffs the
	// reviewer's client cannot serve benign content only to that client.
	pr := probe.New(probe.Options{AllowPrivateNet: *allowPrivNet})
	rateLimitedFetch := newRateLimitedFetcher(pr, 20*time.Millisecond)
	svc.SetFetcher(
		func(ctx context.Context, raw string) (*service.ProbeResult, error) {
			res, err := rateLimitedFetch(ctx, raw)
			if err != nil {
				return nil, err
			}
			return &service.ProbeResult{
				FinalURL: res.FinalURL, StatusCode: res.StatusCode,
				Body: res.Body, TLSValid: res.TLSValid, TLSIssuer: res.TLSIssuer,
				Redirects: res.Redirects,
			}, nil
		},
		analyzePage,
	)

	// --- HTTP -------------------------------------------------------------
	srv := httpapi.New(svc, logger)
	publicSrv := &http.Server{
		Addr:              *publicAddr,
		Handler:           logMiddleware(logger, srv.PublicHandler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              *adminAddr,
		Handler:           logMiddleware(logger, srv.AdminHandler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("public listening", "addr", *publicAddr, "base", *baseURL)
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("public server", "err", err)
			stop()
		}
	}()
	go func() {
		logger.Info("admin listening", "addr", *adminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server", "err", err)
			stop()
		}
	}()

	// --- patrol loop ------------------------------------------------------
	go patrol(ctx, svc, *scanEvery, *scanBatch, logger)

	<-ctx.Done()
	logger.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = publicSrv.Shutdown(shutCtx)
	_ = adminSrv.Shutdown(shutCtx)
}

func patrol(ctx context.Context, svc *service.Service, every time.Duration, batch int, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		scanCtx, cancel := context.WithTimeout(ctx, every/2+time.Duration(batch)*2*time.Second)
		out, err := svc.ScanDue(scanCtx, batch)
		cancel()
		if err != nil {
			logger.Error("patrol", "err", err)
			continue
		}
		quar := 0
		for _, o := range out {
			if o.Quarantined {
				quar++
				logger.Warn("link quarantined", "link", o.LinkID, "code", o.Code, "reason", o.Risk.Level.String())
			}
		}
		if len(out) > 0 {
			logger.Info("patrol pass", "scanned", len(out), "quarantined", quar)
		}
	}
}

// analyzePage turns a probe result into a fingerprint.
func analyzePage(rawURL string, res *service.ProbeResult) *artifact.Fingerprint {
	u, err := parseURL(rawURL)
	if err != nil {
		return &artifact.Fingerprint{FinalURL: rawURL, TLSValid: res.TLSValid}
	}
	doc, _ := htmlx.Parse(res.Body, u)
	finalHost := netutil.HostOf(res.FinalURL)
	f := &artifact.Fingerprint{
		FinalURL:           res.FinalURL,
		Host:               finalHost,
		Registrable:        netutil.Registrable(finalHost),
		Title:              doc.Title,
		MetaRefreshTargets: doc.MetaRefresh,
		FrameSources:       doc.Iframes,
		TLSValid:           res.TLSValid,
		TLSIssuer:          res.TLSIssuer,
		JSRedirectTargets:  htmlx.JSRedirects(doc.InlineJS, u),
		BodySize:           len(res.Body),
	}
	seen := map[string]bool{}
	addTP := func(host string) {
		if host == "" || netutil.SameSite(host, finalHost) {
			return
		}
		reg := netutil.Registrable(host)
		if reg == "" || seen[reg] {
			return
		}
		seen[reg] = true
		f.ThirdPartyDomains = append(f.ThirdPartyDomains, reg)
	}
	for _, s := range doc.Scripts {
		f.ExternalScripts = append(f.ExternalScripts, s)
		addTP(netutil.HostOf(s))
	}
	for _, form := range doc.Forms {
		f.FormActions = append(f.FormActions, form.Action)
		if h := netutil.HostOf(form.Action); h != "" {
			f.FormActionHosts = append(f.FormActionHosts, h)
			addTP(h)
		}
		if form.HasPassword {
			f.HasPassword = true
			f.PasswordForms++
		}
	}
	for _, src := range doc.Iframes {
		addTP(netutil.HostOf(src))
	}
	artifact.Stamp(f)
	f.PageHash = hashBytes(res.Body)
	return f
}

func logMiddleware(l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		l.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.status = code
	s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(200)
	}
	return s.ResponseWriter.Write(b)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// keep model imported for future use of model.Creator in the wiring.
var _ = model.Creator{}
