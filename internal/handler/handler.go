package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"cloak/internal/admin"
	"cloak/internal/cloaker"
	"cloak/internal/config"
	"cloak/internal/rule"
)

type session struct {
	firstSeen time.Time
	requests  int
	paths     []string
	behavior  *rule.BehaviorInfo
}

type Handler struct {
	cloaker  *cloaker.Cloaker
	proxies  map[string]*httputil.ReverseProxy
	sessions map[string]*session
	mu       sync.RWMutex
}

func NewHandler(c *cloaker.Cloaker) *Handler {
	h := &Handler{
		cloaker:  c,
		proxies:  make(map[string]*httputil.ReverseProxy),
		sessions: make(map[string]*session),
	}
	for _, route := range c.Config().Routes {
		if route.Upstream != "" {
			upstream, err := url.Parse(route.Upstream)
			if err != nil {
				log.Printf("[handler] invalid upstream for %s: %v", route.Path, err)
				continue
			}
			h.proxies[route.Path] = httputil.NewSingleHostReverseProxy(upstream)
		}
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Accept-CH", "Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-Viewport-Width, Sec-CH-Width")
	w.Header().Set("Critical-CH", "Sec-CH-Viewport-Width")

	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}

	if r.URL.Path == "/validate" && r.Method == "POST" {
		h.serveValidate(w, r)
		return
	}

	// Behavior beacon endpoint (called by JS in white pages)
	if r.URL.Path == "/_beh" && r.Method == "POST" {
		h.serveBehaviorBeacon(w, r)
		return
	}

	if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
		if !debugAllowed(r) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(admin.PanelHTML))
		return
	}

	if cp := h.cloaker.CompliancePage(r.URL.Path); cp != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(cp)
		return
	}

	sid := h.getOrCreateSession(w, r)
	ses := h.trackSession(sid, r.URL.Path)

	// Populate behavior info into request context for rules to use
	if ses.behavior != nil {
		ctx := r.Context()
		// We need to pass behavior data through the cloaker's Judge method.
		// The engine's buildContext doesn't have access to session data,
		// so we store it in a context value that the engine can read.
		ctx = context.WithValue(ctx, rule.BehaviorCtxKey, ses.behavior)
		r = r.WithContext(ctx)
	}

	// Layer 1: Country gate
	route := h.cloaker.RouteFor(r.URL.Path)
	if route != nil && len(route.TargetCountries) > 0 {
		ip := getClientIP(r)
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			code := h.cloaker.CountryCheck(ip)
			if code != "" {
				inTarget := false
				for _, tc := range route.TargetCountries {
					if strings.EqualFold(code, tc) {
						inTarget = true
						break
					}
				}
				if !inTarget {
					log.Printf("[country] %s blocked: country=%s not in %v", r.RemoteAddr, code, route.TargetCountries)
					h.serveCloak(w, r, route)
					return
				}
			}
		}
	}

	verdict := h.cloaker.Judge(r)

	log.Printf("[judge] %s %s → score=%d action=%s route=%s session=%s reqs=%d details=%v",
		r.RemoteAddr, r.URL.Path, verdict.Score, verdict.Action,
		func() string {
			if route != nil {
				return route.Type
			}
			return "-"
		}(),
		sid[:8], ses.requests, verdict.Details)

	if r.URL.Path == "/judge" || strings.HasSuffix(r.URL.Path, "/judge") || r.Header.Get("X-Debug") == "true" {
		if !debugAllowed(r) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"verdict": verdict,
			"session": map[string]interface{}{
				"id":       sid[:8],
				"requests": ses.requests,
				"age_ms":   time.Since(ses.firstSeen).Milliseconds(),
			},
		})
		return
	}

	switch verdict.Action {
	case rule.ActionPass:
		h.servePass(w, r, route)
	case rule.ActionChallenge:
		h.serveChallenge(w, r)
	case rule.ActionCloak:
		h.serveCloak(w, r, route)
	case rule.ActionReview:
		h.serveReview(w, r, route)
	}
}

func (h *Handler) getOrCreateSession(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("_csid")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}
	b := make([]byte, 16)
	rand.Read(b)
	sid := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     "_csid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   1800,
	})
	return sid
}

func (h *Handler) trackSession(sid, path string) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[sid]; ok {
		s.requests++
		if len(s.paths) < 20 {
			s.paths = append(s.paths, path)
		}
		// Detect privacy/terms page visits (reviewer signal)
		if s.behavior != nil {
			pathLower := strings.ToLower(path)
			if strings.Contains(pathLower, "/privacy") || strings.Contains(pathLower, "/privacypolicy") {
				s.behavior.VisitedPrivacy = true
			}
			if strings.Contains(pathLower, "/terms") || strings.Contains(pathLower, "/termsofservice") {
				s.behavior.VisitedTerms = true
			}
			// Count distinct routes
			routeSet := make(map[string]bool)
			for _, p := range s.paths {
				// Extract base route (first two path segments)
				parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
				if len(parts) > 0 {
					routeSet["/"+parts[0]] = true
				}
			}
			s.behavior.RouteCount = len(routeSet)
			s.behavior.DwellMs = time.Since(s.firstSeen).Milliseconds()
		}
		return s
	}
	s := &session{
		firstSeen: time.Now(),
		requests:  1,
		paths:     []string{path},
		behavior:  &rule.BehaviorInfo{},
	}
	h.sessions[sid] = s
	return s
}

func (h *Handler) servePass(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) {
	if route != nil && route.Upstream != "" {
		if proxy, ok := h.proxies[route.Path]; ok {
			proxy.ServeHTTP(w, r)
			return
		}
	}
	if route == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "pass"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(h.cloaker.WhitePage(route.Type))
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(h.cloaker.ChallengePage())
}

func (h *Handler) serveCloak(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	routeType := ""
	if route != nil {
		routeType = route.Type
	}
	w.Write(h.cloaker.WhitePage(routeType))
}

// serveReview handles detected ad platform reviewers.
// Reviewers see the white page (same as cloak) — the real ad page
// must never be shown to reviewers. The difference from cloak:
// this action is triggered by reviewer detection (not bot detection),
// so you can customize the response differently in the future
// (e.g., show a "compliance version" of the page).
func (h *Handler) serveReview(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	routeType := ""
	if route != nil {
		routeType = route.Type
	}
	w.Write(h.cloaker.WhitePage(routeType))
}

func (h *Handler) serveValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var fp map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "bad json"})
		return
	}

	pow, _ := fp["pow"].(string)
	ts, _ := fp["ts"].(float64)
	if pow == "" || ts == 0 || time.Now().UnixMilli()-int64(ts) > 300000 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "expired"})
		return
	}

	powParts := strings.SplitN(pow, ".", 3)
	if len(powParts) == 3 {
		prefix := powParts[0]
		nonce := powParts[1]
		powResult := powParts[2]
		var h uint32 = 0x811c9dc5
		s := prefix + nonce
		for i := 0; i < len(s); i++ {
			h ^= uint32(s[i])
			h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)
		}
		computed := fmt.Sprintf("%x", h)
		if !strings.HasPrefix(computed, "0000") || computed != powResult {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "pow invalid"})
			return
		}
	}

	payload, _ := json.Marshal(fp)
	tsStr := fmt.Sprintf("%d", int64(ts))

	signKey := h.cloaker.SignKey()
	if len(signKey) == 0 {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	fpB64 := base64.RawURLEncoding.EncodeToString(payload)
	data := tsStr + "." + fpB64

	mac := hmac.New(sha256.New, signKey)
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	cvValue := data + "." + sig
	http.SetCookie(w, &http.Cookie{
		Name:     "_cv",
		Value:    cvValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// serveBehaviorBeacon receives JS behavior reports from white pages.
// The JS sends scroll depth, click count, dwell time, etc.
// This data is stored in the session for the BehaviorRule to evaluate
// on subsequent requests.
func (h *Handler) serveBehaviorBeacon(w http.ResponseWriter, r *http.Request) {
	var report struct {
		SID       string `json:"sid"`
		Elapsed   int64  `json:"elapsed"`
		Scrolls   int    `json:"scrolls"`
		Clicks    int    `json:"clicks"`
		MaxScroll int    `json:"maxScroll"`
		Path      string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Find session and update behavior data
	if report.SID != "" {
		h.mu.Lock()
		if s, ok := h.sessions[report.SID]; ok && s.behavior != nil {
			s.behavior.DwellMs = report.Elapsed
			s.behavior.Clicks = report.Clicks
			if report.MaxScroll > s.behavior.MaxScroll {
				s.behavior.MaxScroll = report.MaxScroll
			}
		}
		h.mu.Unlock()
	}

	w.WriteHeader(http.StatusNoContent)
}

func getClientIP(r *http.Request) net.IP {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return net.ParseIP(strings.TrimSpace(xri))
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx >= 0 {
			return net.ParseIP(strings.TrimSpace(xff[:idx]))
		}
		return net.ParseIP(strings.TrimSpace(xff))
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

func debugAllowed(r *http.Request) bool {
	token := strings.TrimSpace(os.Getenv("CLOAK_ADMIN_TOKEN"))
	if token == "" {
		return false
	}
	if subtleConstantTimeEqual(r.Header.Get("X-Admin-Token"), token) {
		return true
	}
	return subtleConstantTimeEqual(r.URL.Query().Get("debug_token"), token)
}

func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
