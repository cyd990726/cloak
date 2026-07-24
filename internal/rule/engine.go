package rule

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"cloak/internal/ja3"
)

type Action int

const (
	ActionPass      Action = iota
	ActionChallenge Action = iota
	ActionCloak     Action = iota
	ActionReview    Action = iota
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionChallenge:
		return "challenge"
	case ActionCloak:
		return "cloak"
	case ActionReview:
		return "review"
	default:
		return "unknown"
	}
}

type Verdict struct {
	Action  Action   `json:"action"`
	Score   int      `json:"score"`
	Total   int      `json:"total_max"`
	Details []string `json:"details"`
	Results []Result `json:"results"`
}

type Result struct {
	Name    string `json:"name"`
	Score   int    `json:"score"`
	Matched bool   `json:"matched"`
	Details string `json:"details"`
}

type BehaviorInfo struct {
	VisitedPrivacy bool
	VisitedTerms   bool
	RouteCount     int
	DwellMs        int64
	MaxScroll      int
	Clicks         int
}

type Context struct {
	ClientIP  net.IP
	ASN       string
	ASNOrg    string
	Country   string
	RDNS      string
	TZOffset  int
	Behavior  *BehaviorInfo
	mu        sync.RWMutex
}

type Rule interface {
	Name() string
	Weight() int
	Enabled() bool
	Evaluate(req *http.Request, ctx *Context) Result
}

type CountryChecker interface {
	Country(ip net.IP) string
}

type ReviewerResult struct {
	IsReviewer bool
	Confidence int
	Reason     string
}

type ReviewerChecker interface {
	CheckReviewer(req *http.Request, ctx *Context) ReviewerResult
}

type WhitelistResult struct {
	Whitelisted bool
	Reason      string
}

type WhitelistChecker interface {
	CheckWhitelist(req *http.Request, ctx *Context) WhitelistResult
}

type Engine struct {
	rules         []Rule
	threshold     int
	challengeMin  int
	countryGate   CountryChecker
	mu            sync.RWMutex
}

func NewEngine(threshold, challengeMin int, gate CountryChecker) *Engine {
	return &Engine{
		rules:        make([]Rule, 0),
		threshold:    threshold,
		challengeMin: challengeMin,
		countryGate:  gate,
	}
}

func (e *Engine) Register(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make([]Rule, len(e.rules))
	copy(cp, e.rules)
	return cp
}

// Judge runs the three-layer funnel:
//   Layer 1 (Country Gate): IP ∉ target country → cloaked
//   Layer 2 (Bot Gate): bot rules fire → cloaked
//   Layer 3 (Reviewer Gate): reviewer detected → compliance page
//   All layers pass → show real page
func (e *Engine) Judge(req *http.Request) Verdict {
	ctx := e.buildContext(req)

	// Whitelist bypass (administrative override)
	for _, r := range e.Rules() {
		if wc, ok := r.(WhitelistChecker); ok && r.Enabled() {
			if result := wc.CheckWhitelist(req, ctx); result.Whitelisted {
				return Verdict{
					Action:  ActionPass,
					Score:   -1,
					Total:   0,
					Details: []string{"whitelisted: " + result.Reason},
					Results: []Result{{Name: r.Name(), Score: -1, Matched: false, Details: result.Reason}},
				}
			}
		}
	}

	// Populate country from GeoIP, but the actual gate is in the handler
	if e.countryGate != nil {
		code := e.countryGate.Country(ctx.ClientIP)
		if code != "" {
			ctx.Country = code
		}
	}

	// ── Layer 2: Bot Gate (existing crawler/bot rules) ──
	totalMax := 0
	totalScore := 0
	botResults := make([]Result, 0)
	botDetails := make([]string, 0)

	for _, r := range e.Rules() {
		if !r.Enabled() {
			continue
		}
		if _, isReviewer := r.(ReviewerChecker); isReviewer {
			continue // reviewer rules run in Layer 3
		}
		totalMax += r.Weight()
		res := r.Evaluate(req, ctx)
		totalScore += res.Score
		botResults = append(botResults, res)
		if res.Matched && res.Details != "" {
			botDetails = append(botDetails, res.Details)
		}
	}

	if totalScore >= e.threshold {
		return Verdict{
			Action:  ActionCloak,
			Score:   totalScore,
			Total:   totalMax,
			Details: botDetails,
			Results: botResults,
		}
	}

	// ── Layer 3: Reviewer Gate ──
	for _, r := range e.Rules() {
		if rc, ok := r.(ReviewerChecker); ok && r.Enabled() {
			if result := rc.CheckReviewer(req, ctx); result.IsReviewer {
				botResults = append(botResults, Result{
					Name: r.Name(), Score: result.Confidence, Matched: true, Details: result.Reason,
				})
				return Verdict{
					Action:  ActionReview,
					Score:   result.Confidence,
					Total:   100,
					Details: []string{"reviewer: " + result.Reason},
					Results: botResults,
				}
			}
		}
	}

	// ── All gates passed ──
	// Challenge for borderline bot scores
	action := ActionPass
	if totalScore >= e.challengeMin {
		action = ActionChallenge
	}

	return Verdict{
		Action:  action,
		Score:   totalScore,
		Total:   totalMax,
		Details: botDetails,
		Results: botResults,
	}
}

func (e *Engine) buildContext(req *http.Request) *Context {
	ctx := &Context{}
	if ip := realIP(req); ip != "" {
		ctx.ClientIP = net.ParseIP(ip)
	}
	if bh, ok := req.Context().Value(BehaviorCtxKey).(*BehaviorInfo); ok {
		ctx.Behavior = bh
	}
	return ctx
}

type BehaviorCtxKeyType struct{}

var BehaviorCtxKey = BehaviorCtxKeyType{}

func realIP(req *http.Request) string {
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	return host
}

func JA3FromRequest(req *http.Request) string {
	if fp := ja3.FromContext(req.Context()); fp != nil {
		return fp.JA3Hash
	}
	for _, h := range []string{"X-JA3", "X-JA3-Hash", "X-TLS-Fingerprint", "X-SSL-Fingerprint"} {
		if v := strings.TrimSpace(req.Header.Get(h)); v != "" && (len(v) == 32 || len(v) == 64) {
			return v
		}
	}
	return ""
}
