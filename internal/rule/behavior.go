package rule

import (
	"fmt"
	"net/http"
	"strings"
)

// BehaviorRule detects reviewer-like browsing patterns using ONLY
// server-side observable signals — no JS beacon required.
//
// Key insight: we cannot rely on JS beacons because:
//   - First request has no behavior data yet
//   - Reviewers may not execute JS (some use simplified browsers)
//   - JS can be spoofed by sophisticated reviewers
//
// Instead, we detect behavior through:
//   1. Session path history (which pages they visited)
//   2. Request patterns (how many pages, how fast)
//   3. Compliance page visits (privacy/terms — strongest signal)
//   4. Cross-route browsing (reviewers check multiple landing pages)
//
// This rule also implements ReviewerChecker so it can contribute
// to the independent reviewer detection channel.
type BehaviorRule struct {
	enabled bool
	weight  int

	// Sub-weights for confidence scoring
	privacyVisitWeight int // visited privacy/terms page
	multiRouteWeight   int // visited 3+ different routes
	rapidMultiPage     int // 3+ pages in <5 seconds (bot-like but also reviewer pattern)
	complianceChain    int // visited landing page → privacy → terms in sequence
	noCTAPath          int // never visited a CTA path (download/buy/chat)

	// Confidence threshold for reviewer detection
	reviewerThreshold int
}

type BehaviorConfig struct {
	Enabled           bool `yaml:"enabled"`
	Weight            int  `yaml:"weight"`
	PrivacyVisitScore int  `yaml:"privacy_visit_score"`
	MultiRouteScore   int  `yaml:"multi_route_score"`
	RapidMultiScore   int  `yaml:"rapid_multi_score"`
	ComplianceChain   int  `yaml:"compliance_chain_score"`
	NoCTAScore        int  `yaml:"no_cta_score"`
	Threshold         int  `yaml:"threshold"`
}

func NewBehaviorRule(cfg BehaviorConfig) *BehaviorRule {
	r := &BehaviorRule{
		enabled:          cfg.Enabled,
		weight:           cfg.Weight,
		reviewerThreshold: cfg.Threshold,
	}

	r.privacyVisitWeight = cfg.PrivacyVisitScore
	if r.privacyVisitWeight == 0 {
		r.privacyVisitWeight = 30
	}
	r.multiRouteWeight = cfg.MultiRouteScore
	if r.multiRouteWeight == 0 {
		r.multiRouteWeight = 15
	}
	r.rapidMultiPage = cfg.RapidMultiScore
	if r.rapidMultiPage == 0 {
		r.rapidMultiPage = 10
	}
	r.complianceChain = cfg.ComplianceChain
	if r.complianceChain == 0 {
		r.complianceChain = 20
	}
	r.noCTAPath = cfg.NoCTAScore
	if r.noCTAPath == 0 {
		r.noCTAPath = 8
	}
	if r.reviewerThreshold == 0 {
		r.reviewerThreshold = 40
	}

	return r
}

func (r *BehaviorRule) Name() string  { return "behavior" }
func (r *BehaviorRule) Weight() int   { return r.weight }
func (r *BehaviorRule) Enabled() bool { return r.enabled }

// CheckReviewer implements ReviewerChecker.
// Uses session behavior data (from handler's session tracking)
// to determine if this looks like a reviewer.
func (r *BehaviorRule) CheckReviewer(req *http.Request, ctx *Context) ReviewerResult {
	confidence := 0
	reasons := make([]string, 0)

	if ctx.Behavior == nil {
		// No session data yet — check the current request path
		// If they're directly visiting a compliance page, that's a signal
		pathLower := strings.ToLower(req.URL.Path)
		if isCompliancePath(pathLower) {
			confidence += r.privacyVisitWeight
			reasons = append(reasons, "direct visit to compliance page")
		}
	} else {
		bh := ctx.Behavior

		// Signal 1: Visited privacy or terms page
		if bh.VisitedPrivacy || bh.VisitedTerms {
			confidence += r.privacyVisitWeight
			label := ""
			if bh.VisitedPrivacy {
				label = "privacy"
			}
			if bh.VisitedTerms {
				if label != "" {
					label += " + "
				}
				label += "terms"
			}
			reasons = append(reasons, fmt.Sprintf("visited %s page", label))
		}

		// Signal 2: Multiple route visits
		if bh.RouteCount >= 3 {
			confidence += r.multiRouteWeight
			reasons = append(reasons, fmt.Sprintf("%d routes in session", bh.RouteCount))
		}

		// Signal 3: Compliance chain — visited landing page then compliance pages
		if (bh.VisitedPrivacy || bh.VisitedTerms) && bh.RouteCount >= 2 {
			confidence += r.complianceChain
			reasons = append(reasons, "compliance page chain")
		}

		// Signal 4: Rapid multi-page browsing (3+ pages in short time)
		if bh.RouteCount >= 3 && bh.DwellMs > 0 && bh.DwellMs < 5000 {
			confidence += r.rapidMultiPage
			reasons = append(reasons, "rapid multi-page browsing")
		}

		// Signal 5: No CTA interaction at all
		// CTA paths typically contain: /download, /buy, /chat, /signup, /register
		if bh.RouteCount >= 2 && !hasCTAPath(ctx) {
			confidence += r.noCTAPath
			reasons = append(reasons, "no CTA path visited")
		}
	}

	if confidence > 100 {
		confidence = 100
	}

	isReviewer := confidence >= r.reviewerThreshold
	reason := "no reviewer behavior signals"
	if len(reasons) > 0 {
		reason = strings.Join(reasons, "; ")
	}

	return ReviewerResult{
		IsReviewer: isReviewer,
		Confidence: confidence,
		Reason:     reason,
	}
}

// Evaluate implements Rule. Returns a score within the normal scoring system.
func (r *BehaviorRule) Evaluate(req *http.Request, ctx *Context) Result {
	result := r.CheckReviewer(req, ctx)
	if !result.IsReviewer {
		return Result{
			Name:    r.Name(),
			Score:   0,
			Matched: false,
			Details: result.Reason,
		}
	}
	score := result.Confidence * r.weight / 100
	return Result{
		Name:    r.Name(),
		Score:   score,
		Matched: true,
		Details: result.Reason,
	}
}

// isCompliancePath checks if a URL path looks like a compliance/legal page.
func isCompliancePath(pathLower string) bool {
	complianceKeywords := []string{
		"/privacy", "/privacypolicy", "/privacy-policy",
		"/terms", "/termsofservice", "/terms-of-service",
		"/legal", "/legal-notice",
		"/cookie", "/cookie-policy",
		"/dmca", "/copyright",
		"/refund", "/return-policy",
	}
	for _, kw := range complianceKeywords {
		if strings.Contains(pathLower, kw) {
			return true
		}
	}
	return false
}

// hasCTAPath checks if the session has visited any CTA (call-to-action) paths.
func hasCTAPath(ctx *Context) bool {
	if ctx.Behavior == nil {
		return false
	}
	// The handler tracks visited paths in session.paths
	// For now, we use the Clicks field as a proxy — if clicks > 0,
	// the user likely interacted with a CTA
	return ctx.Behavior.Clicks > 0
}
