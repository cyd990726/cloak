package rule

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// ReviewerRule detects HUMAN reviewers from ad platforms.
// This is NOT a bot detection rule — it specifically identifies people
// who manually review ads (Google Ads reviewers, Meta reviewers, etc.)
// using real browsers from ad platform offices.
//
// Key insight: human reviewers are technically indistinguishable from
// real users (same browser, same JS execution, same cookies).
// We can only detect them through:
//   1. IP/ASN signals (they browse from ad platform offices)
//   2. Context signals (no UTM, no ad referrer — they didn't click an ad)
//   3. Path signals (they visit /privacy, /terms — real users don't)
//   4. Timezone signals (review teams are in specific locations)
//
// This rule implements ReviewerChecker to return ActionReview (independent
// from the bot scoring system) and also Rule.Evaluate for scoring.
type ReviewerRule struct {
	enabled bool
	weight  int

	// Data sources (loaded from files, hot-reloadable)
	reviewerASNs  map[uint]bool    // ASN numbers of ad platforms
	reviewerCIDRs []*net.IPNet     // CIDR ranges of reviewer IPs

	// Confidence thresholds for reviewer detection
	// Minimum confidence (0-100) to trigger ActionReview
	reviewerThreshold int

	// Sub-weights for individual signals (contribute to confidence)
	asnWeight    int // IP is from a known ad platform ASN
	ipWeight     int // IP is in a known reviewer CIDR range
	noUTMWeight  int // no UTM/ad tracking params
	noRefWeight  int // no ad referrer
	pathWeight   int // visiting compliance pages (/privacy, /terms)
	tzWeight     int // timezone mismatch with target market

	// Target timezone offset in hours
	targetTZOffset int

	// Compliance page path patterns (reviewers visit these, real users don't)
	compliancePaths []string

	// File paths for hot-reloadable data
	asnFile string
	ipFile  string
}

type ReviewerConfig struct {
	Enabled    bool
	Weight     int
	ASNFile    string `yaml:"asn_file"`
	IPFile     string `yaml:"ip_file"`
	JA3File    string `yaml:"ja3_file"` // kept for config compat, not used
	TargetTZ   int    `yaml:"target_tz"`
	Threshold  int    `yaml:"threshold"` // min confidence to trigger review action
	ASNScore   int    `yaml:"asn_score"`
	IPScore    int    `yaml:"ip_score"`
	NoUTMScore int    `yaml:"no_utm_score"`
	NoRefScore int    `yaml:"no_ref_score"`
	PathScore  int    `yaml:"path_score"`
	TZScore    int    `yaml:"tz_score"`
}

func NewReviewerRule(cfg ReviewerConfig) *ReviewerRule {
	r := &ReviewerRule{
		enabled:          cfg.Enabled,
		weight:           cfg.Weight,
		reviewerASNs:     make(map[uint]bool),
		reviewerCIDRs:    make([]*net.IPNet, 0),
		reviewerThreshold: cfg.Threshold,
		targetTZOffset:   cfg.TargetTZ,
		asnFile:          cfg.ASNFile,
		ipFile:           cfg.IPFile,
		compliancePaths: []string{
			"/privacy", "/privacypolicy", "/privacy-policy",
			"/terms", "/termsofservice", "/terms-of-service",
			"/legal", "/legal-notice",
			"/cookie", "/cookie-policy", "/cookies",
			"/dmca", "/copyright",
			"/refund", "/returns", "/return-policy",
		},
	}

	// Default confidence threshold: 50 (out of 100)
	if r.reviewerThreshold == 0 {
		r.reviewerThreshold = 50
	}

	// Default sub-weights (these contribute to a 0-100 confidence score)
	r.asnWeight = cfg.ASNScore
	if r.asnWeight == 0 {
		r.asnWeight = 30
	}
	r.ipWeight = cfg.IPScore
	if r.ipWeight == 0 {
		r.ipWeight = 40
	}
	r.noUTMWeight = cfg.NoUTMScore
	if r.noUTMWeight == 0 {
		r.noUTMWeight = 8
	}
	r.noRefWeight = cfg.NoRefScore
	if r.noRefWeight == 0 {
		r.noRefWeight = 6
	}
	r.pathWeight = cfg.PathScore
	if r.pathWeight == 0 {
		r.pathWeight = 25
	}
	r.tzWeight = cfg.TZScore
	if r.tzWeight == 0 {
		r.tzWeight = 10
	}

	// Load data files
	if cfg.ASNFile != "" {
		r.loadASNFile(cfg.ASNFile)
	}
	if cfg.IPFile != "" {
		r.loadIPFile(cfg.IPFile)
	}

	return r
}

func (r *ReviewerRule) Name() string  { return "reviewer" }
func (r *ReviewerRule) Weight() int   { return r.weight }
func (r *ReviewerRule) Enabled() bool { return r.enabled }

// CheckReviewer implements ReviewerChecker.
// This is the PRIMARY interface for reviewer detection — it returns
// a confidence score and reason, independent from bot scoring.
func (r *ReviewerRule) CheckReviewer(req *http.Request, ctx *Context) ReviewerResult {
	confidence := 0
	reasons := make([]string, 0)

	// Signal 1: IP from known ad platform ASN
	if r.matchASN(ctx) {
		confidence += r.asnWeight
		reasons = append(reasons, fmt.Sprintf("ASN %s is ad platform", ctx.ASN))
	}

	// Signal 2: IP in known reviewer CIDR range
	if r.matchCIDR(ctx) {
		confidence += r.ipWeight
		reasons = append(reasons, fmt.Sprintf("IP in reviewer range"))
	}

	// Signal 3: No UTM parameters (real users arrive via ad clicks with UTM)
	if r.matchNoUTM(req) {
		confidence += r.noUTMWeight
		reasons = append(reasons, "no UTM params")
	}

	// Signal 4: No ad referrer (real users come from ad platform domains)
	if r.matchNoReferrer(req) {
		confidence += r.noRefWeight
		reasons = append(reasons, "no ad referrer")
	}

	// Signal 5: Visiting compliance pages (privacy/terms/legal)
	// This is a STRONG signal — real users almost never visit these pages
	if r.matchCompliancePath(req) {
		confidence += r.pathWeight
		reasons = append(reasons, "visiting compliance page")
	}

	// Signal 6: Timezone mismatch with target market
	if r.matchTZMismatch(ctx) {
		confidence += r.tzWeight
		reasons = append(reasons, "timezone mismatch")
	}

	// Cap confidence at 100
	if confidence > 100 {
		confidence = 100
	}

	isReviewer := confidence >= r.reviewerThreshold
	reason := "no reviewer signals"
	if len(reasons) > 0 {
		reason = strings.Join(reasons, "; ")
	}

	return ReviewerResult{
		IsReviewer: isReviewer,
		Confidence: confidence,
		Reason:     reason,
	}
}

// Evaluate implements Rule. For reviewer detection, this returns a score
// based on the same signals but within the normal scoring system.
// This is a fallback — the primary path is CheckReviewer.
func (r *ReviewerRule) Evaluate(req *http.Request, ctx *Context) Result {
	result := r.CheckReviewer(req, ctx)
	if !result.IsReviewer {
		return Result{
			Name:    r.Name(),
			Score:   0,
			Matched: false,
			Details: result.Reason,
		}
	}
	// Map confidence to score (proportional to rule weight)
	score := result.Confidence * r.weight / 100
	return Result{
		Name:    r.Name(),
		Score:   score,
		Matched: true,
		Details: result.Reason,
	}
}

// --- Signal matchers (return true if signal is present) ---

func (r *ReviewerRule) matchASN(ctx *Context) bool {
	if ctx.ASN == "" {
		return false
	}
	asnStr := strings.TrimPrefix(ctx.ASN, "AS")
	var asnNum uint
	fmt.Sscanf(asnStr, "%d", &asnNum)
	return r.reviewerASNs[asnNum]
}

func (r *ReviewerRule) matchCIDR(ctx *Context) bool {
	if ctx.ClientIP == nil {
		return false
	}
	for _, cidr := range r.reviewerCIDRs {
		if cidr.Contains(ctx.ClientIP) {
			return true
		}
	}
	return false
}

func (r *ReviewerRule) matchNoUTM(req *http.Request) bool {
	q := req.URL.Query()
	for _, key := range []string{
		"utm_source", "utm_medium", "utm_campaign",
		"utm_content", "utm_term",
		"gclid", "fbclid", "ttclid", "msclkid",
	} {
		if q.Get(key) != "" {
			return false // has ad tracking param → likely real user
		}
	}
	return true
}

func (r *ReviewerRule) matchNoReferrer(req *http.Request) bool {
	ref := req.Header.Get("Referer")
	if ref == "" {
		return true
	}
	refLower := strings.ToLower(ref)
	adDomains := []string{
		"google.com", "googleads", "googlesyndication", "g.doubleclick.net",
		"facebook.com", "fbcdn.net", "instagram.com",
		"tiktok.com", "bytedance.com",
		"bing.com", "microsoft.com",
		"twitter.com", "x.com",
		"pinterest.com", "snapchat.com",
		"reddit.com", "linkedin.com",
		"apple.com", "amazon.com",
	}
	for _, domain := range adDomains {
		if strings.Contains(refLower, domain) {
			return false // has ad referrer → likely real user
		}
	}
	return true
}

func (r *ReviewerRule) matchCompliancePath(req *http.Request) bool {
	pathLower := strings.ToLower(req.URL.Path)
	for _, cp := range r.compliancePaths {
		if strings.Contains(pathLower, cp) {
			return true
		}
	}
	return false
}

func (r *ReviewerRule) matchTZMismatch(ctx *Context) bool {
	if r.targetTZOffset == 0 || ctx.TZOffset == 0 {
		return false
	}
	diff := ctx.TZOffset - r.targetTZOffset
	if diff < 0 {
		diff = -diff
	}
	return diff > 2
}

// --- Data management ---

// ReloadData re-reads all data files without restarting the service.
func (r *ReviewerRule) ReloadData() {
	if r.asnFile != "" {
		newASNs := make(map[uint]bool)
		r.loadASNFileInto(r.asnFile, newASNs)
		r.reviewerASNs = newASNs
	}
	if r.ipFile != "" {
		newCIDRs := make([]*net.IPNet, 0)
		r.loadIPFileInto(r.ipFile, &newCIDRs)
		r.reviewerCIDRs = newCIDRs
	}
}

func (r *ReviewerRule) loadASNFile(path string) {
	r.loadASNFileInto(path, r.reviewerASNs)
}

func (r *ReviewerRule) loadASNFileInto(path string, target map[uint]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		var asn uint
		if _, err := fmt.Sscanf(line, "%d", &asn); err == nil && asn > 0 {
			target[asn] = true
		}
	}
}

func (r *ReviewerRule) loadIPFile(path string) {
	r.loadIPFileInto(path, &r.reviewerCIDRs)
}

func (r *ReviewerRule) loadIPFileInto(path string, target *[]*net.IPNet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		_, cidr, err := net.ParseCIDR(line)
		if err == nil {
			*target = append(*target, cidr)
		}
	}
}

// AddASN adds a single ASN (for programmatic use / API).
func (r *ReviewerRule) AddASN(asn uint) {
	r.reviewerASNs[asn] = true
}

// AddCIDR adds a CIDR range.
func (r *ReviewerRule) AddCIDR(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	r.reviewerCIDRs = append(r.reviewerCIDRs, network)
	return nil
}

// Stats returns the number of loaded entries for monitoring.
func (r *ReviewerRule) Stats() map[string]int {
	return map[string]int{
		"asns":  len(r.reviewerASNs),
		"cidrs": len(r.reviewerCIDRs),
	}
}
