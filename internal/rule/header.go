package rule

import (
	"net/http"
	"strings"
)

type HeaderRule struct {
	enabled bool
	weight  int
	checks  map[string]int
}

var requiredHeaders = map[string]int{
	"accept":          3,
	"accept-language": 5,
	"accept-encoding": 2,
}

func NewHeaderRule(enabled bool, weight int, checks map[string]int) *HeaderRule {
	if checks == nil {
		checks = make(map[string]int)
	}
	return &HeaderRule{
		enabled: enabled,
		weight:  weight,
		checks:  checks,
	}
}

func (r *HeaderRule) Name() string  { return "http_header" }
func (r *HeaderRule) Weight() int   { return r.weight }
func (r *HeaderRule) Enabled() bool { return r.enabled }

func (r *HeaderRule) Evaluate(req *http.Request, ctx *Context) Result {
	score := 0
	matches := make([]string, 0)

	if s := r.checkMissingHeaders(req); s > 0 {
		score += s
		matches = append(matches, "missing required headers")
	}

	if s := r.checkSecFetch(req); s > 0 {
		score += s
		matches = append(matches, "Sec-Fetch headers absent")
	}

	if s := r.checkConnection(req); s > 0 {
		score += s
		matches = append(matches, "connection header anomaly")
	}

	score = min(score, r.weight)

	matched := score > 0
	detail := "headers ok"
	if matched {
		detail = strings.Join(matches, "; ")
	}

	return Result{
		Name:    r.Name(),
		Score:   score,
		Matched: matched,
		Details: detail,
	}
}

func (r *HeaderRule) checkMissingHeaders(req *http.Request) int {
	score := 0
	for name, points := range requiredHeaders {
		if req.Header.Get(name) == "" {
			score += points
		}
	}
	return score
}

func (r *HeaderRule) checkSecFetch(req *http.Request) int {
	hasSecFetch := false
	for _, h := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
		if req.Header.Get(h) != "" {
			hasSecFetch = true
			break
		}
	}
	if !hasSecFetch {
		ua := req.Header.Get("User-Agent")
		if strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Edg/") {
			return r.checksValue("missing_sec_fetch", 8)
		}
	}
	return 0
}

func (r *HeaderRule) checkConnection(req *http.Request) int {
	conn := strings.ToLower(req.Header.Get("Connection"))
	if conn == "close" {
		ua := req.Header.Get("User-Agent")
		if strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") {
			return r.checksValue("connection_close", 3)
		}
	}
	return 0
}

func (r *HeaderRule) checksValue(key string, defaultVal int) int {
	if v, ok := r.checks[key]; ok {
		return v
	}
	return defaultVal
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
