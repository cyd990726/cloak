package rule

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type UARule struct {
	enabled  bool
	weight   int
	patterns []*regexp.Regexp
}

func NewUARule(enabled bool, weight int, patterns []string) *UARule {
	r := &UARule{
		enabled:  enabled,
		weight:   weight,
		patterns: make([]*regexp.Regexp, 0),
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(p))
		if err == nil {
			r.patterns = append(r.patterns, re)
		}
	}
	return r
}

func (r *UARule) Name() string  { return "user_agent" }
func (r *UARule) Weight() int   { return r.weight }
func (r *UARule) Enabled() bool { return r.enabled }

func (r *UARule) Evaluate(req *http.Request, ctx *Context) Result {
	ua := req.Header.Get("User-Agent")
	if ua == "" {
		return Result{
			Name:    r.Name(),
			Score:   r.weight,
			Matched: true,
			Details: "empty User-Agent",
		}
	}

	for _, re := range r.patterns {
		if re.MatchString(ua) {
			return Result{
				Name:    r.Name(),
				Score:   r.weight,
				Matched: true,
				Details: fmt.Sprintf("User-Agent %q matched pattern %s", ua, re.String()),
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: "UA clean"}
}
