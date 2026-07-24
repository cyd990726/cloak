package rule

import (
	"fmt"
	"net/http"
	"strings"
)

type IPTypeRule struct {
	enabled   bool
	weight    int
	cloudKeywords []string
}

var defaultCloudKeywords = []string{
	"cloud", "hosting", "datacenter", "data center",
	"vps", "dedicated server", "server hosting",
	"compute", "layer", "infrastructure",
	"colocation", "colo", "cdn",
	"internet services",
}

func NewIPTypeRule(enabled bool, weight int, cloudKeywords []string) *IPTypeRule {
	if len(cloudKeywords) == 0 {
		cloudKeywords = defaultCloudKeywords
	}
	r := &IPTypeRule{
		enabled:       enabled,
		weight:        weight,
		cloudKeywords: cloudKeywords,
	}
	return r
}

func (r *IPTypeRule) Name() string  { return "ip_type" }
func (r *IPTypeRule) Weight() int   { return r.weight }
func (r *IPTypeRule) Enabled() bool { return r.enabled }

func (r *IPTypeRule) Evaluate(req *http.Request, ctx *Context) Result {
	org := ctx.ASNOrg
	if org == "" {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "ASN org unknown"}
	}

	orgLower := strings.ToLower(org)

	for _, kw := range r.cloudKeywords {
		if strings.Contains(orgLower, strings.ToLower(kw)) {
			return Result{
				Name:    r.Name(),
				Score:   r.weight,
				Matched: true,
				Details: fmt.Sprintf("IP from datacenter/cloud: ASN org %q contains %q", org, kw),
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("ASN org %q appears residential", org)}
}
