package rule

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type ASNRule struct {
	enabled     bool
	weight      int
	patterns    []string
	ipBlacklist map[string]bool
	ipWhitelist map[string]bool
	lookup      ASNLookup
}

type ASNLookup interface {
	Lookup(ip net.IP) (asn string, org string, err error)
}

func NewASNRule(enabled bool, weight int, patterns, ipBlacklist, ipWhitelist []string, blacklistFile, whitelistFile string, lookup ASNLookup) *ASNRule {
	r := &ASNRule{
		enabled:     enabled,
		weight:      weight,
		patterns:    patterns,
		ipBlacklist: make(map[string]bool),
		ipWhitelist: make(map[string]bool),
		lookup:      lookup,
	}
	for _, ip := range ipBlacklist {
		ip = strings.TrimSpace(ip)
		if ip != "" { r.ipBlacklist[ip] = true }
	}
	for _, ip := range ipWhitelist {
		ip = strings.TrimSpace(ip)
		if ip != "" { r.ipWhitelist[ip] = true }
	}
	if blacklistFile != "" {
		loadIPFile(blacklistFile, r.ipBlacklist)
	}
	if whitelistFile != "" {
		loadIPFile(whitelistFile, r.ipWhitelist)
	}
	return r
}

func loadIPFile(path string, target map[string]bool) {
	f, err := os.Open(path)
	if err != nil { return }
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' { continue }
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" { target[line] = true }
	}
}

func (r *ASNRule) Name() string  { return "asn" }
func (r *ASNRule) Weight() int   { return r.weight }
func (r *ASNRule) Enabled() bool { return r.enabled }

func (r *ASNRule) Evaluate(req *http.Request, ctx *Context) Result {
	ip := ctx.ClientIP
	if ip == nil {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "no client IP"}
	}

	ipStr := ip.String()

	if r.ipWhitelist[ipStr] {
		return Result{Name: r.Name(), Score: -r.weight, Matched: false, Details: fmt.Sprintf("IP %s in whitelist", ipStr)}
	}

	if r.ipBlacklist[ipStr] {
		return Result{Name: r.Name(), Score: r.weight, Matched: true, Details: fmt.Sprintf("IP %s in blacklist", ipStr)}
	}

	asn, org, err := r.lookup.Lookup(ip)
	if err != nil || asn == "" {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("ASN lookup failed for %s: %v", ipStr, err)}
	}

	ctx.mu.Lock()
	ctx.ASN = asn
	ctx.ASNOrg = org
	ctx.mu.Unlock()

	orgLower := strings.ToLower(org)
	for _, pattern := range r.patterns {
		if strings.Contains(orgLower, strings.ToLower(pattern)) {
			return Result{
				Name:    r.Name(),
				Score:   r.weight,
				Matched: true,
				Details: fmt.Sprintf("ASN %s org %s matches pattern %s", asn, org, pattern),
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("ASN %s org %s no match", asn, org)}
}

// CheckWhitelist implements WhitelistChecker. If the IP is in the whitelist,
// the engine will skip all other rules and return ActionPass.
func (r *ASNRule) CheckWhitelist(req *http.Request, ctx *Context) WhitelistResult {
	if ctx.ClientIP == nil {
		return WhitelistResult{}
	}
	if r.ipWhitelist[ctx.ClientIP.String()] {
		return WhitelistResult{Whitelisted: true, Reason: fmt.Sprintf("IP %s in whitelist", ctx.ClientIP)}
	}
	return WhitelistResult{}
}
