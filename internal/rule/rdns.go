package rule

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rDNSCacheEntry struct {
	hostname string
	expires  time.Time
}

type RDNSRule struct {
	enabled  bool
	weight   int
	patterns []string
	cacheTTL time.Duration
	cache    map[string]*rDNSCacheEntry
	mu       sync.RWMutex
}

func NewRDNSRule(enabled bool, weight int, patterns []string, cacheTTL int) *RDNSRule {
	if cacheTTL <= 0 {
		cacheTTL = 300
	}
	return &RDNSRule{
		enabled:  enabled,
		weight:   weight,
		patterns: patterns,
		cacheTTL: time.Duration(cacheTTL) * time.Second,
		cache:    make(map[string]*rDNSCacheEntry),
	}
}

func (r *RDNSRule) Name() string  { return "rdns" }
func (r *RDNSRule) Weight() int   { return r.weight }
func (r *RDNSRule) Enabled() bool { return r.enabled }

func (r *RDNSRule) Evaluate(req *http.Request, ctx *Context) Result {
	ip := ctx.ClientIP
	if ip == nil {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "no client IP"}
	}

	ipStr := ip.String()
	hostname := r.lookupCached(ipStr)

	ctx.mu.Lock()
	ctx.RDNS = hostname
	ctx.mu.Unlock()

	if hostname == "" {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("no rDNS for %s", ipStr)}
	}

	hostLower := strings.ToLower(hostname)
	for _, pattern := range r.patterns {
		if strings.Contains(hostLower, strings.ToLower(pattern)) {
			return Result{
				Name:    r.Name(),
				Score:   r.weight,
				Matched: true,
				Details: fmt.Sprintf("rDNS %s matched pattern %s", hostname, pattern),
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("rDNS %s no match", hostname)}
}

func (r *RDNSRule) lookupCached(ip string) string {
	r.mu.RLock()
	entry, ok := r.cache[ip]
	r.mu.RUnlock()

	if ok && time.Now().Before(entry.expires) {
		return entry.hostname
	}

	hostname := r.doLookup(ip)
	entry = &rDNSCacheEntry{
		hostname: hostname,
		expires:  time.Now().Add(r.cacheTTL),
	}

	r.mu.Lock()
	r.cache[ip] = entry
	r.mu.Unlock()

	return hostname
}

func (r *RDNSRule) doLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}

	name := strings.TrimSuffix(names[0], ".")
	return name
}
