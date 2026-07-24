package rule

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type HoneypotRule struct {
	enabled bool
	weight  int
	paths   map[string]bool
	mu      sync.RWMutex
}

func NewHoneypotRule(enabled bool, weight int, paths []string) *HoneypotRule {
	r := &HoneypotRule{
		enabled: enabled,
		weight:  weight,
		paths:   make(map[string]bool),
	}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p[0] != '/' {
			p = "/" + p
		}
		r.paths[p] = true
	}
	return r
}

func (r *HoneypotRule) Name() string  { return "honeypot" }
func (r *HoneypotRule) Weight() int   { return r.weight }
func (r *HoneypotRule) Enabled() bool { return r.enabled }

func (r *HoneypotRule) Evaluate(req *http.Request, ctx *Context) Result {
	path := req.URL.Path

	r.mu.RLock()
	defer r.mu.RUnlock()

	for p := range r.paths {
		if path == p || (strings.HasPrefix(path, p) && (len(path) == len(p) || path[len(p)] == '/')) {
			return Result{
				Name:    r.Name(),
				Score:   r.weight,
				Matched: true,
				Details: fmt.Sprintf("honeypot triggered: %s (by rule %s)", path, p),
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: "honeypot not triggered"}
}

func (r *HoneypotRule) AddPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path != "" && path[0] != '/' {
		path = "/" + path
	}
	r.paths[path] = true
}

func (r *HoneypotRule) Paths() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	paths := make([]string, 0, len(r.paths))
	for p := range r.paths {
		paths = append(paths, p)
	}
	return paths
}
