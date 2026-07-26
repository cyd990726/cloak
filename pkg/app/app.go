package app

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloak/internal/cloaker"
	"cloak/internal/config"
	"cloak/internal/handler"
	"cloak/internal/rule"
)

var (
	defaultOnce    sync.Once
	defaultHandler http.Handler
	defaultService *Service
	defaultErr     error
)

type Service struct {
	handler http.Handler
	cloaker *cloaker.Cloaker
}

type JudgePayload struct {
	IP        string            `json:"ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     map[string]string `json:"query"`
	Headers   map[string]string `json:"headers"`
	Country   string            `json:"country"`
	TZOffset  int               `json:"tz_offset"`
	Timestamp int64             `json:"timestamp"`
}

type JudgeResult struct {
	Audience    string   `json:"audience"`
	AllowReturn bool     `json:"allow_return"`
	Action      string   `json:"action"`
	Score       int      `json:"score"`
	Total       int      `json:"total_max"`
	Reasons     []string `json:"reasons"`
}

// New builds the HTTP handler used by both the standalone server and
// serverless adapters.
func New(configPath string) (http.Handler, *config.Config, error) {
	service, cfg, err := NewService(configPath)
	if err != nil {
		return nil, nil, err
	}
	return service.handler, cfg, nil
}

func NewService(configPath string) (*Service, *config.Config, error) {
	configPath = resolveConfigPath(configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	normalizeRelativePaths(cfg, filepath.Dir(configPath))

	c, err := cloaker.New(cfg)
	if err != nil {
		return nil, nil, err
	}

	return &Service{
		handler: handler.NewHandler(c),
		cloaker: c,
	}, cfg, nil
}

// Default returns a lazily initialized handler for serverless runtimes.
func Default() (http.Handler, error) {
	return DefaultWithConfig(configPath())
}

// DefaultWithConfig returns a lazily initialized handler using the provided
// config path on the first call.
func DefaultWithConfig(configPath string) (http.Handler, error) {
	defaultOnce.Do(func() {
		defaultService, _, defaultErr = NewService(configPath)
		if defaultService != nil {
			defaultHandler = defaultService.handler
		}
	})
	return defaultHandler, defaultErr
}

func DefaultServiceWithConfig(configPath string) (*Service, error) {
	defaultOnce.Do(func() {
		defaultService, _, defaultErr = NewService(configPath)
		if defaultService != nil {
			defaultHandler = defaultService.handler
		}
	})
	return defaultService, defaultErr
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Service) Judge(payload JudgePayload) (JudgeResult, error) {
	req, err := payload.HTTPRequest()
	if err != nil {
		return JudgeResult{}, err
	}
	verdict := s.cloaker.Judge(req)
	return judgeResultFromVerdict(verdict), nil
}

func (p JudgePayload) HTTPRequest() (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := strings.TrimSpace(p.Path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	values := url.Values{}
	for key, value := range p.Query {
		if strings.TrimSpace(key) == "" {
			continue
		}
		values.Set(key, value)
	}
	if encoded := values.Encode(); encoded != "" {
		path = path + "?" + encoded
	}

	req, err := http.NewRequest(method, "https://cloak-judge.local"+path, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range p.Headers {
		if strings.TrimSpace(key) == "" || value == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	if p.IP != "" {
		req.Header.Set("X-Real-IP", p.IP)
		req.Header.Set("X-Forwarded-For", p.IP)
		req.RemoteAddr = p.IP + ":0"
	}
	if p.Country != "" {
		req.Header.Set("X-Visitor-Country", strings.ToUpper(strings.TrimSpace(p.Country)))
	}
	if p.TZOffset != 0 {
		req.Header.Set("X-TZ-Offset", fmt.Sprintf("%d", p.TZOffset))
	}
	return req, nil
}

func judgeResultFromVerdict(verdict rule.Verdict) JudgeResult {
	action := verdict.Action.String()
	audience := "B"
	allowReturn := true
	if verdict.Action == rule.ActionCloak || verdict.Action == rule.ActionReview || verdict.Action == rule.ActionChallenge {
		audience = "A"
		allowReturn = false
	}
	return JudgeResult{
		Audience:    audience,
		AllowReturn: allowReturn,
		Action:      action,
		Score:       verdict.Score,
		Total:       verdict.Total,
		Reasons:     verdict.Details,
	}
}

func configPath() string {
	if path := firstNonEmptyEnv("CLOAK_CONFIG", "CONFIG_PATH"); path != "" {
		return path
	}
	return "config.yaml"
}

func resolveConfigPath(path string) string {
	if path == "" {
		path = "config.yaml"
	}
	if filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}

	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	for {
		candidate := filepath.Join(wd, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return path
		}
		wd = parent
	}
}

func normalizeRelativePaths(cfg *config.Config, baseDir string) {
	cfg.Server.CountryDB = joinRelative(baseDir, cfg.Server.CountryDB)
	cfg.Server.CertFile = joinRelative(baseDir, cfg.Server.CertFile)
	cfg.Server.KeyFile = joinRelative(baseDir, cfg.Server.KeyFile)

	for i := range cfg.Routes {
		cfg.Routes[i].Template = joinRelative(baseDir, cfg.Routes[i].Template)
	}

	for i := range cfg.Rules.ASN.Databases {
		cfg.Rules.ASN.Databases[i] = joinRelative(baseDir, cfg.Rules.ASN.Databases[i])
	}
	cfg.Rules.ASN.BlacklistFile = joinRelative(baseDir, cfg.Rules.ASN.BlacklistFile)
	cfg.Rules.ASN.WhitelistFile = joinRelative(baseDir, cfg.Rules.ASN.WhitelistFile)
	cfg.Rules.Reviewer.ASNFile = joinRelative(baseDir, cfg.Rules.Reviewer.ASNFile)
	cfg.Rules.Reviewer.IPFile = joinRelative(baseDir, cfg.Rules.Reviewer.IPFile)
	cfg.Rules.Reviewer.JA3File = joinRelative(baseDir, cfg.Rules.Reviewer.JA3File)
}

func joinRelative(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
