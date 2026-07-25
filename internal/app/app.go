package app

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloak/internal/cloaker"
	"cloak/internal/config"
	"cloak/internal/handler"
)

var (
	defaultOnce    sync.Once
	defaultHandler http.Handler
	defaultErr     error
)

// New builds the HTTP handler used by both the standalone server and
// serverless adapters.
func New(configPath string) (http.Handler, *config.Config, error) {
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

	return handler.NewHandler(c), cfg, nil
}

// Default returns a lazily initialized handler for serverless runtimes.
func Default() (http.Handler, error) {
	return DefaultWithConfig(configPath())
}

// DefaultWithConfig returns a lazily initialized handler using the provided
// config path on the first call.
func DefaultWithConfig(configPath string) (http.Handler, error) {
	defaultOnce.Do(func() {
		defaultHandler, _, defaultErr = New(configPath)
	})
	return defaultHandler, defaultErr
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
