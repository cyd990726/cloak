package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Scoring ScoringConfig `yaml:"scoring"`
	Rules   RulesConfig   `yaml:"rules"`
	Routes  []RouteConfig `yaml:"routes"`
}

type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	HTTPSPort int    `yaml:"https_port"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	SecretKey string `yaml:"secret_key"`
	CountryDB string `yaml:"country_db"`
}

type RouteConfig struct {
	Path            string                 `yaml:"path"`
	Type            string                 `yaml:"type"`
	Upstream        string                 `yaml:"upstream"`
	Template        string                 `yaml:"template"`
	Data            map[string]interface{} `yaml:"data"`
	TargetCountries []string               `yaml:"target_countries"`
}

type ScoringConfig struct {
	Threshold    int `yaml:"threshold"`
	ChallengeMin int `yaml:"challenge_min"`
}

type RulesConfig struct {
	ASN      ASNConfig      `yaml:"asn"`
	UA       UAConfig       `yaml:"ua"`
	Header   HeaderConfig   `yaml:"header"`
	RDNS     RDNSConfig     `yaml:"rdns"`
	JA3      JA3Config      `yaml:"ja3"`
	Device   DeviceConfig   `yaml:"device"`
	IPType   IPTypeConfig   `yaml:"ip_type"`
	Honeypot HoneypotConfig `yaml:"honeypot"`
	JSFP     JSFPConfig     `yaml:"js_fp"`
	Reviewer ReviewerConfig `yaml:"reviewer"`
	Behavior BehaviorConfig `yaml:"behavior"`
}

type ReviewerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Weight     int    `yaml:"weight"`
	ASNFile    string `yaml:"asn_file"`
	IPFile     string `yaml:"ip_file"`
	JA3File    string `yaml:"ja3_file"` // kept for config compat, not used by reviewer rule
	TargetTZ   int    `yaml:"target_tz"`
	Threshold  int    `yaml:"threshold"` // min confidence to trigger review action
	ASNScore   int    `yaml:"asn_score"`
	IPScore    int    `yaml:"ip_score"`
	NoUTMScore int    `yaml:"no_utm_score"`
	NoRefScore int    `yaml:"no_ref_score"`
	PathScore  int    `yaml:"path_score"`
	TZScore    int    `yaml:"tz_score"`
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

type JSFPConfig struct {
	Enabled bool `yaml:"enabled"`
	Weight  int  `yaml:"weight"`
}

type IPTypeConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Weight        int      `yaml:"weight"`
	CloudKeywords []string `yaml:"cloud_keywords"`
}

type HoneypotConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Weight      int      `yaml:"weight"`
	Paths       []string `yaml:"paths"`
	InjectLinks bool     `yaml:"inject_links"`
}

type DeviceConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Weight          int      `yaml:"weight"`
	MobilePatterns  []string `yaml:"mobile_patterns"`
	DesktopPatterns []string `yaml:"desktop_patterns"`
}

type JA3Config struct {
	Enabled bool              `yaml:"enabled"`
	Weight  int               `yaml:"weight"`
	Hashes  map[string]string `yaml:"hashes"`
}

type ASNConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Weight        int      `yaml:"weight"`
	Databases     []string `yaml:"databases"`
	Patterns      []string `yaml:"patterns"`
	IPBlacklist   []string `yaml:"ip_blacklist"`
	BlacklistFile string   `yaml:"blacklist_file"`
	IPWhitelist   []string `yaml:"ip_whitelist"`
	WhitelistFile string   `yaml:"whitelist_file"`
}

type UAConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Weight   int      `yaml:"weight"`
	Patterns []string `yaml:"patterns"`
}

type HeaderConfig struct {
	Enabled bool           `yaml:"enabled"`
	Weight  int            `yaml:"weight"`
	Checks  map[string]int `yaml:"checks"`
}

type RDNSConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Weight   int      `yaml:"weight"`
	CacheTTL int      `yaml:"cache_ttl"`
	Patterns []string `yaml:"patterns"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.applyEnvOverrides(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Scoring.Threshold == 0 {
		c.Scoring.Threshold = 80
	}
}

func (c *Config) applyEnvOverrides() error {
	if v := firstEnv("CLOAK_HOST", "SERVER_HOST"); v != "" {
		c.Server.Host = v
	}
	if v := firstEnv("CLOAK_PORT", "PORT"); v != "" {
		port, err := parsePort(v)
		if err != nil {
			return fmt.Errorf("invalid server port from environment: %w", err)
		}
		c.Server.Port = port
	}
	if v := firstEnv("CLOAK_SECRET_KEY", "SECRET_KEY"); v != "" {
		c.Server.SecretKey = v
	}
	if v := firstEnv("CLOAK_COUNTRY_DB", "COUNTRY_DB"); v != "" {
		c.Server.CountryDB = v
	}
	if v := firstEnv("CLOAK_HTTPS_PORT", "HTTPS_PORT"); v != "" {
		port, err := parsePort(v)
		if err != nil {
			return fmt.Errorf("invalid HTTPS port from environment: %w", err)
		}
		c.Server.HTTPSPort = port
	}
	if v := firstEnv("CLOAK_CERT_FILE"); v != "" {
		c.Server.CertFile = v
	}
	if v := firstEnv("CLOAK_KEY_FILE"); v != "" {
		c.Server.KeyFile = v
	}
	return nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok {
			v = strings.TrimSpace(v)
			if v != "" {
				return v
			}
		}
	}
	return ""
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%d is outside 0-65535", port)
	}
	return port, nil
}

func (c *Config) FindRoute(path string) *RouteConfig {
	best := (*RouteConfig)(nil)
	bestLen := 0
	for i := range c.Routes {
		r := &c.Routes[i]
		matchLen := 0
		if r.Path == path {
			return r
		}
		if len(path) >= len(r.Path) &&
			path[:len(r.Path)] == r.Path &&
			(path[len(r.Path)] == '/' || len(path) == len(r.Path)) {
			matchLen = len(r.Path)
		} else if strings.HasSuffix(r.Path, "/") &&
			len(path) >= len(r.Path) &&
			path[:len(r.Path)] == r.Path {
			matchLen = len(r.Path)
		}
		if matchLen > bestLen {
			best = r
			bestLen = matchLen
		}
	}
	return best
}
