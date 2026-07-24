package cloaker

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"cloak/internal/config"
	"cloak/internal/rule"
)

type ASNLookupFunc func(ip net.IP) (asn, org string, err error)

type Cloaker struct {
	cfg             *config.Config
	engine          *rule.Engine
	countryGate     *countryGate
	whitePages      map[string][]byte
	compliancePages map[string][]byte
	defaultWhite    []byte
	challengePage   []byte
	honeypotRule    *rule.HoneypotRule
	signKey         []byte
}

func New(cfg *config.Config) (*Cloaker, error) {
	c := &Cloaker{
		cfg:             cfg,
		whitePages:      make(map[string][]byte),
		compliancePages: make(map[string][]byte),
	}

	var gate rule.CountryChecker
	if cfg.Server.CountryDB != "" {
		cg, err := newCountryGate(cfg.Server.CountryDB)
		if err != nil {
			log.Printf("[country] failed to load country DB %s: %v", cfg.Server.CountryDB, err)
		} else {
			c.countryGate = cg
			gate = cg
			log.Printf("[country] country DB loaded: %s", cfg.Server.CountryDB)
		}
	}

	c.engine = rule.NewEngine(cfg.Scoring.Threshold, cfg.Scoring.ChallengeMin, gate)

	if cfg.Server.SecretKey != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Server.SecretKey))
		mac.Write([]byte("cloak-challenge-fp"))
		c.signKey = mac.Sum(nil)
	}

	if err := c.renderPages(); err != nil {
		return nil, fmt.Errorf("render pages: %w", err)
	}

	c.registerRules()

	return c, nil
}

func (c *Cloaker) Config() *config.Config { return c.cfg }

func (c *Cloaker) Judge(r *http.Request) rule.Verdict { return c.engine.Judge(r) }

func (c *Cloaker) SignKey() []byte { return c.signKey }

func (c *Cloaker) WhitePage(routeType string) []byte {
	if routeType != "" {
		if wp, ok := c.whitePages[routeType]; ok {
			return wp
		}
	}
	return c.defaultWhite
}

func (c *Cloaker) CompliancePage(path string) []byte {
	if cp, ok := c.compliancePages[path]; ok {
		return cp
	}
	return nil
}

func (c *Cloaker) ChallengePage() []byte { return c.challengePage }

func (c *Cloaker) RouteFor(path string) *config.RouteConfig { return c.cfg.FindRoute(path) }

func (c *Cloaker) CountryCheck(ip net.IP) string {
	if c.countryGate != nil {
		code, _ := c.countryGate.CheckCountry(ip)
		return code
	}
	return ""
}

func (c *Cloaker) renderPages() error {
	privacyTmpl, err := loadTemplate("privacy", c.templatePath("privacy.gohtml"))
	if err != nil {
		return fmt.Errorf("privacy template: %w", err)
	}
	termsTmpl, err := loadTemplate("terms", c.templatePath("terms.gohtml"))
	if err != nil {
		return fmt.Errorf("terms template: %w", err)
	}

	for _, route := range c.cfg.Routes {
		if route.Template == "" {
			continue
		}

		tmpl, err := loadTemplate(route.Type, route.Template)
		if err != nil {
			return fmt.Errorf("template %s: %w", route.Template, err)
		}

		templateData := route.Data
		if templateData == nil {
			templateData = make(map[string]interface{})
		}

		rendered, err := renderTemplate(tmpl, templateData)
		if err != nil {
			return fmt.Errorf("render %s: %w", route.Template, err)
		}

		if route.Type != "" {
			c.whitePages[route.Type] = injectHoneypot(rendered, route.Path)
		}
		c.defaultWhite = injectHoneypot(rendered, route.Path)

		complianceData := make(map[string]interface{})
		for k, v := range route.Data {
			complianceData[k] = v
		}
		if _, ok := complianceData["last_updated"]; !ok {
			complianceData["last_updated"] = "January 2026"
		}
		if _, ok := complianceData["contact_email"]; !ok {
			brand := "company"
			if b, ok := route.Data["brand_name"].(string); ok && b != "" {
				brand = b
			}
			complianceData["contact_email"] = "contact@" + brand + ".com"
		}
		if _, ok := complianceData["privacy_url"]; !ok {
			complianceData["privacy_url"] = route.Path + "/privacy"
		}
		if _, ok := complianceData["terms_url"]; !ok {
			complianceData["terms_url"] = route.Path + "/terms"
		}

		privacyHTML, err := renderTemplate(privacyTmpl, complianceData)
		if err != nil {
			return fmt.Errorf("privacy %s: %w", route.Path, err)
		}
		c.compliancePages[route.Path+"/privacy"] = privacyHTML

		termsHTML, err := renderTemplate(termsTmpl, complianceData)
		if err != nil {
			return fmt.Errorf("terms %s: %w", route.Path, err)
		}
		c.compliancePages[route.Path+"/terms"] = termsHTML
	}

	if len(c.whitePages) == 0 {
		c.defaultWhite = []byte(defaultWhitePage)
	}

	c.challengePage = []byte(challengePage)
	return nil
}

func (c *Cloaker) templatePath(name string) string {
	for _, route := range c.cfg.Routes {
		if route.Template != "" {
			return filepath.Join(filepath.Dir(route.Template), name)
		}
	}
	return filepath.Join("templates", name)
}

func loadTemplate(name, path string) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return template.New(name).Funcs(template.FuncMap{
		"default": func(def, val interface{}) interface{} {
			if val == nil || val == "" {
				return def
			}
			return val
		},
	}).Parse(string(data))
}

func renderTemplate(tmpl *template.Template, data map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Cloaker) registerRules() {
	rc := c.cfg.Rules

	if rc.ASN.Enabled {
		var lookup rule.ASNLookup = &noopASNLookup{}
		for _, db := range rc.ASN.Databases {
			if strings.HasSuffix(db, ".mmdb") {
				l, err := newMaxMindLookup(db)
				if err == nil {
					lookup = l
					break
				}
			}
		}
		c.engine.Register(rule.NewASNRule(
			rc.ASN.Enabled, rc.ASN.Weight, rc.ASN.Patterns,
			rc.ASN.IPBlacklist, rc.ASN.IPWhitelist,
			rc.ASN.BlacklistFile, rc.ASN.WhitelistFile,
			lookup,
		))
	}

	if rc.UA.Enabled {
		c.engine.Register(rule.NewUARule(rc.UA.Enabled, rc.UA.Weight, rc.UA.Patterns))
	}

	if rc.Header.Enabled {
		c.engine.Register(rule.NewHeaderRule(rc.Header.Enabled, rc.Header.Weight, rc.Header.Checks))
	}

	if rc.RDNS.Enabled {
		c.engine.Register(rule.NewRDNSRule(rc.RDNS.Enabled, rc.RDNS.Weight, rc.RDNS.Patterns, rc.RDNS.CacheTTL))
	}

	if rc.JA3.Enabled {
		c.engine.Register(rule.NewJA3Rule(rc.JA3.Enabled, rc.JA3.Weight, rc.JA3.Hashes))
	}

	if rc.Device.Enabled {
		c.engine.Register(rule.NewDeviceRule(rc.Device.Enabled, rc.Device.Weight, rc.Device.MobilePatterns, rc.Device.DesktopPatterns))
	}

	if rc.IPType.Enabled {
		c.engine.Register(rule.NewIPTypeRule(rc.IPType.Enabled, rc.IPType.Weight, rc.IPType.CloudKeywords))
	}

	if rc.Honeypot.Enabled {
		hpRule := rule.NewHoneypotRule(rc.Honeypot.Enabled, rc.Honeypot.Weight, rc.Honeypot.Paths)
		if rc.Honeypot.InjectLinks {
			for _, route := range c.cfg.Routes {
				for _, suffix := range []string{"/_admin", "/_private", "/_debug", "/wp-admin", "/.env", "/backup"} {
					hpRule.AddPath(route.Path + suffix)
				}
			}
		}
		c.honeypotRule = hpRule
		c.engine.Register(hpRule)
	}

	if rc.JSFP.Enabled {
		c.engine.Register(rule.NewJSFingerprintRule(rc.JSFP.Enabled, rc.JSFP.Weight, c.signKey))
	}

	if rc.Reviewer.Enabled {
		c.engine.Register(rule.NewReviewerRule(rule.ReviewerConfig{
			Enabled:    rc.Reviewer.Enabled,
			Weight:     rc.Reviewer.Weight,
			ASNFile:    rc.Reviewer.ASNFile,
			IPFile:     rc.Reviewer.IPFile,
			JA3File:    rc.Reviewer.JA3File,
			TargetTZ:   rc.Reviewer.TargetTZ,
			Threshold:  rc.Reviewer.Threshold,
			ASNScore:   rc.Reviewer.ASNScore,
			IPScore:    rc.Reviewer.IPScore,
			NoUTMScore: rc.Reviewer.NoUTMScore,
			NoRefScore: rc.Reviewer.NoRefScore,
			PathScore:  rc.Reviewer.PathScore,
			TZScore:    rc.Reviewer.TZScore,
		}))
	}

	if rc.Behavior.Enabled {
		c.engine.Register(rule.NewBehaviorRule(rule.BehaviorConfig{
			Enabled:           rc.Behavior.Enabled,
			Weight:            rc.Behavior.Weight,
			PrivacyVisitScore: rc.Behavior.PrivacyVisitScore,
			MultiRouteScore:   rc.Behavior.MultiRouteScore,
			RapidMultiScore:   rc.Behavior.RapidMultiScore,
			ComplianceChain:   rc.Behavior.ComplianceChain,
			NoCTAScore:        rc.Behavior.NoCTAScore,
			Threshold:         rc.Behavior.Threshold,
		}))
	}
}

func injectHoneypot(html []byte, routePath string) []byte {
	hpPaths := []string{
		routePath + "/_admin",
		routePath + "/_private",
		routePath + "/_debug",
		routePath + "/wp-admin",
		routePath + "/.env",
		routePath + "/backup",
	}
	links := ""
	for _, p := range hpPaths {
		links += fmt.Sprintf(`<a href="%s" style="display:none;visibility:hidden;position:absolute;left:-9999px" tabindex="-1" aria-hidden="true">.</a>`, p)
	}

	for i := len(html) - 1; i >= 0; i-- {
		if html[i] == '>' {
			// check if it's </body> or </html>
			start := i - 6
			if start >= 0 && string(html[start:i+1]) == "</body>" {
				result := make([]byte, 0, len(html)+len(links))
				result = append(result, html[:start]...)
				result = append(result, links...)
				result = append(result, html[start:]...)
				return result
			}
			start = i - 6
			if start >= 0 && string(html[start:i+1]) == "</html>" {
				result := make([]byte, 0, len(html)+len(links))
				result = append(result, html[:start]...)
				result = append(result, links...)
				result = append(result, html[start:]...)
				return result
			}
		}
	}
	return html
}

type noopASNLookup struct{}

func (n *noopASNLookup) Lookup(ip net.IP) (string, string, error) {
	return "", "", fmt.Errorf("no geoip database configured")
}

const defaultWhitePage = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title></title></head><body></body></html>`

const challengePage = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Verifying...</title>
<script>
(function(){
  var fp = {};
  var t = Date.now();

  function hash(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24); h >>>= 0; }
    return h.toString(16);
  }

  // PoW
  var target = "0000", nonce = 0;
  var prefix = t.toString(36);
  var result = hash(prefix + nonce);
  while (result.substring(0, target.length) !== target && nonce < 2000000) { nonce++; result = hash(prefix + nonce); }
  fp.pow = prefix + "." + nonce + "." + result;
  fp.ts = t;

  // Canvas
  try {
    var canvas = document.createElement("canvas"); canvas.width = 280; canvas.height = 60;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#f60"; ctx.fillRect(10, 10, 50, 30);
    ctx.fillStyle = "#069"; ctx.beginPath(); ctx.arc(100, 30, 15, 0, Math.PI*2); ctx.fill();
    ctx.fillStyle = "#fff"; ctx.font = "18px Arial"; ctx.fillText("Cloak", 130, 35);
    fp.canvas = hash(canvas.toDataURL());
  } catch(e) { fp.canvas = "err"; }

  // WebGL
  try {
    var gl = document.createElement("canvas").getContext("webgl") || document.createElement("canvas").getContext("experimental-webgl");
    if (gl) {
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      fp.webgl_vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : "";
      fp.webgl_renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "";
    }
  } catch(e) {}

  // Touch / Screen / Hardware
  fp.touch = ("ontouchstart" in window || navigator.maxTouchPoints > 0);
  fp.screen = screen.width + "x" + screen.height;
  fp.viewport = (window.innerWidth || document.documentElement.clientWidth) + "x" + (window.innerHeight || document.documentElement.clientHeight);
  fp.dpr = window.devicePixelRatio || 1;
  fp.webdriver = navigator.webdriver || false;
  fp.languages = (navigator.languages || []).join(",");
  fp.platform = navigator.platform || "";
  fp.cores = navigator.hardwareConcurrency || 0;
  fp.memory = navigator.deviceMemory || 0;

  // Font
  try {
    var fonts = [], testFonts = ["Arial", "Helvetica", "Times New Roman", "Courier New", "Georgia"];
    var c2 = document.createElement("canvas"), ctx2 = c2.getContext("2d");
    ctx2.font = "72px monospace"; var monoW = ctx2.measureText("mmmmmmmmmmlli").width;
    for (var i = 0; i < testFonts.length; i++) {
      ctx2.font = "72px " + testFonts[i];
      if (ctx2.measureText("mmmmmmmmmmlli").width !== monoW) fonts.push(testFonts[i]);
    }
    fp.fonts = fonts.join(",");
  } catch(e) {}

  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/validate", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.onload = function() { location.reload(); };
  xhr.onerror = function() { location.reload(); };
  xhr.send(JSON.stringify(fp));
})();
</script>
</head><body style="background:#fff;margin:0"></body></html>`
