package rule

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type DeviceRule struct {
	enabled        bool
	weight         int
	mobileRE       []*regexp.Regexp
	pcRE           []*regexp.Regexp
}

var mobileUARE = []string{
	`(?i)Android|iPhone|iPad|iPod`,
	`(?i)Mobile Safari|Mobile;|Opera Mini`,
	`(?i)Windows Phone|BlackBerry|webOS`,
}

var pcUARE = []string{
	`(?i)Windows NT|Macintosh|X11; Linux`,
	`(?i)CrOS|Ubuntu|Fedora`,
}

func NewDeviceRule(enabled bool, weight int, mobilePatterns, desktopPatterns []string) *DeviceRule {
	r := &DeviceRule{enabled: enabled, weight: weight}

	for _, p := range mobilePatterns {
		re, err := regexp.Compile(p)
		if err == nil { r.mobileRE = append(r.mobileRE, re) }
	}
	if len(r.mobileRE) == 0 {
		for _, p := range mobileUARE {
			r.mobileRE = append(r.mobileRE, regexp.MustCompile(p))
		}
	}

	for _, p := range desktopPatterns {
		re, err := regexp.Compile(p)
		if err == nil { r.pcRE = append(r.pcRE, re) }
	}
	if len(r.pcRE) == 0 {
		for _, p := range pcUARE {
			r.pcRE = append(r.pcRE, regexp.MustCompile(p))
		}
	}

	return r
}

func (r *DeviceRule) Name() string  { return "device" }
func (r *DeviceRule) Weight() int   { return r.weight }
func (r *DeviceRule) Enabled() bool { return r.enabled }

func (r *DeviceRule) Evaluate(req *http.Request, ctx *Context) Result {
	ua := req.Header.Get("User-Agent")

	// 1. Client Hints viewport (most reliable, browser-sent)
	if vp := req.Header.Get("Sec-CH-Viewport-Width"); vp != "" {
		w := 0; fmt.Sscanf(vp, "%d", &w)
		if w >= 1024 {
			return Result{Name: r.Name(), Score: r.weight / 4, Matched: true,
				Details: fmt.Sprintf("viewport %s >= 1024 (likely desktop)", vp)}
		}
		if w > 0 && w < 768 {
			return Result{Name: r.Name(), Score: 0, Matched: false,
				Details: fmt.Sprintf("mobile viewport: %s", vp)}
		}
	}

	// 2. Client Hints platform mismatch
	chPlatform := strings.Trim(strings.TrimSpace(req.Header.Get("Sec-CH-UA-Platform")), `"`)
	if chPlatform != "" {
		isMobile := isMobileUA(ua, r.mobileRE)
		if isMobile && (chPlatform == "Windows" || chPlatform == "macOS" || chPlatform == "Linux") {
			return Result{Name: r.Name(), Score: r.weight, Matched: true,
				Details: fmt.Sprintf("UA claims mobile but Sec-CH-UA-Platform=%s", chPlatform)}
		}
	}

	// 3. UA says mobile + ASN is cloud/datacenter → disguised crawler
	isMobile := isMobileUA(ua, r.mobileRE)
	asnOrg := ctx.ASNOrg
	if isMobile && asnOrg != "" {
		orgLower := strings.ToLower(asnOrg)
		for _, kw := range []string{"cloud", "hosting", "datacenter", "vps", "compute", "digitalocean", "linode", "vultr", "aws", "azure", "gcp", "google"} {
			if strings.Contains(orgLower, kw) {
				return Result{Name: r.Name(), Score: r.weight, Matched: true,
					Details: fmt.Sprintf("UA mobile but ASN org %q is cloud/hosting", asnOrg)}
			}
		}
	}

	// 4. UA says mobile + JA3 is a known non-mobile fingerprint (from trusted context)
	ja3Hash := strings.ToLower(JA3FromRequest(req))
	if isMobile && ja3Hash != "" {
		for _, badJA3 := range []string{
			"72a3e1e69d39cd98bfe2e4e9bb5b2e66", // Go HTTP
			"e64d0991fe298dfd0e6bafcb72c19e3f", // Go HTTP 1.22+
			"a26c7fa04c6c2a7d1c6e6c79939862e2", // Python httpx
			"659cedd01af02340e9e9438e3df7c49e", // Python requests
			"ab8a154b30c4a4e581d83903106e10d6", // Headless Chrome
			"adadc1e573cbe6dd40f7e7711d9ae115", // curl
		} {
			if ja3Hash == badJA3 {
				return Result{Name: r.Name(), Score: r.weight, Matched: true,
					Details: fmt.Sprintf("UA mobile but JA3 %s is server/client library", ja3Hash)}
			}
		}
	}

	// 5. Missing UA entirely → definitely not a real user
	if ua == "" {
		return Result{Name: r.Name(), Score: r.weight / 2, Matched: true,
			Details: "empty User-Agent"}
	}

	// 6. Pure PC UA (Windows/Mac/Linux) — low weight marker, not a blocker
	isPC := false
	for _, re := range r.pcRE {
		if re.MatchString(ua) { isPC = true; break }
	}
	if isMobile {
		isPC = false
	}
	if isPC {
		return Result{Name: r.Name(), Score: r.weight / 5, Matched: true,
			Details: "PC User-Agent (low weight marker)"}
	}

	// 7. Mobile — pass
	if isMobile {
		return Result{Name: r.Name(), Score: 0, Matched: false,
			Details: "mobile device"}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: "unable to classify"}
}

func isMobileUA(ua string, reList []*regexp.Regexp) bool {
	for _, re := range reList {
		if re.MatchString(ua) { return true }
	}
	return false
}
