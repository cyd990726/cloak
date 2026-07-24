package rule

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type JSFingerprintRule struct {
	enabled bool
	weight  int
	signKey []byte
}

func NewJSFingerprintRule(enabled bool, weight int, signKey []byte) *JSFingerprintRule {
	return &JSFingerprintRule{enabled: enabled, weight: weight, signKey: signKey}
}

func (r *JSFingerprintRule) Name() string  { return "js_fp" }
func (r *JSFingerprintRule) Weight() int   { return r.weight }
func (r *JSFingerprintRule) Enabled() bool { return r.enabled }

func (r *JSFingerprintRule) Evaluate(req *http.Request, ctx *Context) Result {
	cv, err := req.Cookie("_cv")
	if err != nil || cv.Value == "" {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "no _cv cookie"}
	}

	// format: ts.base64_fp.hex_hmac
	parts := strings.Split(cv.Value, ".")
	if len(parts) < 3 {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "invalid _cv format"}
	}

	tsStr := parts[0]
	fpB64 := parts[1]
	sigHex := parts[2]

	// verify signature
	if len(r.signKey) > 0 {
		data := tsStr + "." + fpB64
		mac := hmac.New(sha256.New, r.signKey)
		mac.Write([]byte(data))
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sigHex), []byte(expected)) {
			return Result{Name: r.Name(), Score: 0, Matched: false, Details: "signature mismatch"}
		}
	}

	// verify timestamp freshness (1 hour)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "bad timestamp"}
	}
	ageMs := time.Now().UnixMilli() - ts
	if ageMs < 0 || ageMs > 3600000 {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("_cv expired (%ds)", ageMs/1000)}
	}

	// decode and check fingerprint
	fpJSON, err := base64.RawURLEncoding.DecodeString(fpB64)
	if err != nil {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "cannot decode fingerprint"}
	}

	var fp struct {
		Webdriver     bool   `json:"webdriver"`
		Touch         bool   `json:"touch"`
		Cores         int    `json:"cores"`
		Memory        int    `json:"memory"`
		Canvas        string `json:"canvas"`
		WebglVendor   string `json:"webgl_vendor"`
		WebglRenderer string `json:"webgl_renderer"`
		Viewport      string `json:"viewport"`
		Screen        string `json:"screen"`
		Platform      string `json:"platform"`
		Fonts         string `json:"fonts"`
		DPR           any    `json:"dpr"`
		Pow           string `json:"pow"`
		Ts            int64  `json:"ts"`
	}
	if err := json.Unmarshal(fpJSON, &fp); err != nil {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "cannot parse fingerprint"}
	}

	triggers := make([]string, 0)

	if fp.Webdriver {
		triggers = append(triggers, "navigator.webdriver=true")
	}

	if !fp.Touch && r.uaSaysMobile(req) {
		triggers = append(triggers, "mobile UA but no touch support")
	}

	if fp.Cores > 0 && fp.Cores <= 2 && fp.Viewport != "" {
		triggers = append(triggers, fmt.Sprintf("low CPU cores (%d)", fp.Cores))
	}

	if fp.Canvas == "" || fp.Canvas == "err" {
		triggers = append(triggers, "canvas fingerprint failed")
	}

	if fp.Viewport == "800x600" || fp.Viewport == "0x0" {
		triggers = append(triggers, fmt.Sprintf("suspicious viewport (%s)", fp.Viewport))
	}

	if len(triggers) == 0 {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "JS fingerprint clean"}
	}

	return Result{
		Name: r.Name(), Score: r.weight, Matched: true,
		Details: strings.Join(triggers, "; "),
	}
}

func (r *JSFingerprintRule) uaSaysMobile(req *http.Request) bool {
	ua := strings.ToLower(req.Header.Get("User-Agent"))
	for _, kw := range []string{"iphone", "ipad", "android", "mobile"} {
		if strings.Contains(ua, kw) { return true }
	}
	return false
}
