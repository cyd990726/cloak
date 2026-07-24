package rule

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"cloak/internal/ja3"
)

type JA3Rule struct {
	enabled       bool
	weight        int
	customHashes  map[string]string
}

var uaMobileRE = regexp.MustCompile(`(?i)iPhone|iPad|iPod|Android.*Mobile|Mobile.*Safari`)

var uaBrowserRE = map[string]*regexp.Regexp{
	"safari_ios":      regexp.MustCompile(`(?i)iPhone.*Safari|iPad.*Safari`),
	"chrome_android":  regexp.MustCompile(`(?i)Android.*Chrome`),
	"firefox":         regexp.MustCompile(`(?i)Firefox`),
	"edge":            regexp.MustCompile(`(?i)Edg/`),
}

var clientLibraryJA3Prefixes = []string{
	"72a3e1e6", // Go HTTP
	"e64d0991", // Go HTTP 1.22
	"a4f3f95a", // Go HTTP 1.21
	"cc228765", // Go HTTP older
	"a26c7fa0", // Python httpx
	"659cedd0", // Python urllib3
	"e627d755", // Python requests alt
	"f2f63ca8", // Python aiohttp
	"401e913b", // Python httplib2
	"3f4e5cae", // Python urllib
	"b32309a2", // Node.js http
	"c292756c", // Node.js https
	"42941b55", // Node.js undici
	"adadc1e5", // curl
	"4dabf24c", // curl alt
	"7a27a6e9", // curl older
	"556dbb3f", // wget
	"b6cdda92", // Java HttpClient
	"93ade6c6", // Java okhttp
	"52e5f491", // Java Apache
	"8cd9efb6", // Scrapy
}

func NewJA3Rule(enabled bool, weight int, customHashes map[string]string) *JA3Rule {
	if customHashes == nil {
		customHashes = make(map[string]string)
	}
	return &JA3Rule{
		enabled:      enabled,
		weight:       weight,
		customHashes: customHashes,
	}
}

func (r *JA3Rule) Name() string  { return "ja3" }
func (r *JA3Rule) Weight() int   { return r.weight }
func (r *JA3Rule) Enabled() bool { return r.enabled }

func (r *JA3Rule) Evaluate(req *http.Request, ctx *Context) Result {
	ja3Hash := r.extractJA3(req)
	ua := req.Header.Get("User-Agent")

	if ja3Hash == "" {
		return Result{Name: r.Name(), Score: 0, Matched: false, Details: "no JA3 fingerprint available"}
	}

	ja3Hash = strings.ToLower(ja3Hash)

	// 1. known crawler hash match → full weight
	for hash, desc := range r.customHashes {
		if strings.ToLower(hash) == ja3Hash {
			return Result{
				Name: r.Name(), Score: r.weight, Matched: true,
				Details: fmt.Sprintf("custom JA3 %s matched: %s", ja3Hash, desc),
			}
		}
	}

	matched, desc := ja3.IsKnownCrawler(ja3Hash)
	if matched {
		return Result{
			Name: r.Name(), Score: r.weight, Matched: true,
			Details: fmt.Sprintf("JA3 %s matched known crawler: %s", ja3Hash, desc),
		}
	}

	// 2. UA-JA3 consistency: mobile UA + server/client library JA3 = disguised
	if ua != "" && uaMobileRE.MatchString(ua) {
		for _, prefix := range clientLibraryJA3Prefixes {
			if strings.HasPrefix(ja3Hash, prefix) {
				return Result{
					Name: r.Name(), Score: r.weight, Matched: true,
					Details: fmt.Sprintf("mobile UA (%s) but JA3 %s is server/client library", uaBrief(ua), ja3Hash),
				}
			}
		}
	}

	// 3. browser JA3 is unrecognized but UA claims a real browser → medium weight
	if ua != "" {
		for browser, re := range uaBrowserRE {
			if re.MatchString(ua) {
				return Result{
					Name: r.Name(), Score: r.weight / 3, Matched: true,
					Details: fmt.Sprintf("UA claims %s but JA3 %s not in known browser DB", browser, ja3Hash),
				}
			}
		}
	}

	return Result{Name: r.Name(), Score: 0, Matched: false, Details: fmt.Sprintf("JA3 %s no match", ja3Hash)}
}

func (r *JA3Rule) extractJA3(req *http.Request) string {
	// Read from trusted TLS context only — never from request headers
	// (attackers can forge X-JA3 headers to bypass detection)
	return JA3FromRequest(req)
}

func uaBrief(ua string) string {
	if len(ua) > 40 {
		return ua[:40] + "..."
	}
	return ua
}
