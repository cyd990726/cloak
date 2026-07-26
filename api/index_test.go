package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerRestoresRewrittenPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/index.go?__cloak_path=/healthz", nil)
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestDebugEndpointRequiresToken(t *testing.T) {
	t.Setenv("CLOAK_ADMIN_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/index.go?__cloak_path=/__vercel_debug", nil)
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDebugEndpointAcceptsToken(t *testing.T) {
	t.Setenv("CLOAK_ADMIN_TOKEN", "test-token")

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/index.go?__cloak_path=/__vercel_debug&debug_token=test-token", nil)
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestJudgeRequiresToken(t *testing.T) {
	t.Setenv("CLOAK_API_TOKEN", "")

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/judge", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestJudgeReturnsAudience(t *testing.T) {
	t.Setenv("CLOAK_API_TOKEN", "test-token")

	body := `{"ip":"8.8.8.8","method":"GET","path":"/l/demo","headers":{"user-agent":"Mozilla/5.0 Chrome/120.0","accept":"text/html","accept-language":"en-US","accept-encoding":"gzip","sec-fetch-site":"none","sec-fetch-mode":"navigate","sec-fetch-dest":"document"},"query":{"gclid":"abc"}}`
	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/judge", bytes.NewBufferString(body))
	req.Header.Set("X-Cloak-Token", "test-token")
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); !bytes.Contains([]byte(got), []byte(`"audience"`)) {
		t.Fatalf("expected audience in body, got %s", got)
	}
}
