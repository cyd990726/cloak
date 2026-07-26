package handler

import (
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
