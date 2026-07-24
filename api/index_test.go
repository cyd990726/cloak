package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerRestoresRewrittenPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/index.go?__cloak_path=/healthz", nil)
	rec := httptest.NewRecorder()

	Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("unexpected body: %q", got)
	}
}
