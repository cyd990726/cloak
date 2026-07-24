package handler

import (
	"log"
	"net/http"
	"strings"

	"cloak/internal/app"
)

// Handler is the Vercel Serverless Function entrypoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	h, err := app.Default()
	if err != nil {
		log.Printf("failed to initialize app: %v", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	restoreRewrittenPath(r)
	h.ServeHTTP(w, r)
}

func restoreRewrittenPath(r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("__cloak_path"))
	if path == "" {
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	q := r.URL.Query()
	q.Del("__cloak_path")
	r.URL.RawQuery = q.Encode()
	r.URL.Path = path
}
