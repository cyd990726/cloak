package handler

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"cloak/pkg/app"
)

//go:embed assets
var assets embed.FS

var (
	assetOnce      sync.Once
	assetConfig    string
	assetConfigErr error
)

// Handler is the Vercel Serverless Function entrypoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("panic in Vercel function: %v\n%s", recovered, debug.Stack())
			http.Error(w, fmt.Sprintf("panic: %v", recovered), http.StatusInternalServerError)
		}
	}()

	restoreRewrittenPath(r)

	if r.URL.Path == "/__vercel_debug" {
		if !debugAllowed(r) {
			http.NotFound(w, r)
			return
		}
		serveDebug(w)
		return
	}

	configPath, err := embeddedConfigPath()
	if err != nil {
		log.Printf("failed to prepare embedded assets: %v", err)
		http.Error(w, fmt.Sprintf("failed to prepare embedded assets: %v", err), http.StatusServiceUnavailable)
		return
	}

	h, err := app.DefaultWithConfig(configPath)
	if err != nil {
		log.Printf("failed to initialize app: %v", err)
		http.Error(w, fmt.Sprintf("failed to initialize app: %v", err), http.StatusServiceUnavailable)
		return
	}

	h.ServeHTTP(w, r)
}

func serveDebug(w http.ResponseWriter) {
	result := map[string]interface{}{
		"function": "ok",
	}

	entries, err := fs.Glob(assets, "assets/**")
	if err != nil {
		result["assetGlobError"] = err.Error()
	} else {
		result["assetCount"] = len(entries)
	}

	configPath, err := embeddedConfigPath()
	if err != nil {
		result["embeddedConfigError"] = err.Error()
	} else {
		result["embeddedConfigPath"] = configPath
		if stat, err := os.Stat(configPath); err != nil {
			result["embeddedConfigStatError"] = err.Error()
		} else {
			result["embeddedConfigSize"] = stat.Size()
		}
	}

	if configPath != "" {
		if _, err := app.DefaultWithConfig(configPath); err != nil {
			result["appError"] = err.Error()
		} else {
			result["app"] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}

func embeddedConfigPath() (string, error) {
	assetOnce.Do(func() {
		root, err := os.MkdirTemp("", "cloak-vercel-*")
		if err != nil {
			assetConfigErr = err
			return
		}
		if err := copyEmbeddedAssets(root); err != nil {
			assetConfigErr = err
			return
		}
		assetConfig = filepath.Join(root, "config.yaml")
	})
	return assetConfig, assetConfigErr
}

func copyEmbeddedAssets(root string) error {
	return fs.WalkDir(assets, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel("assets", path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(root, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
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

func debugAllowed(r *http.Request) bool {
	token := strings.TrimSpace(os.Getenv("CLOAK_ADMIN_TOKEN"))
	if token == "" {
		return false
	}
	if constantTimeEqual(r.Header.Get("X-Admin-Token"), token) {
		return true
	}
	return constantTimeEqual(r.URL.Query().Get("debug_token"), token)
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
