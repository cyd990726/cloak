package handler

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloak/internal/app"
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
	configPath, err := embeddedConfigPath()
	if err != nil {
		log.Printf("failed to prepare embedded assets: %v", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	h, err := app.DefaultWithConfig(configPath)
	if err != nil {
		log.Printf("failed to initialize app: %v", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	restoreRewrittenPath(r)
	h.ServeHTTP(w, r)
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
