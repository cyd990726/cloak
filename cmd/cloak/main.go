package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"cloak/internal/app"
	"cloak/internal/ja3"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("cloak starting, config=%s", *configPath)

	h, cfg, err := app.New(*configPath)
	if err != nil {
		log.Fatalf("failed to initialize app: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// JA3 is now read from context by rules, no need to set headers
			h.ServeHTTP(w, r)
		}),
	}

	go func() {
		log.Printf("HTTP listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	if cfg.Server.HTTPSPort > 0 && cfg.Server.CertFile != "" && cfg.Server.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
		if err != nil {
			log.Printf("failed to load TLS cert: %v, HTTPS disabled", err)
		} else {
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			rawListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HTTPSPort))
			if err != nil {
				log.Printf("failed to listen HTTPS: %v", err)
			} else {
				ja3Listener := ja3.NewListener(rawListener, tlsConfig, nil)

				httpsSrv := &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						// JA3 is passed via ConnContext, rules read it from context
						h.ServeHTTP(w, r)
					}),
					ConnContext: func(ctx context.Context, c net.Conn) context.Context {
						if jc, ok := c.(*ja3.Conn); ok {
							return context.WithValue(ctx, ja3.ContextKey, jc.Fingerprint)
						}
						return ctx
					},
				}

				go func() {
					log.Printf("HTTPS listening on :%d", cfg.Server.HTTPSPort)
					if err := httpsSrv.Serve(ja3Listener); err != nil && err != http.ErrServerClosed {
						log.Printf("HTTPS server error: %v", err)
					}
				}()
			}
		}
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
}
