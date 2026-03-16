package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/query"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

func main() {
	configPath := flag.String("config", "sentinel.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize Elasticsearch store.
	esStore, err := store.New(cfg.Elasticsearch)
	if err != nil {
		log.Fatalf("Failed to create Elasticsearch store: %v", err)
	}

	// Create store adapter that maps store.SearchRawResult → query.SearchRawResult.
	searcher := &storeAdapter{store: esStore}

	// Default index pattern from config prefix.
	defaultIndex := cfg.Elasticsearch.IndexPrefix + "-events-*"

	// Create API handler.
	apiHandler := query.NewAPIHandler(searcher, defaultIndex)

	// Build router with middleware.
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.Query.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-API-Key"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes.
	r.Get("/api/v1/health", apiHandler.HandleHealth)
	r.Post("/api/v1/query", apiHandler.HandleQuery)

	// Server.
	addr := fmt.Sprintf("%s:%d", cfg.Query.Addr, cfg.Query.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("sentinel-query listening on %s\n", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-done
	fmt.Println("\nShutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	fmt.Println("Stopped.")
}

// storeAdapter adapts store.Store to the query.Searcher interface,
// mapping store.SearchRawResult → query.SearchRawResult to avoid import cycles.
type storeAdapter struct {
	store *store.Store
}

func (a *storeAdapter) SearchRaw(ctx context.Context, index string, body map[string]any) (*query.SearchRawResult, error) {
	result, err := a.store.SearchRaw(ctx, index, body)
	if err != nil {
		return nil, err
	}
	return &query.SearchRawResult{
		Total:  result.Total,
		Hits:   result.Hits,
		Aggs:   result.Aggs,
		TookMs: result.TookMs,
	}, nil
}
