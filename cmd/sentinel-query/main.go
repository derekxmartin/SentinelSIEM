package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/SentinelSIEM/sentinel-siem/internal/auth"
	"github.com/SentinelSIEM/sentinel-siem/internal/cases"
	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/lifecycle"
	"github.com/SentinelSIEM/sentinel-siem/internal/metrics"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/query"
	"github.com/SentinelSIEM/sentinel-siem/internal/sources"
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

	// Ensure dedicated indices exist.
	ctx := context.Background()
	if err := esStore.EnsureSourceIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure source index: %v", err)
	}
	if err := esStore.EnsureUserIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure user index: %v", err)
	}
	if err := esStore.EnsureSessionIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure session index: %v", err)
	}
	if err := esStore.EnsureCaseIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure case index: %v", err)
	}

	// Initialize API key store.
	apiKeyIndex := esStore.Prefix() + "-api-keys"
	keyStore := common.NewAPIKeyStore(esStore, apiKeyIndex)
	if err := keyStore.LoadAll(ctx); err != nil {
		log.Printf("Warning: failed to load API keys: %v", err)
	}

	// Initialize JWT manager.
	jwtSecret := []byte(cfg.Auth.JWTSecret)
	jwtManager := auth.NewJWTManager(jwtSecret)

	// Initialize MFA encryptor (optional — MFA enrollment disabled if not configured).
	var mfaEncryptor *auth.MFAEncryptor
	if cfg.Auth.MFAEncryptionKey != "" {
		enc, err := auth.NewMFAEncryptor(cfg.Auth.MFAEncryptionKey)
		if err != nil {
			log.Fatalf("Invalid MFA encryption key: %v", err)
		}
		mfaEncryptor = enc
		log.Println("MFA encryption configured")
	} else {
		log.Println("MFA encryption key not set — MFA enrollment will be unavailable")
	}

	// Initialize auth service.
	authService := auth.NewService(esStore, jwtManager, mfaEncryptor, esStore.UserIndexName(), esStore.SessionIndexName())

	// Initialize normalization engine (for parser testing).
	registry := normalize.NewRegistry()
	engine := normalize.NewEngine(registry)

	// Initialize source service and handler.
	sourceService := sources.NewService(esStore, keyStore, esStore.SourceIndexName())
	sourceHandler := sources.NewAPIHandler(sourceService, engine)

	// Create store adapter that maps store.SearchRawResult → query.SearchRawResult.
	searcher := &storeAdapter{store: esStore}

	// Default index pattern from config prefix.
	defaultIndex := cfg.Elasticsearch.IndexPrefix + "-events-*"

	// Create query API handler.
	apiHandler := query.NewAPIHandler(searcher, defaultIndex)

	// Create auth API handler with login rate limiter (5 attempts per 30s per IP).
	loginLimiter := auth.NewLoginRateLimiter(5, 30*time.Second)
	authHandler := auth.NewAPIHandler(authService, loginLimiter)

	// Initialize case management services.
	caseIndex := esStore.Prefix() + "-cases"
	caseSvc := cases.NewService(esStore, caseIndex)
	alertIndex := esStore.Prefix() + "-alerts-*"
	escalationSvc := cases.NewEscalationService(caseSvc, esStore, alertIndex)
	caseHandler := cases.NewCaseAPIHandler(caseSvc, escalationSvc)

	// Create admin handler for user and API key management.
	adminHandler := auth.NewAdminHandler(authService, keyStore)

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
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-API-Key", "Authorization"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Prometheus metrics endpoint (no auth — scraped by infrastructure).
	r.Handle("/metrics", metrics.Handler())

	// Public routes (no auth required).
	r.Get("/api/v1/health", apiHandler.HandleHealth)
	r.Post("/api/v1/auth/login", authHandler.HandleLogin)
	r.Post("/api/v1/auth/mfa", authHandler.HandleMFAVerify)
	r.Post("/api/v1/auth/refresh", authHandler.HandleRefresh)
	r.Get("/api/v1/auth/setup-required", authHandler.HandleSetupRequired)
	r.Post("/api/v1/auth/setup", authHandler.HandleFirstRunSetup)

	// Protected routes (JWT or API key required).
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(jwtManager, keyStore))

		// Query.
		r.Post("/api/v1/query", apiHandler.HandleQuery)

		// Auth management.
		r.Post("/api/v1/auth/logout", authHandler.HandleLogout)
		r.Get("/api/v1/auth/profile", authHandler.HandleGetProfile)
		r.Put("/api/v1/auth/profile", authHandler.HandleUpdateProfile)
		r.Post("/api/v1/auth/password", authHandler.HandleChangePassword)

		// MFA management (requires active session).
		r.Post("/api/v1/auth/me/mfa/enroll", authHandler.HandleMFAEnroll)
		r.Post("/api/v1/auth/me/mfa/verify", authHandler.HandleMFAVerifyEnrollment)
		r.Delete("/api/v1/auth/me/mfa", authHandler.HandleMFADisable)

		// Source management routes.
		sourceHandler.Routes(r)

		// Case management routes.
		caseHandler.Routes(r)

		// Admin routes (admin role required).
		adminHandler.Routes(r)
	})

	// Server.
	addr := fmt.Sprintf("%s:%d", cfg.Query.Addr, cfg.Query.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in background.
	go func() {
		fmt.Printf("sentinel-query listening on %s\n", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Register ordered shutdown phases.
	sm := lifecycle.NewShutdownManager(10 * time.Second)

	sm.Register("stop HTTP server", func(ctx context.Context) error {
		return srv.Shutdown(ctx)
	})

	sm.Register("flush login rate limiter", func(_ context.Context) error {
		loginLimiter.Stop()
		return nil
	})

	// Block until signal, then run all phases.
	if err := sm.WaitForSignal(); err != nil {
		log.Printf("Shutdown completed with errors: %v", err)
	}
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
