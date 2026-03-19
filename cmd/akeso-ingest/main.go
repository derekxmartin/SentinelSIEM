package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/alert"
	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/config"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
	"github.com/derekxmartin/akeso-siem/internal/ingest"
	"github.com/derekxmartin/akeso-siem/internal/lifecycle"
	"github.com/derekxmartin/akeso-siem/internal/metrics"
	"github.com/derekxmartin/akeso-siem/internal/normalize"
	"github.com/derekxmartin/akeso-siem/internal/normalize/parsers"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

func main() {
	configPath := flag.String("config", "akeso.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logCleanup, err := common.SetupLogging(cfg.Logging, "akeso-ingest")
	if err != nil {
		log.Fatalf("Failed to setup file logging: %v", err)
	}
	defer logCleanup()

	// Initialize parser registry with all known parsers.
	registry := normalize.NewRegistry()
	registry.Register(parsers.Newakeso_edrParser())
	registry.Register(parsers.NewAkesoNDRParser())
	registry.Register(parsers.NewWinEvtXMLParser())
	registry.Register(parsers.NewWinEvtJSONParser())

	// Register syslog parser with sub-parsers from config dir.
	syslogParser, err := parsers.NewSyslogECSParser(cfg.Ingest.Syslog.SubParserDir)
	if err != nil {
		log.Fatalf("Failed to create syslog parser: %v", err)
	}
	registry.Register(syslogParser)

	engine := normalize.NewEngine(registry)

	log.Printf("Registered parsers: %v", registry.SourceTypes())

	// Initialize Elasticsearch store.
	esStore, err := store.New(cfg.Elasticsearch)
	if err != nil {
		log.Fatalf("Failed to create Elasticsearch store: %v", err)
	}

	// Ensure index template exists.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := esStore.EnsureTemplate(ctx); err != nil {
		log.Printf("Warning: failed to ensure index template (ES may be unavailable): %v", err)
	} else {
		log.Println("Elasticsearch index template ensured")
	}

	// Ensure NDR host score index exists.
	if err := esStore.EnsureHostScoreIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure host score index (ES may be unavailable): %v", err)
	} else {
		log.Println("NDR host score index ensured")
	}

	// Create hot-reloadable Sigma rule loader.
	reloadInterval := time.Duration(cfg.Correlate.ReloadInterval) * time.Second
	ruleLoader := correlate.NewRuleLoader(cfg.Correlate.RulesDir, cfg.Correlate.LogsourceMapPath, reloadInterval)
	stats := ruleLoader.Stats()
	log.Printf("Sigma rule engine loaded: %d rules compiled, %d skipped, %d buckets, %d errors",
		stats.RulesCompiled, stats.RulesSkipped, stats.BucketCount, len(stats.CompileErrors))

	// Start file watcher for hot-reload.
	ruleLoader.StartWatcher()

	// Create alert dedup cache.
	var dedupCache *correlate.DedupCache
	if cfg.Correlate.DedupWindowSec > 0 {
		dedupCache = correlate.NewDedupCache(time.Duration(cfg.Correlate.DedupWindowSec) * time.Second)
		log.Printf("Alert dedup window: %ds", cfg.Correlate.DedupWindowSec)
	}

	// Build the ingest pipeline: HTTP → normalize → ES → rule engine.
	// esStore implements both Indexer and HostScoreIndexer.
	pipeline := ingest.NewPipeline(engine, esStore, cfg.Elasticsearch.IndexPrefix, esStore, ruleLoader, dedupCache)

	// Create dead letter queue for failed events.
	dlq := ingest.NewDeadLetterQueue(esStore, cfg.Elasticsearch.IndexPrefix)
	pipeline.SetDLQ(dlq)
	log.Println("Dead letter queue enabled")

	// Create alert retry queue (3 retries with exponential backoff → DLQ).
	alertRetryQ := alert.NewRetryQueue(esStore, dlq)
	pipeline.SetAlertRetryQueue(alertRetryQ)
	log.Println("Alert retry queue enabled (max 3 retries)")

	listener := ingest.NewHTTPListener(cfg.Ingest, pipeline.Handle)

	// Mount the reload endpoint for CLI-triggered hot-reload.
	listener.Post("/api/v1/rules/reload", ruleLoader.ReloadHandler())

	// Create correlation state manager for expiration and memory bounds.
	stateManager := correlate.NewStateManager(nil, nil, nil, correlate.StateManagerConfig{
		ExpiryInterval:    time.Duration(cfg.Correlate.StateExpirySec) * time.Second,
		MaxBucketsPerRule: cfg.Correlate.MaxBucketsPerRule,
	})
	stateManager.Start()

	// Mount correlation health endpoint.
	listener.Get("/api/v1/correlate/health", stateManager.HealthHandler())

	// Mount Prometheus metrics endpoint.
	listener.Get("/metrics", metrics.Handler().ServeHTTP)

	// Set initial rules loaded gauge.
	metrics.RulesLoaded.Set(float64(stats.RulesCompiled))

	srv := &http.Server{
		Addr:         listener.ListenAddr(),
		Handler:      listener.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start syslog listener.
	syslogListener := ingest.NewSyslogListener(cfg.Ingest.Syslog, pipeline.Handle)
	syslogCtx, syslogCancel := context.WithCancel(context.Background())
	defer syslogCancel()

	if err := syslogListener.Start(syslogCtx); err != nil {
		log.Printf("Warning: syslog listener failed to start: %v", err)
	}
	if err := syslogListener.StartTLS(syslogCtx); err != nil {
		log.Printf("Warning: syslog TLS listener failed to start: %v", err)
	}

	// Start HTTP server in background.
	go func() {
		fmt.Printf("akeso-ingest listening on %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Register ordered shutdown phases.
	// Order: stop accepting → drain in-flight → flush state → close background workers.
	sm := lifecycle.NewShutdownManager(10 * time.Second)

	sm.Register("stop HTTP server", func(ctx context.Context) error {
		return srv.Shutdown(ctx)
	})

	sm.Register("stop syslog listeners", func(ctx context.Context) error {
		syslogCancel()
		return syslogListener.Stop()
	})

	sm.Register("drain in-flight events", func(_ context.Context) error {
		pipeline.Drain()
		log.Printf("[shutdown] %d events processed during lifetime", pipeline.Processed())
		return nil
	})

	sm.Register("stop correlation state manager", func(_ context.Context) error {
		stateManager.Stop()
		return nil
	})

	sm.Register("flush alert retry queue", func(_ context.Context) error {
		alertRetryQ.Stop()
		return nil
	})

	sm.Register("flush dead letter queue", func(_ context.Context) error {
		dlq.Stop()
		return nil
	})

	sm.Register("stop rule loader", func(_ context.Context) error {
		ruleLoader.Stop()
		return nil
	})

	// Block until signal, then run all phases.
	if err := sm.WaitForSignal(); err != nil {
		log.Printf("Shutdown completed with errors: %v", err)
	}
}
