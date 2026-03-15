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

	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/correlate"
	"github.com/SentinelSIEM/sentinel-siem/internal/ingest"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize/parsers"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

func main() {
	configPath := flag.String("config", "sentinel.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize parser registry with all known parsers.
	registry := normalize.NewRegistry()
	registry.Register(parsers.Newsentinel_edrParser())
	registry.Register(parsers.NewSentinelNDRParser())
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
	listener := ingest.NewHTTPListener(cfg.Ingest, pipeline.Handle)

	// Mount the reload endpoint for CLI-triggered hot-reload.
	listener.Post("/api/v1/rules/reload", ruleLoader.ReloadHandler())

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

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("sentinel-ingest listening on %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-done
	fmt.Println("\nShutting down...")

	// Stop rule loader file watcher.
	ruleLoader.Stop()

	// Stop syslog listener.
	syslogCancel()
	syslogListener.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	fmt.Println("Stopped.")
}
