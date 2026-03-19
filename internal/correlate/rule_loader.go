package correlate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// RuleEvaluator is the interface used by the pipeline to evaluate events.
// Both RuleEngine (static) and RuleLoader (hot-reloadable) satisfy this.
type RuleEvaluator interface {
	Evaluate(event *common.ECSEvent) []Alert
	Stats() EngineStats
}

// RuleLoader wraps a RuleEngine with hot-reload capability.
// It monitors the rules directory for changes and atomically swaps in a new
// engine when rules are added, modified, or removed. In-flight evaluations
// continue against the old engine until they complete — no event loss.
type RuleLoader struct {
	engine         atomic.Pointer[RuleEngine]
	rulesDir       string
	logsourceMap   string
	reloadInterval time.Duration
	lastChecksum   atomic.Value // stores [32]byte
	cancel         context.CancelFunc
	done           chan struct{}
}

// NewRuleLoader creates a RuleLoader that manages hot-reloadable Sigma rules.
// It performs an initial load of rules from rulesDir. If the initial load fails
// (no rules found, logsource map missing), the loader starts with an empty engine
// and will pick up rules on the next poll cycle.
//
// reloadInterval controls the polling frequency. Use 0 for default (10s).
func NewRuleLoader(rulesDir, logsourceMapPath string, reloadInterval time.Duration) *RuleLoader {
	if reloadInterval <= 0 {
		reloadInterval = 10 * time.Second
	}

	rl := &RuleLoader{
		rulesDir:       rulesDir,
		logsourceMap:   logsourceMapPath,
		reloadInterval: reloadInterval,
		done:           make(chan struct{}),
	}

	// Initial load.
	engine, checksum := rl.buildEngine()
	rl.engine.Store(engine)
	rl.lastChecksum.Store(checksum)

	return rl
}

// Evaluate routes an event through the current rule engine.
// Safe for concurrent use. In-flight calls continue against the engine
// snapshot they started with, even if a reload swaps in a new engine.
func (rl *RuleLoader) Evaluate(event *common.ECSEvent) []Alert {
	return rl.engine.Load().Evaluate(event)
}

// Stats returns the current engine's statistics.
func (rl *RuleLoader) Stats() EngineStats {
	return rl.engine.Load().Stats()
}

// Reload forces an immediate reload of rules from disk.
// Returns the new engine stats and any error. Thread-safe.
func (rl *RuleLoader) Reload() (EngineStats, error) {
	engine, checksum := rl.buildEngine()
	rl.engine.Store(engine)
	rl.lastChecksum.Store(checksum)

	stats := engine.Stats()
	log.Printf("[rule-loader] reload complete: %d compiled, %d skipped, %d buckets",
		stats.RulesCompiled, stats.RulesSkipped, stats.BucketCount)

	return stats, nil
}

// StartWatcher begins polling the rules directory for changes.
// When file modifications are detected (via checksum of paths + mod times),
// a new RuleEngine is built and atomically swapped in.
// Call Stop() to shut down the watcher.
func (rl *RuleLoader) StartWatcher() {
	ctx, cancel := context.WithCancel(context.Background())
	rl.cancel = cancel

	go rl.pollLoop(ctx)
	log.Printf("[rule-loader] file watcher started (interval=%s, dir=%s)", rl.reloadInterval, rl.rulesDir)
}

// Stop shuts down the file watcher. Blocks until the poll loop exits.
func (rl *RuleLoader) Stop() {
	if rl.cancel != nil {
		rl.cancel()
		<-rl.done
		log.Println("[rule-loader] file watcher stopped")
	}
}

// ReloadHandler returns an HTTP handler for POST /api/v1/rules/reload.
// Triggers an immediate reload and returns the new engine stats as JSON.
func (rl *RuleLoader) ReloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		stats, err := rl.Reload()
		if err != nil {
			http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","rules_compiled":%d,"rules_skipped":%d,"buckets":%d,"errors":%d}`,
			stats.RulesCompiled, stats.RulesSkipped, stats.BucketCount, len(stats.CompileErrors))
	}
}

// pollLoop checks the rules directory for changes at each interval.
func (rl *RuleLoader) pollLoop(ctx context.Context) {
	defer close(rl.done)

	ticker := time.NewTicker(rl.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.checkAndReload()
		}
	}
}

// checkAndReload computes a checksum of the rules directory and reloads
// if it differs from the last known state.
func (rl *RuleLoader) checkAndReload() {
	checksum := rl.computeChecksum()
	last, _ := rl.lastChecksum.Load().([32]byte)

	if checksum == last {
		return
	}

	log.Println("[rule-loader] rule file changes detected, reloading...")
	rl.Reload()
}

// buildEngine loads rules from disk and creates a new RuleEngine.
// Returns an empty engine (no rules) if loading fails, so the system
// degrades gracefully rather than crashing.
func (rl *RuleLoader) buildEngine() (*RuleEngine, [32]byte) {
	checksum := rl.computeChecksum()

	rules, parseErrors := LoadRulesFromDir(rl.rulesDir)
	for _, pe := range parseErrors {
		log.Printf("[rule-loader] parse error: %v", pe)
	}

	if len(rules) == 0 {
		log.Printf("[rule-loader] no rules found in %s, engine will have no rules", rl.rulesDir)
		return NewRuleEngine(NewRuleRegistry(nil), &LogsourceMap{}), checksum
	}

	lsMap, err := LoadLogsourceMap(rl.logsourceMap)
	if err != nil {
		log.Printf("[rule-loader] failed to load logsource map: %v", err)
		return NewRuleEngine(NewRuleRegistry(nil), &LogsourceMap{}), checksum
	}

	registry := NewRuleRegistry(rules)
	engine := NewRuleEngine(registry, lsMap)

	stats := engine.Stats()
	log.Printf("[rule-loader] built engine: %d rules compiled, %d skipped, %d buckets, %d errors",
		stats.RulesCompiled, stats.RulesSkipped, stats.BucketCount, len(stats.CompileErrors))

	return engine, checksum
}

// computeChecksum produces a SHA-256 digest of all rule file paths and their
// modification times. A change in any file (added, modified, or removed)
// produces a different checksum.
func (rl *RuleLoader) computeChecksum() [32]byte {
	var entries []string

	_ = filepath.Walk(rl.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		// Use relative path + mod time as the fingerprint for this file.
		rel, _ := filepath.Rel(rl.rulesDir, path)
		entries = append(entries, fmt.Sprintf("%s:%d", rel, info.ModTime().UnixNano()))
		return nil
	})

	// Sort for deterministic checksums regardless of walk order.
	sort.Strings(entries)

	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e))
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
