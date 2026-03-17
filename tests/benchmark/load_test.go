// Package benchmark provides load testing for the SentinelSIEM ingest pipeline.
//
// Tests exercise the full pipeline (normalize → index → rule eval → alert)
// using mock backends so no Elasticsearch is required.
//
// Run with:
//
//	go test ./tests/benchmark/ -v -run TestLoadTest -timeout 15m
//	go test ./tests/benchmark/ -v -run TestLoadTest -timeout 2m -loadduration 1m
package benchmark

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/correlate"
	"github.com/SentinelSIEM/sentinel-siem/internal/ingest"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize/parsers"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

var (
	loadDuration *time.Duration
	targetEPS    *int
	batchSize    *int
)

func init() {
	loadDuration = flag.Duration("loadduration", 10*time.Minute, "duration of load test")
	targetEPS = flag.Int("loadeps", 1000, "target events per second")
	batchSize = flag.Int("loadbatch", 50, "events per batch")
}

// mockIndexer counts indexed events without touching Elasticsearch.
type mockIndexer struct {
	indexed atomic.Int64
}

func (m *mockIndexer) BulkIndex(_ context.Context, _ string, events []common.ECSEvent) error {
	m.indexed.Add(int64(len(events)))
	return nil
}

var _ store.Indexer = (*mockIndexer)(nil)

// mockHostScoreIndexer is a no-op.
type mockHostScoreIndexer struct{}

func (m *mockHostScoreIndexer) UpsertHostScore(_ context.Context, _ *common.ECSEvent) error {
	return nil
}

var _ store.HostScoreIndexer = (*mockHostScoreIndexer)(nil)

// mockRuleEvaluator simulates rule evaluation with realistic latency.
// It tracks per-event evaluation times and occasionally generates alerts.
type mockRuleEvaluator struct {
	evalCount   atomic.Int64
	alertCount  atomic.Int64
	mu          sync.Mutex
	evalTimesUs []int64 // microseconds
}

func (m *mockRuleEvaluator) Evaluate(event *common.ECSEvent) []correlate.Alert {
	start := time.Now()

	// Simulate rule evaluation CPU work (~100-500µs per event).
	sum := 0.0
	iterations := 500 + rand.Intn(500)
	for i := 0; i < iterations; i++ {
		sum += math.Sqrt(float64(i))
	}

	elapsed := time.Since(start)
	m.evalCount.Add(1)

	// Track eval time.
	m.mu.Lock()
	m.evalTimesUs = append(m.evalTimesUs, elapsed.Microseconds())
	m.mu.Unlock()

	// ~1% of events generate an alert.
	if rand.Intn(100) == 0 {
		m.alertCount.Add(1)
		return []correlate.Alert{{
			RuleID: "bench-rule-001",
			Title:  "Benchmark Alert",
			Level:  "medium",
			Tags:   []string{"benchmark"},
			Event:  event,
		}}
	}
	return nil
}

func (m *mockRuleEvaluator) Stats() correlate.EngineStats {
	return correlate.EngineStats{RulesCompiled: 50}
}

func (m *mockRuleEvaluator) evalPercentile(p float64) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.evalTimesUs) == 0 {
		return 0
	}

	sorted := make([]int64, len(m.evalTimesUs))
	copy(sorted, m.evalTimesUs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(float64(len(sorted)-1) * p)
	return time.Duration(sorted[idx]) * time.Microsecond
}

// generateEvent creates a realistic JSON event matching parser envelope formats.
func generateEvent(i int, sourceTypes []string) json.RawMessage {
	st := sourceTypes[i%len(sourceTypes)]
	ts := time.Now().UTC().Format(time.RFC3339)

	var raw string
	switch st {
	case "sentinel_edr":
		// EDR envelope: host is a string, event is an inner object.
		raw = fmt.Sprintf(`{
			"source_type": "sentinel_edr",
			"schema": "sentinel/v1",
			"host": "workstation-%d",
			"agent_id": "agent-bench-%d",
			"timestamp": %q,
			"event": {
				"eventId": "bench-%d",
				"timestamp": %q,
				"source": "DriverProcess",
				"severity": "Low",
				"process": {
					"pid": %d,
					"parentPid": 1024,
					"threadId": 100,
					"sessionId": 1,
					"imagePath": "C:\\Windows\\System32\\cmd.exe",
					"commandLine": "cmd.exe /c whoami",
					"userSid": "S-1-5-21-1234-1001",
					"integrityLevel": 8192,
					"isElevated": false,
					"parentImagePath": "C:\\Windows\\explorer.exe"
				},
				"payload": {
					"isCreate": true,
					"newProcessId": %d,
					"parentProcessId": 1024,
					"imagePath": "C:\\Windows\\System32\\cmd.exe",
					"commandLine": "cmd.exe /c whoami"
				}
			}
		}`, i%100, i%1000, ts, i, ts, 1000+i%9000, 1000+i%9000)
	case "sentinel_ndr":
		// NDR envelope: needs event_type, ECS fields at top level.
		raw = fmt.Sprintf(`{
			"source_type": "sentinel_ndr",
			"timestamp": %q,
			"event_type": "ndr:session",
			"event": {"category": ["network"], "type": ["connection"], "action": "connection_end"},
			"source": {"ip": "192.168.%d.%d", "port": %d},
			"destination": {"ip": "10.%d.%d.%d", "port": 443},
			"network": {"transport": "tcp", "bytes": %d}
		}`, ts, i%256, (i/256)%256, 1024+i%64000, i%256, (i/256)%256, (i/65536)%256, 100+i%100000)
	case "winevt_json":
		// WinEvt JSON envelope.
		raw = fmt.Sprintf(`{
			"source_type": "winevt_json",
			"timestamp": %q,
			"host": {"name": "dc-%d"},
			"winlog": {"channel": "Security", "event_id": %d, "provider_name": "Microsoft-Windows-Security-Auditing"},
			"event": {"action": "logon", "category": ["authentication"], "type": ["start"]},
			"user": {"name": "admin%d"}
		}`, ts, i%10, []int{4624, 4625, 4672, 4688, 4720}[i%5], i%20)
	default:
		raw = fmt.Sprintf(`{
			"source_type": %q,
			"timestamp": %q,
			"message": "benchmark event %d"
		}`, st, ts, i)
	}
	return json.RawMessage(raw)
}

// TestLoadTest runs the sustained load test: 1000 eps × 10 min.
func TestLoadTest(t *testing.T) {
	duration := *loadDuration
	eps := *targetEPS
	batch := *batchSize

	t.Logf("Load test: %d eps × %s, batch size %d", eps, duration, batch)

	// Build normalization engine with real parsers.
	registry := normalize.NewRegistry()
	registry.Register(parsers.Newsentinel_edrParser())
	registry.Register(parsers.NewSentinelNDRParser())
	registry.Register(parsers.NewWinEvtJSONParser())
	engine := normalize.NewEngine(registry)

	// Create mock backends.
	indexer := &mockIndexer{}
	hostScore := &mockHostScoreIndexer{}
	ruleEval := &mockRuleEvaluator{}

	// Create pipeline.
	pipeline := ingest.NewPipeline(engine, indexer, "sentinel", hostScore, ruleEval, nil)

	// Source types to cycle through.
	sourceTypes := []string{"sentinel_edr", "sentinel_ndr", "winevt_json"}

	// Memory baseline.
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Track batch latencies.
	var (
		latencyMu    sync.Mutex
		latenciesMs  []float64
		totalSent    atomic.Int64
		totalBatches atomic.Int64
	)

	// Rate control: send `eps/batch` batches per second.
	batchesPerSec := eps / batch
	if batchesPerSec < 1 {
		batchesPerSec = 1
	}
	interval := time.Second / time.Duration(batchesPerSec)

	t.Logf("Sending %d batches/sec (interval %s)", batchesPerSec, interval)

	start := time.Now()
	deadline := start.Add(duration)

	// Use a fixed number of worker goroutines to send batches.
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}

	batchCh := make(chan []json.RawMessage, workers*2)
	var wg sync.WaitGroup

	// Workers consume batches.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for events := range batchCh {
				batchStart := time.Now()
				pipeline.Handle(events)
				elapsed := time.Since(batchStart)

				latencyMu.Lock()
				latenciesMs = append(latenciesMs, float64(elapsed.Milliseconds()))
				latencyMu.Unlock()

				totalBatches.Add(1)
			}
		}()
	}

	// Producer sends batches at the target rate.
	eventCounter := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Progress reporting every 10 seconds.
	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			elapsed := time.Since(start)
			if elapsed >= duration {
				return
			}
			sent := totalSent.Load()
			actualEPS := float64(sent) / elapsed.Seconds()
			indexed := indexer.indexed.Load()
			var memCurrent runtime.MemStats
			runtime.ReadMemStats(&memCurrent)
			heapMB := float64(memCurrent.HeapAlloc) / 1024 / 1024
			t.Logf("[%s] sent=%d indexed=%d eps=%.0f heap=%.1fMB alerts=%d",
				elapsed.Round(time.Second), sent, indexed, actualEPS, heapMB, ruleEval.alertCount.Load())
		}
	}()

	for time.Now().Before(deadline) {
		<-ticker.C

		// Generate batch.
		events := make([]json.RawMessage, batch)
		for i := 0; i < batch; i++ {
			events[i] = generateEvent(eventCounter, sourceTypes)
			eventCounter++
		}
		totalSent.Add(int64(batch))

		// Non-blocking send — if workers are backed up, we'll measure that as latency.
		select {
		case batchCh <- events:
		default:
			// Channel full — process inline to avoid dropping.
			batchStart := time.Now()
			pipeline.Handle(events)
			elapsed := time.Since(batchStart)
			latencyMu.Lock()
			latenciesMs = append(latenciesMs, float64(elapsed.Milliseconds()))
			latencyMu.Unlock()
			totalBatches.Add(1)
		}
	}

	close(batchCh)
	wg.Wait()

	// Wait for pipeline to drain.
	pipeline.Drain()

	totalElapsed := time.Since(start)

	// Memory after.
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// Compute latency percentiles.
	latencyMu.Lock()
	sort.Float64s(latenciesMs)
	latencies := latenciesMs
	latencyMu.Unlock()

	p50 := percentile(latencies, 0.50)
	p95 := percentile(latencies, 0.95)
	p99 := percentile(latencies, 0.99)

	// Results.
	sent := totalSent.Load()
	indexed := indexer.indexed.Load()
	actualEPS := float64(sent) / totalElapsed.Seconds()
	heapGrowthMB := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024
	evalP50 := ruleEval.evalPercentile(0.50)
	evalP95 := ruleEval.evalPercentile(0.95)
	evalP99 := ruleEval.evalPercentile(0.99)

	t.Log("========== LOAD TEST RESULTS ==========")
	t.Logf("Duration:        %s", totalElapsed.Round(time.Millisecond))
	t.Logf("Events sent:     %d", sent)
	t.Logf("Events indexed:  %d", indexed)
	t.Logf("Alerts generated:%d", ruleEval.alertCount.Load())
	t.Logf("Actual EPS:      %.0f", actualEPS)
	t.Logf("Batches:         %d", totalBatches.Load())
	t.Log("--- Pipeline Batch Latency ---")
	t.Logf("  p50:  %.0f ms", p50)
	t.Logf("  p95:  %.0f ms", p95)
	t.Logf("  p99:  %.0f ms", p99)
	t.Log("--- Rule Eval Per-Event ---")
	t.Logf("  p50:  %s", evalP50)
	t.Logf("  p95:  %s", evalP95)
	t.Logf("  p99:  %s", evalP99)
	t.Log("--- Memory ---")
	t.Logf("  Heap before:  %.1f MB", float64(memBefore.HeapAlloc)/1024/1024)
	t.Logf("  Heap after:   %.1f MB", float64(memAfter.HeapAlloc)/1024/1024)
	t.Logf("  Heap growth:  %.1f MB", heapGrowthMB)
	t.Logf("  Total alloc:  %.1f MB", float64(memAfter.TotalAlloc)/1024/1024)
	t.Log("========================================")

	// Assertions.
	if actualEPS < float64(eps)*0.9 {
		t.Errorf("FAIL: actual EPS %.0f below 90%% of target %d", actualEPS, eps)
	}

	if p95 > 5000 {
		t.Errorf("FAIL: p95 batch latency %.0fms exceeds 5s threshold", p95)
	}

	if evalP95 > 10*time.Millisecond {
		t.Errorf("FAIL: p95 rule eval %s exceeds 10ms threshold", evalP95)
	}

	// Leak check: heap growth should be reasonable (< 500MB for 600K events).
	if heapGrowthMB > 500 {
		t.Errorf("FAIL: heap grew %.1fMB — possible memory leak", heapGrowthMB)
	}

	// All sent events should be indexed (no loss).
	if indexed < sent {
		t.Errorf("FAIL: %d events sent but only %d indexed (%.1f%% loss)",
			sent, indexed, 100*(1-float64(indexed)/float64(sent)))
	}
}

// BenchmarkPipelineHandle measures per-batch throughput for Go's benchmarking framework.
func BenchmarkPipelineHandle(b *testing.B) {
	registry := normalize.NewRegistry()
	registry.Register(parsers.Newsentinel_edrParser())
	engine := normalize.NewEngine(registry)

	indexer := &mockIndexer{}
	ruleEval := &mockRuleEvaluator{}
	pipeline := ingest.NewPipeline(engine, indexer, "sentinel", nil, ruleEval, nil)

	sourceTypes := []string{"sentinel_edr"}
	events := make([]json.RawMessage, 50)
	for i := range events {
		events[i] = generateEvent(i, sourceTypes)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pipeline.Handle(events)
	}
}

// BenchmarkRuleEvaluation measures per-event rule evaluation time with the real engine.
func BenchmarkRuleEvaluation(b *testing.B) {
	// Load real rules.
	ruleLoader := correlate.NewRuleLoader("../../rules", "../../rules/logsource_map.yaml", 0)
	stats := ruleLoader.Stats()
	b.Logf("Loaded %d rules", stats.RulesCompiled)

	event := &common.ECSEvent{
		Timestamp:  time.Now(),
		SourceType: "sentinel_edr",
		Event: &common.EventFields{
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "process_create",
		},
		Host: &common.HostFields{
			Name: "workstation-1",
		},
		Process: &common.ProcessFields{
			Name:        "powershell.exe",
			CommandLine: "powershell.exe -enc SGVsbG8gV29ybGQ=",
			PID:         1234,
		},
		User: &common.UserFields{
			Name: "admin",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ruleLoader.Evaluate(event)
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
