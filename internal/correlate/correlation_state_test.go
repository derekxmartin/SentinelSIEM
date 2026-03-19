package correlate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

func TestStateManager_ExpireOnce(t *testing.T) {
	// Set up an event_count evaluator with data that should expire.
	ecRule := &CorrelationRule{
		ID:        "ec-exp",
		Type:      CorrelationEventCount,
		Rules:     []string{"r1"},
		GroupBy:   []string{"user.name"},
		Timespan:  5 * time.Minute,
		Condition: OpGTE,
		Threshold: 100,
	}
	ecEval := NewEventCountEvaluator([]*CorrelationRule{ecRule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ecEval.Process(makeAlert("r1"), makeTemporalEvent(base, "alice"))
	ecEval.Process(makeAlert("r1"), makeTemporalEvent(base.Add(1*time.Minute), "bob"))

	sm := NewStateManager(ecEval, nil, nil, StateManagerConfig{
		ExpiryInterval: 1 * time.Second,
	})

	// Before expiry — 2 buckets active.
	h := sm.Health()
	if h.EventCount["ec-exp"] != 2 {
		t.Fatalf("expected 2 event_count buckets, got %d", h.EventCount["ec-exp"])
	}

	// ExpireOnce with time well past the window.
	// We need to manipulate time — ExpireState uses the passed time.
	// Use the evaluator directly since ExpireOnce calls expireAll which uses time.Now().
	expired := ecEval.ExpireState(base.Add(10 * time.Minute))
	if expired != 2 {
		t.Fatalf("expected 2 expired, got %d", expired)
	}

	h = sm.Health()
	if h.EventCount["ec-exp"] != 0 {
		t.Errorf("expected 0 buckets after expiry, got %d", h.EventCount["ec-exp"])
	}
}

func TestStateManager_Health_AllEvaluators(t *testing.T) {
	ecRule := &CorrelationRule{
		ID: "ec-1", Type: CorrelationEventCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, Timespan: 10 * time.Minute,
		Condition: OpGTE, Threshold: 100,
	}
	vcRule := &CorrelationRule{
		ID: "vc-1", Type: CorrelationValueCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, ValueField: "host.name",
		Timespan: 10 * time.Minute, Condition: OpGTE, Threshold: 100,
	}
	tpRule := &CorrelationRule{
		ID: "tp-1", Type: CorrelationTemporal, Rules: []string{"r1", "r2"},
		GroupBy: []string{"user.name"}, Timespan: 10 * time.Minute,
		Ordered: true, Condition: OpGTE, Threshold: 1,
	}

	ecEval := NewEventCountEvaluator([]*CorrelationRule{ecRule})
	vcEval := NewValueCountEvaluator([]*CorrelationRule{vcRule})
	tpEval := NewTemporalEvaluator([]*CorrelationRule{tpRule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	event := makeTemporalEvent(base, "alice")

	ecEval.Process(makeAlert("r1"), event)
	vcEval.Process(makeAlert("r1"), &common.ECSEvent{
		Timestamp: base, User: &common.UserFields{Name: "alice"},
		Host: &common.HostFields{Name: "HOST-A"},
	})
	tpEval.Process(makeAlert("r1"), event)

	sm := NewStateManager(ecEval, vcEval, tpEval, StateManagerConfig{
		ExpiryInterval:    30 * time.Second,
		MaxBucketsPerRule: 10000,
	})

	h := sm.Health()

	if h.EventCount["ec-1"] != 1 {
		t.Errorf("expected 1 event_count bucket, got %d", h.EventCount["ec-1"])
	}
	if h.ValueCount["vc-1"] != 1 {
		t.Errorf("expected 1 value_count bucket, got %d", h.ValueCount["vc-1"])
	}
	if h.Temporal["tp-1"] != 1 {
		t.Errorf("expected 1 temporal chain, got %d", h.Temporal["tp-1"])
	}
	if h.MaxBuckets != 10000 {
		t.Errorf("expected max_buckets 10000, got %d", h.MaxBuckets)
	}
}

func TestStateManager_HealthHandler_JSON(t *testing.T) {
	sm := NewStateManager(nil, nil, nil, StateManagerConfig{
		ExpiryInterval:    30 * time.Second,
		MaxBucketsPerRule: 5000,
	})

	handler := sm.HealthHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/correlate/health", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var h CorrelationHealth
	if err := json.NewDecoder(rr.Body).Decode(&h); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if h.MaxBuckets != 5000 {
		t.Errorf("expected max_buckets 5000 in JSON, got %d", h.MaxBuckets)
	}
	if h.TotalExpired != 0 {
		t.Errorf("expected total_expired 0, got %d", h.TotalExpired)
	}
}

func TestStateManager_NilEvaluators(t *testing.T) {
	sm := NewStateManager(nil, nil, nil, DefaultStateManagerConfig())

	h := sm.Health()
	if len(h.EventCount) != 0 || len(h.ValueCount) != 0 || len(h.Temporal) != 0 {
		t.Error("expected empty stats for nil evaluators")
	}

	// ExpireOnce should not panic with nil evaluators.
	result := sm.ExpireOnce()
	if result != 0 {
		t.Errorf("expected 0 expired for nil evaluators, got %d", result)
	}
}

func TestStateManager_StartStop(t *testing.T) {
	sm := NewStateManager(nil, nil, nil, StateManagerConfig{
		ExpiryInterval: 10 * time.Millisecond,
	})

	sm.Start()

	// Let a few ticks pass.
	time.Sleep(50 * time.Millisecond)

	// Stop should return promptly.
	done := make(chan struct{})
	go func() {
		sm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s")
	}
}

func TestStateManager_DefaultConfig(t *testing.T) {
	cfg := DefaultStateManagerConfig()
	if cfg.ExpiryInterval != 30*time.Second {
		t.Errorf("expected default expiry 30s, got %s", cfg.ExpiryInterval)
	}
	if cfg.MaxBucketsPerRule != 10000 {
		t.Errorf("expected default max buckets 10000, got %d", cfg.MaxBucketsPerRule)
	}
}

// --- PruneToLimit tests ---

func TestEventCountEvaluator_PruneToLimit(t *testing.T) {
	rule := &CorrelationRule{
		ID: "ec-prune", Type: CorrelationEventCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, Timespan: 10 * time.Minute,
		Condition: OpGTE, Threshold: 100,
	}
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create 5 buckets.
	for i := 0; i < 5; i++ {
		eval.Process(makeAlert("r1"), makeTemporalEvent(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("user-%d", i)))
	}

	stats := eval.Stats()
	if stats["ec-prune"] != 5 {
		t.Fatalf("expected 5 buckets, got %d", stats["ec-prune"])
	}

	// Prune to 3.
	pruned := eval.PruneToLimit(3)
	if pruned != 2 {
		t.Errorf("expected 2 pruned, got %d", pruned)
	}

	stats = eval.Stats()
	if stats["ec-prune"] != 3 {
		t.Errorf("expected 3 buckets after prune, got %d", stats["ec-prune"])
	}
}

func TestValueCountEvaluator_PruneToLimit(t *testing.T) {
	rule := &CorrelationRule{
		ID: "vc-prune", Type: CorrelationValueCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, ValueField: "host.name",
		Timespan: 10 * time.Minute, Condition: OpGTE, Threshold: 100,
	}
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		eval.Process(makeAlert("r1"), makeEventWithSource(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("user-%d", i), "HOST-A", "10.0.0.1"))
	}

	stats := eval.Stats()
	if stats["vc-prune"] != 5 {
		t.Fatalf("expected 5 buckets, got %d", stats["vc-prune"])
	}

	pruned := eval.PruneToLimit(2)
	if pruned != 3 {
		t.Errorf("expected 3 pruned, got %d", pruned)
	}

	stats = eval.Stats()
	if stats["vc-prune"] != 2 {
		t.Errorf("expected 2 buckets after prune, got %d", stats["vc-prune"])
	}
}

func TestTemporalEvaluator_PruneToLimit(t *testing.T) {
	rule := &CorrelationRule{
		ID: "tp-prune", Type: CorrelationTemporal, Rules: []string{"a", "b"},
		GroupBy: []string{"user.name"}, Timespan: 10 * time.Minute,
		Ordered: true, Condition: OpGTE, Threshold: 1,
	}
	eval := NewTemporalEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		eval.Process(makeAlertForRule("a"), makeTemporalEvent(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("user-%d", i)))
	}

	stats := eval.Stats()
	if stats["tp-prune"] != 5 {
		t.Fatalf("expected 5 chains, got %d", stats["tp-prune"])
	}

	pruned := eval.PruneToLimit(1)
	if pruned != 4 {
		t.Errorf("expected 4 pruned, got %d", pruned)
	}

	stats = eval.Stats()
	if stats["tp-prune"] != 1 {
		t.Errorf("expected 1 chain after prune, got %d", stats["tp-prune"])
	}
}

func TestPruneToLimit_UnlimitedSkips(t *testing.T) {
	rule := &CorrelationRule{
		ID: "ec-unlim", Type: CorrelationEventCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, Timespan: 10 * time.Minute,
		Condition: OpGTE, Threshold: 100,
	}
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		eval.Process(makeAlert("r1"), makeTemporalEvent(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("user-%d", i)))
	}

	sm := NewStateManager(eval, nil, nil, StateManagerConfig{
		ExpiryInterval:    30 * time.Second,
		MaxBucketsPerRule: 0, // unlimited
	})

	// Test only pruneAll — should not prune anything when unlimited.
	pruned := sm.pruneAll()
	if pruned != 0 {
		t.Errorf("expected 0 pruned with unlimited config, got %d", pruned)
	}

	// All 10 buckets should still be present.
	stats := eval.Stats()
	if stats["ec-unlim"] != 10 {
		t.Errorf("expected 10 buckets still present, got %d", stats["ec-unlim"])
	}
}

func TestStateManager_MemoryBoundsEnforced(t *testing.T) {
	rule := &CorrelationRule{
		ID: "ec-bounded", Type: CorrelationEventCount, Rules: []string{"r1"},
		GroupBy: []string{"user.name"}, Timespan: 1 * time.Hour,
		Condition: OpGTE, Threshold: 100,
	}
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create 20 buckets.
	for i := 0; i < 20; i++ {
		eval.Process(makeAlert("r1"), makeTemporalEvent(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("user-%d", i)))
	}

	sm := NewStateManager(eval, nil, nil, StateManagerConfig{
		ExpiryInterval:    30 * time.Second,
		MaxBucketsPerRule: 10,
	})

	sm.ExpireOnce()

	stats := eval.Stats()
	if stats["ec-bounded"] > 10 {
		t.Errorf("expected at most 10 buckets, got %d", stats["ec-bounded"])
	}
}
