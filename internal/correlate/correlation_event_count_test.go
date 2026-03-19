package correlate

import (
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// helper to create a correlation rule for event_count tests.
func makeEventCountRule(id string, ruleIDs []string, groupBy []string, threshold int, op ConditionOp, timespan time.Duration) *CorrelationRule {
	return &CorrelationRule{
		ID:        id,
		Title:     "Test Rule " + id,
		Level:     "high",
		Type:      CorrelationEventCount,
		Rules:     ruleIDs,
		GroupBy:   groupBy,
		Timespan:  timespan,
		Condition: op,
		Threshold: threshold,
	}
}

// helper to create a single-event alert.
func makeAlert(ruleID string) Alert {
	return Alert{
		RuleID:  ruleID,
		Title:   "Single event: " + ruleID,
		Level:   "medium",
		Ruleset: "sigma_single",
	}
}

// helper to create an ECS event with user and host fields.
func makeEvent(ts time.Time, userName, hostName string) *common.ECSEvent {
	return &common.ECSEvent{
		Timestamp: ts,
		User:      &common.UserFields{Name: userName},
		Host:      &common.HostFields{Name: hostName},
	}
}

func TestEventCountEvaluator_ThresholdMet(t *testing.T) {
	// >5 failed logons per user in 10min → alert (acceptance criteria).
	rule := makeEventCountRule("corr-1", []string{"failed-logon"}, []string{"user.name"}, 5, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 4 events — should NOT fire (4 < 5).
	for i := 0; i < 4; i++ {
		alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(time.Duration(i)*time.Minute), "admin", "HOST-A"))
		if len(alerts) != 0 {
			t.Fatalf("expected no alert at event %d, got %d", i+1, len(alerts))
		}
	}

	// 5th event — should fire (5 >= 5).
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(4*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert on 5th event, got %d", len(alerts))
	}
	if alerts[0].RuleID != "corr-1" {
		t.Errorf("expected rule ID corr-1, got %s", alerts[0].RuleID)
	}
	if alerts[0].Ruleset != "sigma_correlation" {
		t.Errorf("expected ruleset sigma_correlation, got %s", alerts[0].Ruleset)
	}
}

func TestEventCountEvaluator_BelowThreshold(t *testing.T) {
	rule := makeEventCountRule("corr-2", []string{"failed-logon"}, []string{"user.name"}, 5, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send exactly 4 events — no alert.
	for i := 0; i < 4; i++ {
		alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(time.Duration(i)*time.Minute), "admin", "HOST-A"))
		if len(alerts) != 0 {
			t.Fatalf("expected no alert at event %d, got %d", i+1, len(alerts))
		}
	}
}

func TestEventCountEvaluator_SlidingWindowEviction(t *testing.T) {
	rule := makeEventCountRule("corr-3", []string{"failed-logon"}, []string{"user.name"}, 3, OpGTE, 5*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 2 events at t=0 and t=1m.
	eval.Process(makeAlert("failed-logon"), makeEvent(base, "alice", "HOST-A"))
	eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "alice", "HOST-A"))

	// Send 3rd event at t=6m — the first two are outside the 5m window.
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(6*time.Minute), "alice", "HOST-A"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: old events should have been evicted")
	}
}

func TestEventCountEvaluator_GroupByIsolation(t *testing.T) {
	rule := makeEventCountRule("corr-4", []string{"failed-logon"}, []string{"user.name"}, 3, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 2 events for "alice" and 2 for "bob" — neither reaches 3.
	eval.Process(makeAlert("failed-logon"), makeEvent(base, "alice", "HOST-A"))
	eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "bob", "HOST-A"))
	eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(2*time.Minute), "alice", "HOST-A"))
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(3*time.Minute), "bob", "HOST-A"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: different users should be isolated")
	}

	// 3rd event for "alice" — should fire.
	alerts = eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(4*time.Minute), "alice", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for alice, got %d", len(alerts))
	}
}

func TestEventCountEvaluator_MultipleGroupByFields(t *testing.T) {
	rule := makeEventCountRule("corr-5", []string{"failed-logon"}, []string{"user.name", "host.name"}, 2, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// alice@HOST-A: 1 event
	eval.Process(makeAlert("failed-logon"), makeEvent(base, "alice", "HOST-A"))
	// alice@HOST-B: 1 event — different group
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "alice", "HOST-B"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: different host group")
	}

	// alice@HOST-A: 2nd event — should fire.
	alerts = eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(2*time.Minute), "alice", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for alice@HOST-A, got %d", len(alerts))
	}
}

func TestEventCountEvaluator_UnrelatedRuleIgnored(t *testing.T) {
	rule := makeEventCountRule("corr-6", []string{"failed-logon"}, []string{"user.name"}, 1, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Alert from a different rule ID — should be ignored.
	alerts := eval.Process(makeAlert("process-create"), makeEvent(base, "admin", "HOST-A"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: unrelated rule ID")
	}
}

func TestEventCountEvaluator_NoRealert(t *testing.T) {
	rule := makeEventCountRule("corr-7", []string{"failed-logon"}, []string{"user.name"}, 2, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Fire on 2nd event.
	eval.Process(makeAlert("failed-logon"), makeEvent(base, "admin", "HOST-A"))
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// 3rd event within same window — should NOT re-alert.
	alerts = eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(2*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 0 {
		t.Fatal("expected no re-alert within same window")
	}
}

func TestEventCountEvaluator_RealertAfterWindowExpiry(t *testing.T) {
	rule := makeEventCountRule("corr-8", []string{"failed-logon"}, []string{"user.name"}, 2, OpGTE, 5*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Fire alert.
	eval.Process(makeAlert("failed-logon"), makeEvent(base, "admin", "HOST-A"))
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Wait well past the window so old events are fully evicted, then send 2 more.
	eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(10*time.Minute), "admin", "HOST-A"))
	alerts = eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(11*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after window expiry, got %d", len(alerts))
	}
}

func TestEventCountEvaluator_GlobalGroupBy(t *testing.T) {
	// No group-by fields → all events go into a single global bucket.
	rule := makeEventCountRule("corr-9", []string{"failed-logon"}, nil, 3, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("failed-logon"), makeEvent(base, "alice", "HOST-A"))
	eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(1*time.Minute), "bob", "HOST-B"))
	alerts := eval.Process(makeAlert("failed-logon"), makeEvent(base.Add(2*time.Minute), "charlie", "HOST-C"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert with global group-by, got %d", len(alerts))
	}
}

func TestEventCountEvaluator_NilEvent(t *testing.T) {
	rule := makeEventCountRule("corr-10", []string{"failed-logon"}, nil, 1, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	alerts := eval.Process(makeAlert("failed-logon"), nil)
	if len(alerts) != 0 {
		t.Fatal("expected no alert for nil event")
	}
}

func TestEventCountEvaluator_ConditionOperators(t *testing.T) {
	tests := []struct {
		name      string
		op        ConditionOp
		threshold int
		count     int
		want      bool
	}{
		{"gte_met", OpGTE, 3, 3, true},
		{"gte_above", OpGTE, 3, 5, true},
		{"gte_below", OpGTE, 3, 2, false},
		{"gt_met", OpGT, 3, 4, true},
		{"gt_equal", OpGT, 3, 3, false},
		{"lte_met", OpLTE, 3, 3, true},
		{"lte_below", OpLTE, 3, 2, true},
		{"lte_above", OpLTE, 3, 4, false},
		{"lt_met", OpLT, 3, 2, true},
		{"lt_equal", OpLT, 3, 3, false},
		{"eq_met", OpEQ, 3, 3, true},
		{"eq_miss", OpEQ, 3, 4, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := meetsThreshold(tt.count, tt.op, tt.threshold)
			if got != tt.want {
				t.Errorf("meetsThreshold(%d, %s, %d) = %v, want %v", tt.count, tt.op, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestEventCountEvaluator_SkipsNonEventCountRules(t *testing.T) {
	valueCountRule := &CorrelationRule{
		ID:         "vc-1",
		Type:       CorrelationValueCount,
		Rules:      []string{"r1"},
		ValueField: "source.ip",
		Timespan:   5 * time.Minute,
		Condition:  OpGTE,
		Threshold:  3,
	}
	temporalRule := &CorrelationRule{
		ID:       "temp-1",
		Type:     CorrelationTemporal,
		Rules:    []string{"r1", "r2"},
		Ordered:  true,
		GroupBy:  []string{"user.name"},
		Timespan: 5 * time.Minute,
	}

	eval := NewEventCountEvaluator([]*CorrelationRule{valueCountRule, temporalRule})
	stats := eval.Stats()
	if len(stats) != 0 {
		t.Errorf("expected 0 event_count entries, got %d", len(stats))
	}
}

func TestEventCountEvaluator_Stats(t *testing.T) {
	rule := makeEventCountRule("corr-s1", []string{"r1"}, []string{"user.name"}, 10, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Process events for 2 different users → 2 buckets.
	eval.Process(makeAlert("r1"), makeEvent(base, "alice", "HOST-A"))
	eval.Process(makeAlert("r1"), makeEvent(base.Add(1*time.Minute), "bob", "HOST-A"))

	stats := eval.Stats()
	if stats["corr-s1"] != 2 {
		t.Errorf("expected 2 active buckets, got %d", stats["corr-s1"])
	}
}

func TestEventCountEvaluator_ExpireState(t *testing.T) {
	rule := makeEventCountRule("corr-e1", []string{"r1"}, []string{"user.name"}, 10, OpGTE, 5*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("r1"), makeEvent(base, "alice", "HOST-A"))
	eval.Process(makeAlert("r1"), makeEvent(base.Add(1*time.Minute), "bob", "HOST-A"))

	// Expire at t+10m — both buckets should be removed.
	expired := eval.ExpireState(base.Add(10 * time.Minute))
	if expired != 2 {
		t.Errorf("expected 2 expired buckets, got %d", expired)
	}

	stats := eval.Stats()
	if stats["corr-e1"] != 0 {
		t.Errorf("expected 0 active buckets after expiry, got %d", stats["corr-e1"])
	}
}

func TestEvictBefore(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	timestamps := []time.Time{
		base,
		base.Add(1 * time.Minute),
		base.Add(2 * time.Minute),
		base.Add(3 * time.Minute),
		base.Add(4 * time.Minute),
	}

	// Evict everything before t+2m.
	result := evictBefore(timestamps, base.Add(2*time.Minute))
	if len(result) != 3 {
		t.Fatalf("expected 3 remaining timestamps, got %d", len(result))
	}
	if !result[0].Equal(base.Add(2 * time.Minute)) {
		t.Errorf("first remaining should be t+2m, got %v", result[0])
	}
}

func TestEvictBefore_NoneEvicted(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	timestamps := []time.Time{base.Add(5 * time.Minute)}

	result := evictBefore(timestamps, base)
	if len(result) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(result))
	}
}

func TestEvictBefore_AllEvicted(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	timestamps := []time.Time{base, base.Add(1 * time.Minute)}

	result := evictBefore(timestamps, base.Add(5*time.Minute))
	if len(result) != 0 {
		t.Fatalf("expected 0 remaining, got %d", len(result))
	}
}

func TestBuildGroupByKey(t *testing.T) {
	event := makeEvent(time.Now(), "admin", "HOST-A")

	// Single field.
	key := buildGroupByKey([]string{"user.name"}, event)
	if key != "admin" {
		t.Errorf("expected 'admin', got %q", key)
	}

	// Multiple fields.
	key = buildGroupByKey([]string{"user.name", "host.name"}, event)
	if key != "admin|HOST-A" {
		t.Errorf("expected 'admin|HOST-A', got %q", key)
	}

	// No group-by → global key.
	key = buildGroupByKey(nil, event)
	if key != "_global_" {
		t.Errorf("expected '_global_', got %q", key)
	}
}

func TestEventCountEvaluator_MultipleRulesIndependent(t *testing.T) {
	rule1 := makeEventCountRule("corr-m1", []string{"r1"}, []string{"user.name"}, 2, OpGTE, 10*time.Minute)
	rule2 := makeEventCountRule("corr-m2", []string{"r1"}, []string{"host.name"}, 3, OpGTE, 10*time.Minute)
	eval := NewEventCountEvaluator([]*CorrelationRule{rule1, rule2})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// 1st event — no alerts.
	alerts := eval.Process(makeAlert("r1"), makeEvent(base, "admin", "HOST-A"))
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}

	// 2nd event, same user, same host — rule1 fires (2 >= 2), rule2 doesn't (2 < 3).
	alerts = eval.Process(makeAlert("r1"), makeEvent(base.Add(1*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert (rule1 only), got %d", len(alerts))
	}
	if alerts[0].RuleID != "corr-m1" {
		t.Errorf("expected corr-m1, got %s", alerts[0].RuleID)
	}

	// 3rd event — rule2 fires now (3 >= 3).
	alerts = eval.Process(makeAlert("r1"), makeEvent(base.Add(2*time.Minute), "admin", "HOST-A"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert (rule2 only), got %d", len(alerts))
	}
	if alerts[0].RuleID != "corr-m2" {
		t.Errorf("expected corr-m2, got %s", alerts[0].RuleID)
	}
}
