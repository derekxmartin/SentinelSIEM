package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// helper to create a value_count correlation rule.
func makeValueCountRule(id string, ruleIDs []string, groupBy []string, valueField string, threshold int, op ConditionOp, timespan time.Duration) *CorrelationRule {
	return &CorrelationRule{
		ID:         id,
		Title:      "Test Value Count " + id,
		Level:      "high",
		Type:       CorrelationValueCount,
		Rules:      ruleIDs,
		GroupBy:    groupBy,
		ValueField: valueField,
		Timespan:   timespan,
		Condition:  op,
		Threshold:  threshold,
	}
}

// helper to create an ECS event with user, host, and source IP.
func makeEventWithSource(ts time.Time, userName, hostName, sourceIP string) *common.ECSEvent {
	return &common.ECSEvent{
		Timestamp: ts,
		User:      &common.UserFields{Name: userName},
		Host:      &common.HostFields{Name: hostName},
		Source:    &common.EndpointFields{IP: sourceIP},
	}
}

func TestValueCountEvaluator_ThresholdMet(t *testing.T) {
	// >10 distinct hosts per user in 1hr → alert (acceptance criteria).
	rule := makeValueCountRule("vc-1", []string{"logon"}, []string{"user.name"}, "host.name", 10, OpGTE, 1*time.Hour)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 9 logons from distinct hosts — should NOT fire.
	for i := 0; i < 9; i++ {
		alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(time.Duration(i)*time.Minute), "admin", fmt.Sprintf("HOST-%d", i), "10.0.0.1"))
		if len(alerts) != 0 {
			t.Fatalf("expected no alert at event %d, got %d", i+1, len(alerts))
		}
	}

	// 10th distinct host — should fire (10 >= 10).
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(9*time.Minute), "admin", "HOST-9", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert on 10th distinct host, got %d", len(alerts))
	}
	if alerts[0].RuleID != "vc-1" {
		t.Errorf("expected rule ID vc-1, got %s", alerts[0].RuleID)
	}
	if alerts[0].Ruleset != "sigma_correlation" {
		t.Errorf("expected ruleset sigma_correlation, got %s", alerts[0].Ruleset)
	}
}

func TestValueCountEvaluator_BelowThreshold(t *testing.T) {
	// 9 distinct hosts < 10 threshold → no alert.
	rule := makeValueCountRule("vc-2", []string{"logon"}, []string{"user.name"}, "host.name", 10, OpGTE, 1*time.Hour)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 9; i++ {
		alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(time.Duration(i)*time.Minute), "admin", fmt.Sprintf("HOST-%d", i), "10.0.0.1"))
		if len(alerts) != 0 {
			t.Fatalf("expected no alert at event %d, got %d", i+1, len(alerts))
		}
	}
}

func TestValueCountEvaluator_DuplicateValuesNotCounted(t *testing.T) {
	// Same host repeated should not increase distinct count.
	rule := makeValueCountRule("vc-3", []string{"logon"}, []string{"user.name"}, "host.name", 3, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 5 events from the same host — only 1 distinct value.
	for i := 0; i < 5; i++ {
		alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(time.Duration(i)*time.Minute), "admin", "HOST-A", "10.0.0.1"))
		if len(alerts) != 0 {
			t.Fatalf("expected no alert at event %d (same host), got %d", i+1, len(alerts))
		}
	}
}

func TestValueCountEvaluator_SlidingWindowEviction(t *testing.T) {
	rule := makeValueCountRule("vc-4", []string{"logon"}, []string{"user.name"}, "host.name", 3, OpGTE, 5*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Send 2 distinct hosts at t=0, t=1m.
	eval.Process(makeAlert("logon"), makeEventWithSource(base, "admin", "HOST-A", "10.0.0.1"))
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "admin", "HOST-B", "10.0.0.1"))

	// At t=6m the first two are outside the 5m window. 3rd host → only 1 distinct in window.
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(6*time.Minute), "admin", "HOST-C", "10.0.0.1"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: old values should have been evicted")
	}
}

func TestValueCountEvaluator_GroupByIsolation(t *testing.T) {
	rule := makeValueCountRule("vc-5", []string{"logon"}, []string{"user.name"}, "host.name", 2, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// alice → HOST-A, bob → HOST-B — each user has only 1 distinct host.
	eval.Process(makeAlert("logon"), makeEventWithSource(base, "alice", "HOST-A", "10.0.0.1"))
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "bob", "HOST-B", "10.0.0.1"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: different users isolated")
	}

	// alice → HOST-B (2nd distinct host) — should fire for alice.
	alerts = eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(2*time.Minute), "alice", "HOST-B", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for alice, got %d", len(alerts))
	}
}

func TestValueCountEvaluator_SourceIPField(t *testing.T) {
	// Track distinct source IPs per user.
	rule := makeValueCountRule("vc-6", []string{"logon"}, []string{"user.name"}, "source.ip", 3, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("logon"), makeEventWithSource(base, "admin", "HOST-A", "10.0.0.1"))
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "admin", "HOST-A", "10.0.0.2"))
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(2*time.Minute), "admin", "HOST-A", "10.0.0.3"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for 3 distinct source IPs, got %d", len(alerts))
	}
}

func TestValueCountEvaluator_UnrelatedRuleIgnored(t *testing.T) {
	rule := makeValueCountRule("vc-7", []string{"logon"}, []string{"user.name"}, "host.name", 1, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	alerts := eval.Process(makeAlert("process-create"), makeEventWithSource(base, "admin", "HOST-A", "10.0.0.1"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: unrelated rule ID")
	}
}

func TestValueCountEvaluator_NoRealert(t *testing.T) {
	rule := makeValueCountRule("vc-8", []string{"logon"}, []string{"user.name"}, "host.name", 2, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("logon"), makeEventWithSource(base, "admin", "HOST-A", "10.0.0.1"))
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "admin", "HOST-B", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// 3rd distinct host within same window — should NOT re-alert.
	alerts = eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(2*time.Minute), "admin", "HOST-C", "10.0.0.1"))
	if len(alerts) != 0 {
		t.Fatal("expected no re-alert within same window")
	}
}

func TestValueCountEvaluator_RealertAfterWindowExpiry(t *testing.T) {
	rule := makeValueCountRule("vc-9", []string{"logon"}, []string{"user.name"}, "host.name", 2, OpGTE, 5*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Fire first alert.
	eval.Process(makeAlert("logon"), makeEventWithSource(base, "admin", "HOST-A", "10.0.0.1"))
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "admin", "HOST-B", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Well past window — new distinct values should fire again.
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(10*time.Minute), "admin", "HOST-C", "10.0.0.1"))
	alerts = eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(11*time.Minute), "admin", "HOST-D", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after window expiry, got %d", len(alerts))
	}
}

func TestValueCountEvaluator_NilEvent(t *testing.T) {
	rule := makeValueCountRule("vc-10", []string{"logon"}, nil, "host.name", 1, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	alerts := eval.Process(makeAlert("logon"), nil)
	if len(alerts) != 0 {
		t.Fatal("expected no alert for nil event")
	}
}

func TestValueCountEvaluator_MissingValueField(t *testing.T) {
	// If the value field doesn't exist in the event, the event is skipped.
	rule := makeValueCountRule("vc-11", []string{"logon"}, []string{"user.name"}, "source.ip", 1, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Event without Source field.
	event := &common.ECSEvent{
		Timestamp: base,
		User:      &common.UserFields{Name: "admin"},
		Host:      &common.HostFields{Name: "HOST-A"},
	}
	alerts := eval.Process(makeAlert("logon"), event)
	if len(alerts) != 0 {
		t.Fatal("expected no alert when value field is missing")
	}
}

func TestValueCountEvaluator_SkipsNonValueCountRules(t *testing.T) {
	eventCountRule := &CorrelationRule{
		ID:        "ec-1",
		Type:      CorrelationEventCount,
		Rules:     []string{"r1"},
		Timespan:  5 * time.Minute,
		Condition: OpGTE,
		Threshold: 3,
	}

	eval := NewValueCountEvaluator([]*CorrelationRule{eventCountRule})
	stats := eval.Stats()
	if len(stats) != 0 {
		t.Errorf("expected 0 value_count entries, got %d", len(stats))
	}
}

func TestValueCountEvaluator_Stats(t *testing.T) {
	rule := makeValueCountRule("vc-s1", []string{"logon"}, []string{"user.name"}, "host.name", 100, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("logon"), makeEventWithSource(base, "alice", "HOST-A", "10.0.0.1"))
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "bob", "HOST-B", "10.0.0.1"))

	stats := eval.Stats()
	if stats["vc-s1"] != 2 {
		t.Errorf("expected 2 active buckets, got %d", stats["vc-s1"])
	}
}

func TestValueCountEvaluator_ExpireState(t *testing.T) {
	rule := makeValueCountRule("vc-e1", []string{"logon"}, []string{"user.name"}, "host.name", 100, OpGTE, 5*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("logon"), makeEventWithSource(base, "alice", "HOST-A", "10.0.0.1"))
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "bob", "HOST-B", "10.0.0.1"))

	expired := eval.ExpireState(base.Add(10 * time.Minute))
	if expired != 2 {
		t.Errorf("expected 2 expired buckets, got %d", expired)
	}

	stats := eval.Stats()
	if stats["vc-e1"] != 0 {
		t.Errorf("expected 0 active buckets after expiry, got %d", stats["vc-e1"])
	}
}

func TestCountDistinct(t *testing.T) {
	entries := []valueEntry{
		{value: "a"},
		{value: "b"},
		{value: "a"},
		{value: "c"},
		{value: "b"},
	}
	if got := countDistinct(entries); got != 3 {
		t.Errorf("expected 3 distinct, got %d", got)
	}
}

func TestCountDistinct_Empty(t *testing.T) {
	if got := countDistinct(nil); got != 0 {
		t.Errorf("expected 0 distinct for empty, got %d", got)
	}
}

func TestValueCountEvaluator_GlobalGroupBy(t *testing.T) {
	// No group-by → all events in one global bucket.
	rule := makeValueCountRule("vc-g1", []string{"logon"}, nil, "host.name", 3, OpGTE, 10*time.Minute)
	eval := NewValueCountEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlert("logon"), makeEventWithSource(base, "alice", "HOST-A", "10.0.0.1"))
	eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(1*time.Minute), "bob", "HOST-B", "10.0.0.1"))
	alerts := eval.Process(makeAlert("logon"), makeEventWithSource(base.Add(2*time.Minute), "charlie", "HOST-C", "10.0.0.1"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert with global group-by, got %d", len(alerts))
	}
}
