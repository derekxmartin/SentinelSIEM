package correlate

import (
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// helper to create a temporal correlation rule.
func makeTemporalRule(id string, ruleIDs []string, groupBy []string, timespan time.Duration) *CorrelationRule {
	return &CorrelationRule{
		ID:        id,
		Title:     "Temporal " + id,
		Level:     "critical",
		Type:      CorrelationTemporal,
		Rules:     ruleIDs,
		GroupBy:   groupBy,
		Timespan:  timespan,
		Ordered:   true,
		Condition: OpGTE,
		Threshold: 1,
	}
}

// helper to create an alert with a given rule ID.
func makeAlertForRule(ruleID string) Alert {
	return Alert{RuleID: ruleID, Ruleset: "sigma_single"}
}

// helper to create an ECS event with user and timestamp.
func makeTemporalEvent(ts time.Time, userName string) *common.ECSEvent {
	return &common.ECSEvent{
		Timestamp: ts,
		User:      &common.UserFields{Name: userName},
	}
}

// --- Acceptance criteria: failed→success→lsass in order within 15min → alert ---

func TestTemporalEvaluator_OrderedSequenceFires(t *testing.T) {
	// Three-step sequence: failed_logon → successful_logon → lsass_access
	rule := makeTemporalRule("t-1",
		[]string{"failed_logon", "successful_logon", "lsass_access"},
		[]string{"user.name"}, 15*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Step 1: failed logon.
	alerts := eval.Process(makeAlertForRule("failed_logon"), makeTemporalEvent(base, "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert after step 1")
	}

	// Step 2: successful logon.
	alerts = eval.Process(makeAlertForRule("successful_logon"), makeTemporalEvent(base.Add(3*time.Minute), "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert after step 2")
	}

	// Step 3: lsass access → alert fires.
	alerts = eval.Process(makeAlertForRule("lsass_access"), makeTemporalEvent(base.Add(5*time.Minute), "admin"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert on sequence completion, got %d", len(alerts))
	}
	if alerts[0].RuleID != "t-1" {
		t.Errorf("expected rule ID t-1, got %s", alerts[0].RuleID)
	}
	if alerts[0].Ruleset != "sigma_correlation" {
		t.Errorf("expected ruleset sigma_correlation, got %s", alerts[0].Ruleset)
	}
}

// --- Acceptance criteria: out of order → no alert ---

func TestTemporalEvaluator_OutOfOrderNoAlert(t *testing.T) {
	rule := makeTemporalRule("t-2",
		[]string{"failed_logon", "successful_logon", "lsass_access"},
		[]string{"user.name"}, 15*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Wrong order: lsass first, then successful, then failed.
	eval.Process(makeAlertForRule("lsass_access"), makeTemporalEvent(base, "admin"))
	eval.Process(makeAlertForRule("successful_logon"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))
	alerts := eval.Process(makeAlertForRule("failed_logon"), makeTemporalEvent(base.Add(2*time.Minute), "admin"))

	// failed_logon at step 3 starts a new chain (it's step 0).
	// But the sequence is not complete (only 1 step matched).
	if len(alerts) != 0 {
		t.Fatal("expected no alert for out-of-order sequence")
	}
}

func TestTemporalEvaluator_PartialSequenceNoAlert(t *testing.T) {
	rule := makeTemporalRule("t-3",
		[]string{"failed_logon", "successful_logon", "lsass_access"},
		[]string{"user.name"}, 15*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Only first two steps — no alert.
	eval.Process(makeAlertForRule("failed_logon"), makeTemporalEvent(base, "admin"))
	alerts := eval.Process(makeAlertForRule("successful_logon"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert for partial sequence")
	}
}

func TestTemporalEvaluator_WindowExpiry(t *testing.T) {
	rule := makeTemporalRule("t-4",
		[]string{"failed_logon", "successful_logon", "lsass_access"},
		[]string{"user.name"}, 15*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Step 1 at t=0.
	eval.Process(makeAlertForRule("failed_logon"), makeTemporalEvent(base, "admin"))

	// Step 2 at t=3m (within window).
	eval.Process(makeAlertForRule("successful_logon"), makeTemporalEvent(base.Add(3*time.Minute), "admin"))

	// Step 3 at t=20m — outside 15m window → chain expired, no alert.
	alerts := eval.Process(makeAlertForRule("lsass_access"), makeTemporalEvent(base.Add(20*time.Minute), "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: sequence exceeded timespan window")
	}
}

func TestTemporalEvaluator_GroupByIsolation(t *testing.T) {
	rule := makeTemporalRule("t-5",
		[]string{"step_a", "step_b"},
		[]string{"user.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// alice step_a, bob step_b — different users, no sequence completion.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "alice"))
	alerts := eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(1*time.Minute), "bob"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert: different users are isolated")
	}

	// alice step_b — completes alice's sequence.
	alerts = eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(2*time.Minute), "alice"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for alice, got %d", len(alerts))
	}
}

func TestTemporalEvaluator_NilEvent(t *testing.T) {
	rule := makeTemporalRule("t-6", []string{"a", "b"}, []string{"user.name"}, 10*time.Minute)
	eval := NewTemporalEvaluator([]*CorrelationRule{rule})

	alerts := eval.Process(makeAlertForRule("a"), nil)
	if len(alerts) != 0 {
		t.Fatal("expected no alert for nil event")
	}
}

func TestTemporalEvaluator_UnrelatedRuleIgnored(t *testing.T) {
	rule := makeTemporalRule("t-7", []string{"a", "b"}, []string{"user.name"}, 10*time.Minute)
	eval := NewTemporalEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	alerts := eval.Process(makeAlertForRule("unrelated"), makeTemporalEvent(base, "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert for unrelated rule")
	}
}

func TestTemporalEvaluator_SkipsNonTemporalRules(t *testing.T) {
	ecRule := &CorrelationRule{
		ID:        "ec-1",
		Type:      CorrelationEventCount,
		Rules:     []string{"r1"},
		Timespan:  5 * time.Minute,
		Condition: OpGTE,
		Threshold: 3,
	}

	eval := NewTemporalEvaluator([]*CorrelationRule{ecRule})
	stats := eval.Stats()
	if len(stats) != 0 {
		t.Errorf("expected 0 temporal entries, got %d", len(stats))
	}
}

func TestTemporalEvaluator_TwoStepSequence(t *testing.T) {
	rule := makeTemporalRule("t-8", []string{"recon", "exploit"}, []string{"user.name"}, 30*time.Minute)
	eval := NewTemporalEvaluator([]*CorrelationRule{rule})

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlertForRule("recon"), makeTemporalEvent(base, "attacker"))
	alerts := eval.Process(makeAlertForRule("exploit"), makeTemporalEvent(base.Add(5*time.Minute), "attacker"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for 2-step sequence, got %d", len(alerts))
	}
}

func TestTemporalEvaluator_FourStepFullChain(t *testing.T) {
	// Simulates the full-chain detection from REQUIREMENTS.md:
	// NDR port scan → EDR credential dumping → NDR SMB lateral → NDR exfiltration
	rule := makeTemporalRule("full-chain",
		[]string{"ndr_portscan", "edr_credtheft", "ndr_smb_lateral", "ndr_exfil"},
		[]string{"user.name"}, 2*time.Hour)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlertForRule("ndr_portscan"), makeTemporalEvent(base, "attacker"))
	eval.Process(makeAlertForRule("edr_credtheft"), makeTemporalEvent(base.Add(15*time.Minute), "attacker"))
	eval.Process(makeAlertForRule("ndr_smb_lateral"), makeTemporalEvent(base.Add(45*time.Minute), "attacker"))
	alerts := eval.Process(makeAlertForRule("ndr_exfil"), makeTemporalEvent(base.Add(90*time.Minute), "attacker"))

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for 4-step full chain, got %d", len(alerts))
	}
	if alerts[0].RuleID != "full-chain" {
		t.Errorf("expected rule ID full-chain, got %s", alerts[0].RuleID)
	}
}

func TestTemporalEvaluator_FourStepFullChainExpired(t *testing.T) {
	rule := makeTemporalRule("full-chain-exp",
		[]string{"ndr_portscan", "edr_credtheft", "ndr_smb_lateral", "ndr_exfil"},
		[]string{"user.name"}, 2*time.Hour)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlertForRule("ndr_portscan"), makeTemporalEvent(base, "attacker"))
	eval.Process(makeAlertForRule("edr_credtheft"), makeTemporalEvent(base.Add(15*time.Minute), "attacker"))
	eval.Process(makeAlertForRule("ndr_smb_lateral"), makeTemporalEvent(base.Add(45*time.Minute), "attacker"))
	// Final step at 2h30m — outside 2h window.
	alerts := eval.Process(makeAlertForRule("ndr_exfil"), makeTemporalEvent(base.Add(150*time.Minute), "attacker"))

	if len(alerts) != 0 {
		t.Fatal("expected no alert: full chain exceeded 2h window")
	}
}

func TestTemporalEvaluator_ChainRestart(t *testing.T) {
	// If step 1 fires again while mid-chain, the old chain that's still valid
	// should continue (not be replaced).
	rule := makeTemporalRule("t-restart",
		[]string{"step_a", "step_b", "step_c"},
		[]string{"user.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Start chain.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "admin"))
	eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))

	// Another step_a fires — chain is mid-progress, should not restart
	// (the existing chain at step 2 is still within window).
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base.Add(2*time.Minute), "admin"))

	// Complete with step_c — should fire because step_b already matched.
	alerts := eval.Process(makeAlertForRule("step_c"), makeTemporalEvent(base.Add(3*time.Minute), "admin"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after restart attempt, got %d", len(alerts))
	}
}

func TestTemporalEvaluator_ChainResetAfterCompletion(t *testing.T) {
	rule := makeTemporalRule("t-reset",
		[]string{"step_a", "step_b"},
		[]string{"user.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Complete first sequence.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "admin"))
	alerts := eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// New sequence should be trackable after completion.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base.Add(2*time.Minute), "admin"))
	alerts = eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(3*time.Minute), "admin"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for 2nd sequence, got %d", len(alerts))
	}
}

func TestTemporalEvaluator_Stats(t *testing.T) {
	rule := makeTemporalRule("t-s1",
		[]string{"step_a", "step_b"},
		[]string{"user.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Start chains for two users.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "alice"))
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base.Add(1*time.Minute), "bob"))

	stats := eval.Stats()
	if stats["t-s1"] != 2 {
		t.Errorf("expected 2 active chains, got %d", stats["t-s1"])
	}
}

func TestTemporalEvaluator_ExpireState(t *testing.T) {
	rule := makeTemporalRule("t-e1",
		[]string{"step_a", "step_b"},
		[]string{"user.name"}, 5*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Start chains.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "alice"))
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base.Add(1*time.Minute), "bob"))

	expired := eval.ExpireState(base.Add(10 * time.Minute))
	if expired != 2 {
		t.Errorf("expected 2 expired chains, got %d", expired)
	}

	stats := eval.Stats()
	if stats["t-e1"] != 0 {
		t.Errorf("expected 0 active chains after expiry, got %d", stats["t-e1"])
	}
}

func TestTemporalEvaluator_MultipleGroupByFields(t *testing.T) {
	// Group by user.name + host.name — requires both to match.
	rule := makeTemporalRule("t-multi",
		[]string{"step_a", "step_b"},
		[]string{"user.name", "host.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Same user, different host — should NOT complete.
	eval.Process(makeAlertForRule("step_a"), &common.ECSEvent{
		Timestamp: base,
		User:      &common.UserFields{Name: "admin"},
		Host:      &common.HostFields{Name: "HOST-A"},
	})
	alerts := eval.Process(makeAlertForRule("step_b"), &common.ECSEvent{
		Timestamp: base.Add(1 * time.Minute),
		User:      &common.UserFields{Name: "admin"},
		Host:      &common.HostFields{Name: "HOST-B"},
	})
	if len(alerts) != 0 {
		t.Fatal("expected no alert: different host in group-by")
	}

	// Same user + same host — should complete.
	alerts = eval.Process(makeAlertForRule("step_b"), &common.ECSEvent{
		Timestamp: base.Add(2 * time.Minute),
		User:      &common.UserFields{Name: "admin"},
		Host:      &common.HostFields{Name: "HOST-A"},
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for matching group-by, got %d", len(alerts))
	}
}

func TestTemporalEvaluator_SkippedStepNoAlert(t *testing.T) {
	// Steps a→b→c: if step b is skipped, step c should NOT fire.
	rule := makeTemporalRule("t-skip",
		[]string{"step_a", "step_b", "step_c"},
		[]string{"user.name"}, 10*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "admin"))
	// Skip step_b, jump to step_c.
	alerts := eval.Process(makeAlertForRule("step_c"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))
	if len(alerts) != 0 {
		t.Fatal("expected no alert when step is skipped")
	}
}

func TestTemporalEvaluator_StaleChainRestart(t *testing.T) {
	rule := makeTemporalRule("t-stale",
		[]string{"step_a", "step_b", "step_c"},
		[]string{"user.name"}, 5*time.Minute)

	eval := NewTemporalEvaluator([]*CorrelationRule{rule})
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Start chain.
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base, "admin"))
	eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(1*time.Minute), "admin"))

	// 10 minutes later, step_a starts a new chain (old one is stale).
	eval.Process(makeAlertForRule("step_a"), makeTemporalEvent(base.Add(10*time.Minute), "admin"))
	eval.Process(makeAlertForRule("step_b"), makeTemporalEvent(base.Add(11*time.Minute), "admin"))
	alerts := eval.Process(makeAlertForRule("step_c"), makeTemporalEvent(base.Add(12*time.Minute), "admin"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for restarted chain, got %d", len(alerts))
	}
}

func TestBuildTemporalDescription_WithRuleDescription(t *testing.T) {
	rule := &CorrelationRule{
		Description: "Custom description",
		Rules:       []string{"a", "b"},
	}
	chain := &temporalChain{
		matchedEvents: []*common.ECSEvent{{}, {}},
	}

	desc := buildTemporalDescription(rule, chain)
	if desc != "Custom description" {
		t.Errorf("expected custom description, got %q", desc)
	}
}

func TestBuildTemporalDescription_Generated(t *testing.T) {
	rule := &CorrelationRule{
		Rules: []string{"step_a", "step_b"},
	}
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	chain := &temporalChain{
		matchedEvents: []*common.ECSEvent{
			{Timestamp: base},
			{Timestamp: base.Add(5 * time.Minute)},
		},
	}

	desc := buildTemporalDescription(rule, chain)
	if desc == "" {
		t.Fatal("expected non-empty generated description")
	}
	// Should contain the rule IDs and elapsed time.
	if !containsAll(desc, "step_a", "step_b", "5m0s") {
		t.Errorf("description missing expected content: %q", desc)
	}
}

// containsAll checks if s contains all substrings.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
