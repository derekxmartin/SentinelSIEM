package cases

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// mockAlertBackend implements AlertBackend for testing.
type mockAlertBackend struct {
	mu     sync.Mutex
	docs   map[string]versionedEntry // key = id (index ignored for simplicity)
	updates map[string]map[string]any // alertID → merged fields
}

func newMockAlertBackend() *mockAlertBackend {
	return &mockAlertBackend{
		docs:    make(map[string]versionedEntry),
		updates: make(map[string]map[string]any),
	}
}

func (m *mockAlertBackend) addAlert(id string, event common.ECSEvent) {
	data, _ := json.Marshal(event)
	m.docs[id] = versionedEntry{
		data:        data,
		seqNo:       1,
		primaryTerm: 1,
	}
}

func (m *mockAlertBackend) GetDocVersioned(_ context.Context, _, id string) (*store.VersionedDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.docs[id]
	if !ok {
		return nil, fmt.Errorf("document not found: %s", id)
	}
	return &store.VersionedDoc{
		Source:      json.RawMessage(e.data),
		SeqNo:      e.seqNo,
		PrimaryTerm: e.primaryTerm,
	}, nil
}

func (m *mockAlertBackend) UpdateFields(_ context.Context, _, id string, fields map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates[id] = fields
	return nil
}

func (m *mockAlertBackend) SearchRaw(_ context.Context, _ string, _ map[string]any) (*store.SearchRawResult, error) {
	return &store.SearchRawResult{Total: 0, Hits: nil}, nil
}

func newTestEscalationService() (*EscalationService, *mockBackend, *mockAlertBackend) {
	caseMock := newMockBackend()
	caseSvc := NewService(caseMock, "test-cases")
	alertMock := newMockAlertBackend()
	escSvc := NewEscalationService(caseSvc, alertMock, "test-alerts-*")
	return escSvc, caseMock, alertMock
}

func TestEscalateSingleAlert(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	// Add a high-severity network alert.
	alertMock.addAlert("alert-001", common.ECSEvent{
		Event: &common.EventFields{Kind: "alert", Severity: 4},
		Rule: &common.RuleFields{
			Name:     "Suspicious Lateral Movement",
			Severity: "high",
			Tags:     []string{"attack.lateral_movement", "attack.t1021"},
		},
		Source:      &common.EndpointFields{IP: "192.168.1.100"},
		Destination: &common.EndpointFields{IP: "10.0.0.50"},
		User:        &common.UserFields{Name: "jsmith"},
	})

	result, err := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Escalate failed: %v", err)
	}

	if result.AlertsLinked != 1 {
		t.Errorf("expected 1 alert linked, got %d", result.AlertsLinked)
	}

	c := result.Case
	if c.Title != "Suspicious Lateral Movement" {
		t.Errorf("expected auto-generated title, got %q", c.Title)
	}
	if c.Severity != SeverityHigh {
		t.Errorf("expected severity %q, got %q", SeverityHigh, c.Severity)
	}
	if len(c.AlertIDs) != 1 || c.AlertIDs[0] != "alert-001" {
		t.Errorf("expected alert-001 linked, got %v", c.AlertIDs)
	}

	// Check observables extracted.
	assertHasObservable(t, c.Observables, ObservableIP, "192.168.1.100")
	assertHasObservable(t, c.Observables, ObservableIP, "10.0.0.50")
	assertHasObservable(t, c.Observables, ObservableUser, "jsmith")

	// Check tags.
	if len(c.Tags) != 2 {
		t.Errorf("expected 2 MITRE tags, got %d: %v", len(c.Tags), c.Tags)
	}

	// Check alert was marked as escalated.
	if _, ok := alertMock.updates["alert-001"]; !ok {
		t.Error("expected alert-001 to be marked as escalated")
	}
}

func TestEscalateBulkAlerts(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	// Add 5 alerts with varying severity.
	alertMock.addAlert("alert-001", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Credential Theft", Severity: "critical", Tags: []string{"attack.t1003"}},
		Source: &common.EndpointFields{IP: "192.168.1.100"},
		User:   &common.UserFields{Name: "admin"},
	})
	alertMock.addAlert("alert-002", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Lateral Movement", Severity: "high", Tags: []string{"attack.t1021"}},
		Source: &common.EndpointFields{IP: "192.168.1.100"}, // dup IP
		Destination: &common.EndpointFields{IP: "10.0.0.50"},
	})
	alertMock.addAlert("alert-003", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Data Exfil", Severity: "medium", Tags: []string{"attack.t1048"}},
		Destination: &common.EndpointFields{IP: "8.8.8.8"},
	})
	alertMock.addAlert("alert-004", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Persistence", Severity: "high", Tags: []string{"attack.t1003"}}, // dup tag
		Process: &common.ProcessFields{Name: "schtasks.exe"},
	})
	alertMock.addAlert("alert-005", common.ECSEvent{
		Rule: &common.RuleFields{Name: "C2 Beacon", Severity: "high"},
		TLS: &common.TLSFields{
			Client: &common.TLSClientFields{JA3: "ja3hash", ServerName: "c2.evil.com"},
		},
	})

	result, err := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001", "alert-002", "alert-003", "alert-004", "alert-005"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Escalate failed: %v", err)
	}

	if result.AlertsLinked != 5 {
		t.Errorf("expected 5 alerts linked, got %d", result.AlertsLinked)
	}

	c := result.Case

	// Title from first alert with count.
	if c.Title != "Credential Theft (+4 related alerts)" {
		t.Errorf("expected bulk title, got %q", c.Title)
	}

	// Highest severity should be critical.
	if c.Severity != SeverityCritical {
		t.Errorf("expected severity %q, got %q", SeverityCritical, c.Severity)
	}

	// All 5 alert IDs linked.
	if len(c.AlertIDs) != 5 {
		t.Errorf("expected 5 alert IDs, got %d", len(c.AlertIDs))
	}

	// Observables should be deduplicated (192.168.1.100 appears in alert-001 and alert-002).
	ipCount := 0
	for _, o := range c.Observables {
		if o.Type == ObservableIP && o.Value == "192.168.1.100" {
			ipCount++
		}
	}
	if ipCount != 1 {
		t.Errorf("expected 192.168.1.100 to appear once (deduped), got %d", ipCount)
	}

	// Tags should be deduplicated (attack.t1003 in alert-001 and alert-004).
	tagCount := 0
	for _, tag := range c.Tags {
		if tag == "attack.t1003" {
			tagCount++
		}
	}
	if tagCount != 1 {
		t.Errorf("expected attack.t1003 once (deduped), got %d", tagCount)
	}

	// All 5 alerts should be marked as escalated.
	for _, id := range []string{"alert-001", "alert-002", "alert-003", "alert-004", "alert-005"} {
		if _, ok := alertMock.updates[id]; !ok {
			t.Errorf("expected %s to be marked as escalated", id)
		}
	}
}

func TestEscalateNoAlerts(t *testing.T) {
	escSvc, _, _ := newTestEscalationService()
	ctx := context.Background()

	_, err := escSvc.Escalate(ctx, &EscalateRequest{AlertIDs: []string{}}, "analyst1")
	if err == nil {
		t.Fatal("expected error for empty alert IDs")
	}
}

func TestEscalateInvalidAlertID(t *testing.T) {
	escSvc, _, _ := newTestEscalationService()
	ctx := context.Background()

	_, err := escSvc.Escalate(ctx, &EscalateRequest{AlertIDs: []string{"nonexistent"}}, "analyst1")
	if err == nil {
		t.Fatal("expected error for nonexistent alert")
	}
}

func TestEscalateCustomTitle(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	alertMock.addAlert("alert-001", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Auto Title", Severity: "low"},
	})

	result, err := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001"},
		Title:    "Custom Investigation Title",
	}, "analyst1")
	if err != nil {
		t.Fatalf("Escalate failed: %v", err)
	}

	if result.Case.Title != "Custom Investigation Title" {
		t.Errorf("expected custom title, got %q", result.Case.Title)
	}
}

func TestEscalateToExistingCase(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	// Create initial case with one alert.
	alertMock.addAlert("alert-001", common.ECSEvent{
		Rule:   &common.RuleFields{Name: "Initial Alert", Severity: "high"},
		Source: &common.EndpointFields{IP: "192.168.1.1"},
	})

	result, err := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Initial escalate failed: %v", err)
	}

	caseID := result.Case.ID

	// Add more alerts to merge.
	alertMock.addAlert("alert-002", common.ECSEvent{
		Rule:        &common.RuleFields{Name: "Follow-up", Severity: "medium", Tags: []string{"attack.t1059"}},
		Destination: &common.EndpointFields{IP: "10.0.0.99"},
	})
	alertMock.addAlert("alert-003", common.ECSEvent{
		Rule:    &common.RuleFields{Name: "Related", Severity: "low"},
		Process: &common.ProcessFields{Name: "powershell.exe"},
	})

	updated, err := escSvc.EscalateToExisting(ctx, caseID, []string{"alert-002", "alert-003"}, "analyst1")
	if err != nil {
		t.Fatalf("EscalateToExisting failed: %v", err)
	}

	// Should now have 3 alert IDs.
	if len(updated.AlertIDs) != 3 {
		t.Errorf("expected 3 alert IDs, got %d", len(updated.AlertIDs))
	}

	// New observables merged.
	assertHasObservable(t, updated.Observables, ObservableIP, "10.0.0.99")
	assertHasObservable(t, updated.Observables, ObservableProcess, "powershell.exe")

	// Timeline should have merge entry.
	found := false
	for _, entry := range updated.Timeline {
		if entry.ActionType == ActionAlertMerged {
			found = true
		}
	}
	if !found {
		t.Error("expected alert_merged timeline entry")
	}
}

func TestEscalateToExistingSkipsDuplicates(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	alertMock.addAlert("alert-001", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Test", Severity: "low"},
	})

	result, _ := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001"},
	}, "analyst1")

	// Try to merge the same alert again.
	updated, err := escSvc.EscalateToExisting(ctx, result.Case.ID, []string{"alert-001"}, "analyst1")
	if err != nil {
		t.Fatalf("EscalateToExisting failed: %v", err)
	}

	// Should still have only 1 alert ID (no duplicate).
	if len(updated.AlertIDs) != 1 {
		t.Errorf("expected 1 alert ID (no dup), got %d", len(updated.AlertIDs))
	}
}

func TestMapRuleSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"informational", SeverityLow},
		{"", SeverityLow},
	}
	for _, tc := range tests {
		got := mapRuleSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("mapRuleSeverity(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestAlertMarkedEscalated(t *testing.T) {
	escSvc, _, alertMock := newTestEscalationService()
	ctx := context.Background()

	alertMock.addAlert("alert-001", common.ECSEvent{
		Rule: &common.RuleFields{Name: "Test", Severity: "high"},
	})

	result, _ := escSvc.Escalate(ctx, &EscalateRequest{
		AlertIDs: []string{"alert-001"},
	}, "analyst1")

	update, ok := alertMock.updates["alert-001"]
	if !ok {
		t.Fatal("alert-001 should have been updated")
	}

	eventFields, ok := update["event"].(map[string]any)
	if !ok {
		t.Fatal("expected event field in update")
	}
	if eventFields["outcome"] != "escalated" {
		t.Errorf("expected outcome 'escalated', got %v", eventFields["outcome"])
	}

	caseID, ok := update["case_id"].(string)
	if !ok || caseID != result.Case.ID {
		t.Errorf("expected case_id %q, got %v", result.Case.ID, update["case_id"])
	}
}
