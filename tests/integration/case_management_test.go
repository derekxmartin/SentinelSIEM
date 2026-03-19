package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/cases"
	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// ── Mock backends ──────────────────────────────────────────────────────
// These implement the cases.Backend and cases.AlertBackend interfaces
// with in-memory storage, allowing the escalation pipeline to run
// without Elasticsearch.

type versionedEntry struct {
	data        []byte
	seqNo       int
	primaryTerm int
}

// mockCaseBackend implements cases.Backend.
type mockCaseBackend struct {
	mu   sync.Mutex
	docs map[string]versionedEntry
	seq  int
}

func newMockCaseBackend() *mockCaseBackend {
	return &mockCaseBackend{docs: make(map[string]versionedEntry)}
}

func (m *mockCaseBackend) IndexDoc(_ context.Context, _, id string, doc []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.docs[id] = versionedEntry{data: doc, seqNo: m.seq, primaryTerm: 1}
	return nil
}

func (m *mockCaseBackend) GetDocVersioned(_ context.Context, _, id string) (*store.VersionedDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.docs[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return &store.VersionedDoc{
		Source:      json.RawMessage(e.data),
		SeqNo:       e.seqNo,
		PrimaryTerm: e.primaryTerm,
	}, nil
}

func (m *mockCaseBackend) IndexDocIfMatch(_ context.Context, _, id string, doc []byte, seqNo, primaryTerm int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.docs[id]
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	if e.seqNo != seqNo || e.primaryTerm != primaryTerm {
		return fmt.Errorf("conflict: expected seq=%d term=%d, got seq=%d term=%d",
			e.seqNo, e.primaryTerm, seqNo, primaryTerm)
	}
	m.seq++
	m.docs[id] = versionedEntry{data: doc, seqNo: m.seq, primaryTerm: 1}
	return nil
}

func (m *mockCaseBackend) SearchRaw(_ context.Context, _ string, _ map[string]any) (*store.SearchRawResult, error) {
	return &store.SearchRawResult{Total: 0}, nil
}

// mockAlertBackend implements cases.AlertBackend.
type mockAlertBackend struct {
	mu      sync.Mutex
	docs    map[string]versionedEntry
	updates map[string]map[string]any
}

func newMockAlertBackend() *mockAlertBackend {
	return &mockAlertBackend{
		docs:    make(map[string]versionedEntry),
		updates: make(map[string]map[string]any),
	}
}

func (m *mockAlertBackend) addAlert(id string, event common.ECSEvent) {
	data, _ := json.Marshal(event)
	m.docs[id] = versionedEntry{data: data, seqNo: 1, primaryTerm: 1}
}

func (m *mockAlertBackend) GetDocVersioned(_ context.Context, _, id string) (*store.VersionedDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.docs[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return &store.VersionedDoc{
		Source:      json.RawMessage(e.data),
		SeqNo:       e.seqNo,
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
	return &store.SearchRawResult{Total: 0}, nil
}

// ── Helper: assert observable presence ─────────────────────────────────

func assertHasObservable(t *testing.T, obs []cases.Observable, typ, value string) {
	t.Helper()
	for _, o := range obs {
		if o.Type == typ && o.Value == value {
			return
		}
	}
	t.Errorf("missing observable: type=%q value=%q (have %d observables)", typ, value, len(obs))
}

func assertNoObservable(t *testing.T, obs []cases.Observable, typ, value string) {
	t.Helper()
	for _, o := range obs {
		if o.Type == typ && o.Value == value {
			t.Errorf("unexpected observable: type=%q value=%q", typ, value)
			return
		}
	}
}

// ── Tests ──────────────────────────────────────────────────────────────

// TestCaseEscalationFromCrossPortfolioAlerts validates the full pipeline:
//
//  1. Detection engine evaluates events from EDR, AV, DLP, and NDR
//  2. Alerts are generated and stored
//  3. Alerts are escalated to a case
//  4. Case contains observables from all four sources
//  5. NDR network metadata (Community IDs, JA3) appears in observables
//  6. Timeline shows escalation event
func TestCaseEscalationFromCrossPortfolioAlerts(t *testing.T) {
	// ── Step 1: Generate alerts from detection engine ───────────────
	rulesRoot := filepath.Join("..", "..", "rules")
	rules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))
	lsMap, err := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))
	if err != nil {
		t.Fatalf("loading logsource map: %v", err)
	}

	registry := correlate.NewRuleRegistry(rules)
	engine := correlate.NewRuleEngine(registry, lsMap)

	base := time.Date(2026, 3, 16, 14, 0, 0, 0, time.UTC)

	// Create events from 4 different sources, each with rich metadata.

	// EDR: process creation with attacker IP + process + parent process
	edrEvent := &common.ECSEvent{
		Timestamp:  base,
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Action:   "process_create",
		},
		Source:  &common.EndpointFields{IP: "10.1.2.45"},
		Host:   &common.HostFields{Name: "SRV-FINANCE-01"},
		User:   &common.UserFields{Name: "jsmith", Domain: "CORP"},
		Process: &common.ProcessFields{
			Name:        "payload.exe",
			CommandLine: "payload.exe -connect 185.220.101.45",
			Parent:      &common.ParentProcess{Name: "cmd.exe"},
		},
		File: &common.FileFields{
			Name: "payload.exe",
			Hash: &common.HashFields{
				SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				MD5:    "d41d8cd98f00b204e9800998ecf8427e",
			},
		},
	}

	// AV: malware detection with file hash + signature name
	avEvent := &common.ECSEvent{
		Timestamp:  base.Add(2 * time.Minute),
		SourceType: "akeso_av",
		Event: &common.EventFields{
			Kind:   "alert",
			Action: "realtime_block",
		},
		Host: &common.HostFields{Name: "SRV-FINANCE-01"},
		AV: &common.AVFields{
			Signature: &common.AVSignature{Name: "Trojan.GenericKD.48291"},
			Action:    "quarantine",
			Scan:      &common.AVScan{Result: "malicious"},
		},
		File: &common.FileFields{
			Name: "dropper.dll",
			Path: "C:\\Windows\\Temp\\dropper.dll",
			Hash: &common.HashFields{
				SHA256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			},
		},
	}

	// DLP: policy violation with user + classification
	dlpEvent := &common.ECSEvent{
		Timestamp:  base.Add(5 * time.Minute),
		SourceType: "akeso_dlp",
		Event: &common.EventFields{
			Kind:   "alert",
			Action: "policy_violation",
		},
		Host: &common.HostFields{Name: "SRV-FINANCE-01"},
		User: &common.UserFields{Name: "jsmith", Domain: "CORP"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "PCI-Compliance"},
			Classification: "confidential",
		},
		Destination: &common.EndpointFields{IP: "203.0.113.42", Domain: "exfil.badsite.com"},
	}

	// NDR: session with JA3, JA4, Community ID, SNI
	ndrEvent := &common.ECSEvent{
		Timestamp:  base.Add(8 * time.Minute),
		SourceType: "akeso_ndr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"network"},
			Action:   "smb_write",
		},
		Source:      &common.EndpointFields{IP: "10.1.2.45", Port: 49200},
		Destination: &common.EndpointFields{IP: "10.1.3.20", Port: 445},
		Host:        &common.HostFields{Name: "SRV-FINANCE-01"},
		Network: &common.NetworkFields{
			Protocol:    "tcp",
			CommunityID: "1:abc123def456+789/012=",
		},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{
				CommunityID: "1:ndr-session-community-id-001",
				Duration:    3600.5,
				BytesOrig:   512000,
			},
			Detection: &common.NDRDetection{
				Name:     "Lateral Tool Transfer",
				Category: "lateral_movement",
			},
		},
		TLS: &common.TLSFields{
			Version: "1.3",
			Client: &common.TLSClientFields{
				JA3:        "771,4866-4867-4865,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24,0",
				JA4:        "t13d1516h2_8daaf6152771_b186095e22b6",
				ServerName: "c2.malicious-domain.com",
			},
		},
	}

	// Evaluate events and collect alerts.
	allEvents := []*common.ECSEvent{edrEvent, avEvent, dlpEvent, ndrEvent}
	var allAlerts []correlate.Alert
	for _, ev := range allEvents {
		alerts := engine.Evaluate(ev)
		allAlerts = append(allAlerts, alerts...)
	}

	t.Logf("Detection engine produced %d alerts from 4 events", len(allAlerts))
	for _, a := range allAlerts {
		t.Logf("  alert: %s (%s) level=%s", a.Title, a.RuleID, a.Level)
	}

	if len(allAlerts) == 0 {
		t.Fatal("FAIL: detection engine produced 0 alerts — cannot test escalation")
	}

	// ── Step 2: Store alerts in mock backend ────────────────────────
	alertMock := newMockAlertBackend()

	// Build alert ECS events with Rule metadata (as the alert pipeline would).
	alertIDs := make([]string, 0, len(allAlerts))
	for i, alert := range allAlerts {
		alertID := fmt.Sprintf("alert-%03d", i+1)
		alertIDs = append(alertIDs, alertID)

		// Reconstruct the stored alert document: the original event enriched
		// with rule metadata (as the alert pipeline does).
		storedEvent := *alert.Event
		storedEvent.Rule = &common.RuleFields{
			ID:       alert.RuleID,
			Name:     alert.Title,
			Severity: alert.Level,
			Tags:     alert.Tags,
			Ruleset:  alert.Ruleset,
		}
		alertMock.addAlert(alertID, storedEvent)
	}

	// ── Step 3: Escalate to case ───────────────────────────────────
	caseMock := newMockCaseBackend()
	caseSvc := cases.NewService(caseMock, "test-cases")
	escSvc := cases.NewEscalationService(caseSvc, alertMock, "test-alerts-*")

	ctx := context.Background()
	result, err := escSvc.Escalate(ctx, &cases.EscalateRequest{
		AlertIDs: alertIDs,
		Assignee: "analyst1",
	}, "analyst1")
	if err != nil {
		t.Fatalf("Escalate failed: %v", err)
	}

	c := result.Case
	t.Logf("Case created: %s (severity=%s, alerts=%d, observables=%d)",
		c.Title, c.Severity, len(c.AlertIDs), len(c.Observables))

	// ── Step 4: Assert case properties ─────────────────────────────

	// Case should link all alerts.
	if result.AlertsLinked != len(allAlerts) {
		t.Errorf("expected %d alerts linked, got %d", len(allAlerts), result.AlertsLinked)
	}

	// Case should have auto-generated title from first alert.
	if c.Title == "" {
		t.Error("case title should not be empty")
	}

	// Case assignee.
	if c.Assignee != "analyst1" {
		t.Errorf("expected assignee analyst1, got %q", c.Assignee)
	}

	// ── Step 5: Assert observables from each source ────────────────

	obs := c.Observables
	t.Logf("Observables (%d total):", len(obs))
	for _, o := range obs {
		t.Logf("  %s: %s (source=%s)", o.Type, o.Value, o.Source)
	}

	// EDR observables: source IP, process, parent process, user, file hashes.
	assertHasObservable(t, obs, "ip", "10.1.2.45")
	assertHasObservable(t, obs, "process", "payload.exe")
	assertHasObservable(t, obs, "process", "cmd.exe")
	assertHasObservable(t, obs, "user", "jsmith")
	assertHasObservable(t, obs, "hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	assertHasObservable(t, obs, "hash", "d41d8cd98f00b204e9800998ecf8427e")

	// AV observables: different file hashes.
	assertHasObservable(t, obs, "hash", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	assertHasObservable(t, obs, "hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709")

	// DLP observables: destination IP, destination domain, user.
	assertHasObservable(t, obs, "ip", "203.0.113.42")
	assertHasObservable(t, obs, "domain", "exfil.badsite.com")

	// NDR observables: JA3, JA4, SNI, Community IDs, destination IP.
	assertHasObservable(t, obs, "ja3", "771,4866-4867-4865,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24,0")
	assertHasObservable(t, obs, "ja4", "t13d1516h2_8daaf6152771_b186095e22b6")
	assertHasObservable(t, obs, "sni", "c2.malicious-domain.com")
	assertHasObservable(t, obs, "community_id", "1:abc123def456+789/012=")
	assertHasObservable(t, obs, "community_id", "1:ndr-session-community-id-001")
	assertHasObservable(t, obs, "ip", "10.1.3.20")

	// ── Step 6: Assert timeline has escalation entry ───────────────
	if len(c.Timeline) == 0 {
		t.Fatal("case timeline should not be empty")
	}

	foundEscalation := false
	for _, entry := range c.Timeline {
		if entry.ActionType == "escalation" {
			foundEscalation = true
			if entry.Author != "analyst1" {
				t.Errorf("escalation author should be analyst1, got %q", entry.Author)
			}
		}
	}
	if !foundEscalation {
		t.Error("timeline should contain an escalation entry")
	}

	// ── Step 7: Assert alerts marked as escalated ──────────────────
	for _, alertID := range alertIDs {
		fields, ok := alertMock.updates[alertID]
		if !ok {
			t.Errorf("alert %s should have been marked as escalated", alertID)
			continue
		}
		eventFields, ok := fields["event"].(map[string]any)
		if !ok {
			t.Errorf("alert %s: expected event map in update fields", alertID)
			continue
		}
		if eventFields["outcome"] != "escalated" {
			t.Errorf("alert %s: expected outcome=escalated, got %v", alertID, eventFields["outcome"])
		}
	}

	t.Log("PASS: cross-portfolio alert escalation creates case with observables from all sources")
}

// TestCaseObservableDeduplication verifies that duplicate observables from
// overlapping alerts are deduplicated in the case.
func TestCaseObservableDeduplication(t *testing.T) {
	alertMock := newMockAlertBackend()
	caseMock := newMockCaseBackend()
	caseSvc := cases.NewService(caseMock, "test-cases")
	escSvc := cases.NewEscalationService(caseSvc, alertMock, "test-alerts-*")

	// Two alerts from different rules that share the same source IP and user.
	sharedIP := "10.1.2.45"
	sharedUser := "jsmith"

	alertMock.addAlert("alert-dup-1", common.ECSEvent{
		Event: &common.EventFields{Kind: "alert"},
		Rule:  &common.RuleFields{Name: "Rule A", Severity: "high"},
		Source: &common.EndpointFields{IP: sharedIP},
		User:   &common.UserFields{Name: sharedUser},
	})
	alertMock.addAlert("alert-dup-2", common.ECSEvent{
		Event: &common.EventFields{Kind: "alert"},
		Rule:  &common.RuleFields{Name: "Rule B", Severity: "critical"},
		Source: &common.EndpointFields{IP: sharedIP},
		User:   &common.UserFields{Name: sharedUser},
	})

	ctx := context.Background()
	result, err := escSvc.Escalate(ctx, &cases.EscalateRequest{
		AlertIDs: []string{"alert-dup-1", "alert-dup-2"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Escalate failed: %v", err)
	}

	// Count occurrences of the shared IP.
	ipCount := 0
	userCount := 0
	for _, o := range result.Case.Observables {
		if o.Type == "ip" && o.Value == sharedIP {
			ipCount++
		}
		if o.Type == "user" && o.Value == sharedUser {
			userCount++
		}
	}

	if ipCount != 1 {
		t.Errorf("expected IP %s to appear once (deduplicated), got %d", sharedIP, ipCount)
	}
	if userCount != 1 {
		t.Errorf("expected user %s to appear once (deduplicated), got %d", sharedUser, userCount)
	}

	// Highest severity should win.
	if result.Case.Severity != "critical" {
		t.Errorf("expected severity critical (highest from two alerts), got %s", result.Case.Severity)
	}

	t.Log("PASS: observable deduplication works across multiple alerts")
}

// TestCaseMergeAdditionalAlerts verifies that alerts can be merged into an
// existing case, adding new observables without duplicates.
func TestCaseMergeAdditionalAlerts(t *testing.T) {
	alertMock := newMockAlertBackend()
	caseMock := newMockCaseBackend()
	caseSvc := cases.NewService(caseMock, "test-cases")
	escSvc := cases.NewEscalationService(caseSvc, alertMock, "test-alerts-*")

	// Initial alert: EDR with process info.
	alertMock.addAlert("alert-init", common.ECSEvent{
		Event:   &common.EventFields{Kind: "alert"},
		Rule:    &common.RuleFields{Name: "Initial Detection", Severity: "medium", Tags: []string{"attack.execution"}},
		Source:  &common.EndpointFields{IP: "10.1.2.45"},
		Process: &common.ProcessFields{Name: "suspicious.exe"},
	})

	ctx := context.Background()
	result, err := escSvc.Escalate(ctx, &cases.EscalateRequest{
		AlertIDs: []string{"alert-init"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Initial escalate failed: %v", err)
	}

	caseID := result.Case.ID
	initialObsCount := len(result.Case.Observables)
	t.Logf("Initial case: %d observables", initialObsCount)

	// New alert with NDR metadata to merge in.
	alertMock.addAlert("alert-ndr", common.ECSEvent{
		Event: &common.EventFields{Kind: "alert"},
		Rule: &common.RuleFields{
			Name:     "NDR C2 Beacon",
			Severity: "critical",
			Tags:     []string{"attack.command_and_control"},
		},
		Source:      &common.EndpointFields{IP: "10.1.2.45"}, // same IP (should dedup)
		Destination: &common.EndpointFields{IP: "185.220.101.45"},
		Network:     &common.NetworkFields{CommunityID: "1:merge-test-community-id"},
		TLS: &common.TLSFields{
			Client: &common.TLSClientFields{
				JA3:        "merge-ja3-fingerprint",
				ServerName: "c2.evil.com",
			},
		},
	})

	// Merge into existing case.
	updatedCase, err := escSvc.EscalateToExisting(ctx, caseID, []string{"alert-ndr"}, "analyst2")
	if err != nil {
		t.Fatalf("EscalateToExisting failed: %v", err)
	}

	t.Logf("After merge: %d observables (was %d)", len(updatedCase.Observables), initialObsCount)

	// Verify new observables were added.
	assertHasObservable(t, updatedCase.Observables, "ip", "185.220.101.45")
	assertHasObservable(t, updatedCase.Observables, "community_id", "1:merge-test-community-id")
	assertHasObservable(t, updatedCase.Observables, "ja3", "merge-ja3-fingerprint")
	assertHasObservable(t, updatedCase.Observables, "sni", "c2.evil.com")

	// Verify shared IP was deduplicated.
	ipCount := 0
	for _, o := range updatedCase.Observables {
		if o.Type == "ip" && o.Value == "10.1.2.45" {
			ipCount++
		}
	}
	if ipCount != 1 {
		t.Errorf("shared IP should appear once after merge, got %d", ipCount)
	}

	// Verify both alert IDs are linked.
	if len(updatedCase.AlertIDs) != 2 {
		t.Errorf("expected 2 linked alerts, got %d", len(updatedCase.AlertIDs))
	}

	// Verify tags merged.
	hasExecution := false
	hasC2 := false
	for _, tag := range updatedCase.Tags {
		if tag == "attack.execution" {
			hasExecution = true
		}
		if tag == "attack.command_and_control" {
			hasC2 = true
		}
	}
	if !hasExecution || !hasC2 {
		t.Errorf("expected tags from both alerts, got %v", updatedCase.Tags)
	}

	// Verify timeline has merge entry.
	foundMerge := false
	for _, entry := range updatedCase.Timeline {
		if entry.ActionType == "alert_merged" {
			foundMerge = true
			if entry.Author != "analyst2" {
				t.Errorf("merge author should be analyst2, got %q", entry.Author)
			}
		}
	}
	if !foundMerge {
		t.Error("timeline should contain an alert_merged entry")
	}

	t.Log("PASS: alert merge adds new observables and deduplicates existing ones")
}
