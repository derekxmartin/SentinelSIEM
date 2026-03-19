package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
	"github.com/derekxmartin/akeso-siem/internal/normalize"
)

// mockIndexer captures BulkIndex calls for verification.
type mockIndexer struct {
	mu      sync.Mutex
	calls   []bulkIndexCall
	failErr error // if set, BulkIndex returns this error
}

type bulkIndexCall struct {
	Index  string
	Events []common.ECSEvent
}

func (m *mockIndexer) BulkIndex(_ context.Context, index string, events []common.ECSEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, bulkIndexCall{Index: index, Events: events})
	return m.failErr
}

func (m *mockIndexer) totalEvents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, c := range m.calls {
		total += len(c.Events)
	}
	return total
}

func (m *mockIndexer) indexNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for _, c := range m.calls {
		names = append(names, c.Index)
	}
	return names
}

func (m *mockIndexer) alertCalls() []bulkIndexCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []bulkIndexCall
	for _, c := range m.calls {
		if strings.Contains(c.Index, "-alerts-") {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockIndexer) eventCalls() []bulkIndexCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []bulkIndexCall
	for _, c := range m.calls {
		if strings.Contains(c.Index, "-events-") {
			result = append(result, c)
		}
	}
	return result
}

// testParser returns a fixed ECSEvent for testing.
type testParser struct {
	sourceType string
}

func (p *testParser) SourceType() string { return p.sourceType }

func (p *testParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			PID:  1234,
			Name: "test.exe",
		},
	}, nil
}

// makeTestEvent creates a minimal SIEM-envelope event for pipeline testing.
func makeTestEvent(sourceType string) json.RawMessage {
	event := map[string]any{
		"source_type": sourceType,
		"timestamp":   "2026-03-14T12:00:00Z",
		"event": map[string]any{
			"eventId":   "test-id",
			"timestamp": "2026-03-14T12:00:00Z",
			"source":    "DriverProcess",
			"severity":  "Low",
			"process": map[string]any{
				"pid":       1234,
				"imagePath": `C:\test.exe`,
			},
			"payload": map[string]any{
				"isCreate": true,
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func TestPipelineNormalizeAndIndex(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	// Send 5 events.
	events := make([]json.RawMessage, 5)
	for i := range events {
		events[i] = makeTestEvent("akeso_edr")
	}

	pipeline.Handle(events)

	if indexer.totalEvents() != 5 {
		t.Errorf("total indexed events = %d, want 5", indexer.totalEvents())
	}
}

func TestPipelineIndexNaming(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("akeso_edr")})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	// Index should match pattern: akeso-events-akeso_edr-YYYY.MM.dd
	expected := "akeso-events-akeso_edr-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineUnknownSourceType(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	raw := json.RawMessage(`{"source_type":"futuretype","data":"test"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "akeso-events-futuretype-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineMissingSourceType(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	raw := json.RawMessage(`{"data":"no source type"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "akeso-events-unknown-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineMixedValidInvalid(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	events := []json.RawMessage{
		makeTestEvent("akeso_edr"),
		json.RawMessage(`{broken json`),
		makeTestEvent("akeso_edr"),
		json.RawMessage(`{also broken`),
		makeTestEvent("akeso_edr"),
	}

	pipeline.Handle(events)

	// 3 valid events should be indexed, 2 malformed skipped.
	if indexer.totalEvents() != 3 {
		t.Errorf("total indexed events = %d, want 3", indexer.totalEvents())
	}
}

func TestPipelineMultipleSourceTypes(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	reg.Register(&testParser{sourceType: "akeso_av"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	events := []json.RawMessage{
		makeTestEvent("akeso_edr"),
		makeTestEvent("akeso_edr"),
		makeTestEvent("akeso_av"),
	}

	pipeline.Handle(events)

	// Should create 2 index groups.
	names := indexer.indexNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 index groups, got %d: %v", len(names), names)
	}

	// Verify event counts per group.
	indexer.mu.Lock()
	defer indexer.mu.Unlock()
	for _, call := range indexer.calls {
		if contains(call.Index, "akeso_edr") && len(call.Events) != 2 {
			t.Errorf("akeso_edr group: got %d events, want 2", len(call.Events))
		}
		if contains(call.Index, "akeso_av") && len(call.Events) != 1 {
			t.Errorf("akeso_av group: got %d events, want 1", len(call.Events))
		}
	}
}

func TestPipelineEmptyBatch(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	// Should not panic or call indexer.
	pipeline.Handle(nil)
	pipeline.Handle([]json.RawMessage{})

	if indexer.totalEvents() != 0 {
		t.Errorf("expected 0 indexed events, got %d", indexer.totalEvents())
	}
}

func TestPipelineDefaultPrefix(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "", nil, nil, nil)

	raw := json.RawMessage(`{"source_type":"test","data":"x"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "akeso-events-test-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineCustomPrefix(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "myorg", nil, nil, nil)

	raw := json.RawMessage(`{"source_type":"test","data":"x"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "myorg-events-test-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

// --- Host score upsert tests ---

// mockHostScoreIndexer captures UpsertHostScore calls.
type mockHostScoreIndexer struct {
	mu      sync.Mutex
	calls   []*common.ECSEvent
	failErr error
}

func (m *mockHostScoreIndexer) UpsertHostScore(_ context.Context, event *common.ECSEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, event)
	return m.failErr
}

func (m *mockHostScoreIndexer) upsertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// hostScoreParser returns an NDR host_score event.
type hostScoreParser struct{}

func (p *hostScoreParser) SourceType() string { return "akeso_ndr" }

func (p *hostScoreParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"host"},
			Type:     []string{"info"},
			Action:   "host_score_update",
		},
		Host: &common.HostFields{
			Name: "HOST-A",
			IP:   []string{"10.0.0.1"},
		},
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{
				Threat:    85,
				Certainty: 90,
				Quadrant:  "high_high",
			},
		},
	}, nil
}

func TestPipelineHostScoreUpsert(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", hsIndexer, nil, nil)

	events := []json.RawMessage{
		makeTestNDRHostScoreEvent(),
	}
	pipeline.Handle(events)

	// Event should be indexed in normal time-series index.
	if indexer.totalEvents() != 1 {
		t.Errorf("indexed events = %d, want 1", indexer.totalEvents())
	}

	// Event should also be upserted to host score index.
	if hsIndexer.upsertCount() != 1 {
		t.Errorf("host score upserts = %d, want 1", hsIndexer.upsertCount())
	}
}

func TestPipelineHostScoreNotUpsertedForNonHostScore(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", hsIndexer, nil, nil)

	events := []json.RawMessage{makeTestEvent("akeso_edr")}
	pipeline.Handle(events)

	// Regular events should NOT trigger host score upsert.
	if hsIndexer.upsertCount() != 0 {
		t.Errorf("host score upserts = %d, want 0", hsIndexer.upsertCount())
	}
}

func TestPipelineHostScoreNilIndexer(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	// nil host score indexer — should not panic.
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	events := []json.RawMessage{makeTestNDRHostScoreEvent()}
	pipeline.Handle(events) // Should not panic.

	if indexer.totalEvents() != 1 {
		t.Errorf("indexed events = %d, want 1", indexer.totalEvents())
	}
}

func TestPipelineMultipleHostScoreEvents(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", hsIndexer, nil, nil)

	events := []json.RawMessage{
		makeTestNDRHostScoreEvent(),
		makeTestNDRHostScoreEvent(),
		makeTestNDRHostScoreEvent(),
	}
	pipeline.Handle(events)

	if hsIndexer.upsertCount() != 3 {
		t.Errorf("host score upserts = %d, want 3", hsIndexer.upsertCount())
	}
}

func TestIsHostScoreEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    *common.ECSEvent
		expected bool
	}{
		{"nil event", nil, false},
		{"empty event", &common.ECSEvent{}, false},
		{"no event fields", &common.ECSEvent{NDR: &common.NDRFields{HostScore: &common.NDRHostScore{}}}, false},
		{"wrong action", &common.ECSEvent{
			Event: &common.EventFields{Action: "session"},
			NDR:   &common.NDRFields{HostScore: &common.NDRHostScore{}},
		}, false},
		{"correct host_score", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
			NDR:   &common.NDRFields{HostScore: &common.NDRHostScore{Threat: 50}},
		}, true},
		{"missing NDR", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
		}, false},
		{"missing HostScore", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
			NDR:   &common.NDRFields{},
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHostScoreEvent(tc.event); got != tc.expected {
				t.Errorf("isHostScoreEvent() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func makeTestNDRHostScoreEvent() json.RawMessage {
	event := map[string]any{
		"source_type": "akeso_ndr",
		"timestamp":   "2026-03-15T10:00:00Z",
		"event_type":  "ndr:host_score",
	}
	data, _ := json.Marshal(event)
	return data
}

// --- Rule engine integration tests ---

// buildTestRuleEngine creates a minimal rule engine with a single rule that
// matches process_creation events where process.name == "malware.exe".
func buildTestRuleEngine() *correlate.RuleEngine {
	rules := []*correlate.SigmaRule{
		{
			ID:    "test-rule-001",
			Title: "Suspicious Process",
			Level: "high",
			Tags:  []string{"attack.execution"},
			Logsource: correlate.SigmaLogsource{
				Category: "process_creation",
			},
			Detection: &correlate.SigmaDetection{
				Selections: map[string]correlate.SigmaSelection{
					"selection": {
						{
							FieldMatchers: []correlate.SigmaFieldMatcher{
								{
									Field:  "process.name",
									Values: []interface{}{"malware.exe"},
								},
							},
						},
					},
				},
				Condition: "selection",
			},
		},
	}

	registry := correlate.NewRuleRegistry(rules)

	lsMap, _ := correlate.ParseLogsourceMap([]byte(`
mappings:
  - logsource:
      category: process_creation
    conditions:
      event.category: process
      event.type: start
`))

	return correlate.NewRuleEngine(registry, lsMap)
}

// matchingParser returns an event that will match the test rule.
type matchingParser struct{}

func (p *matchingParser) SourceType() string { return "akeso_edr" }

func (p *matchingParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "process_create",
		},
		Process: &common.ProcessFields{
			PID:  666,
			Name: "malware.exe",
		},
	}, nil
}

// nonMatchingParser returns an event that will NOT match the test rule.
type nonMatchingParser struct{}

func (p *nonMatchingParser) SourceType() string { return "akeso_edr" }

func (p *nonMatchingParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "process_create",
		},
		Process: &common.ProcessFields{
			PID:  1234,
			Name: "notepad.exe",
		},
	}, nil
}

func TestPipelineRuleEngineMatchGeneratesAlert(t *testing.T) {
	ruleEngine := buildTestRuleEngine()
	reg := normalize.NewRegistry()
	reg.Register(&matchingParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, ruleEngine, nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("akeso_edr")})

	// Should have event index + alert index calls.
	alertCalls := indexer.alertCalls()
	if len(alertCalls) == 0 {
		t.Fatal("expected alert index calls, got none")
	}

	// Verify alert was indexed to correct index pattern.
	for _, call := range alertCalls {
		if !strings.HasPrefix(call.Index, "akeso-alerts-") {
			t.Errorf("alert index = %q, want prefix 'akeso-alerts-'", call.Index)
		}
	}

	// Verify alert document fields.
	alertDoc := alertCalls[0].Events[0]
	if alertDoc.Event == nil {
		t.Fatal("alert event fields are nil")
	}
	if alertDoc.Event.Kind != "alert" {
		t.Errorf("alert kind = %q, want 'alert'", alertDoc.Event.Kind)
	}
	if alertDoc.Event.Action != "sigma_match" {
		t.Errorf("alert action = %q, want 'sigma_match'", alertDoc.Event.Action)
	}
	if alertDoc.SourceType != "sigma_alert" {
		t.Errorf("alert source_type = %q, want 'sigma_alert'", alertDoc.SourceType)
	}
	if alertDoc.Rule == nil {
		t.Fatal("alert rule fields are nil")
	}
	if alertDoc.Rule.Name != "Suspicious Process" {
		t.Errorf("alert rule.name = %q, want 'Suspicious Process'", alertDoc.Rule.Name)
	}
	if alertDoc.Rule.ID != "test-rule-001" {
		t.Errorf("alert rule.id = %q, want 'test-rule-001'", alertDoc.Rule.ID)
	}
	if alertDoc.Rule.Severity != "high" {
		t.Errorf("alert rule.severity = %q, want 'high'", alertDoc.Rule.Severity)
	}
	if alertDoc.Rule.Ruleset != "sigma_single" {
		t.Errorf("alert rule.ruleset = %q, want 'sigma_single'", alertDoc.Rule.Ruleset)
	}
	if alertDoc.Rule.Category != "sigma" {
		t.Errorf("alert rule.category = %q, want 'sigma'", alertDoc.Rule.Category)
	}
}

func TestPipelineRuleEngineNoMatchNoAlert(t *testing.T) {
	ruleEngine := buildTestRuleEngine()
	reg := normalize.NewRegistry()
	reg.Register(&nonMatchingParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, ruleEngine, nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("akeso_edr")})

	// Events should still be indexed.
	eventCalls := indexer.eventCalls()
	if len(eventCalls) == 0 {
		t.Fatal("expected event index calls")
	}

	// But NO alerts should be created.
	alertCalls := indexer.alertCalls()
	if len(alertCalls) != 0 {
		t.Errorf("expected 0 alert calls, got %d", len(alertCalls))
	}
}

func TestPipelineNilRuleEngineNoAlerts(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "akeso_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	// nil rule engine — should not panic or generate alerts.
	pipeline := NewPipeline(engine, indexer, "akeso", nil, nil, nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("akeso_edr")})

	alertCalls := indexer.alertCalls()
	if len(alertCalls) != 0 {
		t.Errorf("expected 0 alert calls with nil rule engine, got %d", len(alertCalls))
	}
}

func TestPipelineMultipleMatchingEvents(t *testing.T) {
	ruleEngine := buildTestRuleEngine()
	reg := normalize.NewRegistry()
	reg.Register(&matchingParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, ruleEngine, nil)

	events := []json.RawMessage{
		makeTestEvent("akeso_edr"),
		makeTestEvent("akeso_edr"),
		makeTestEvent("akeso_edr"),
	}
	pipeline.Handle(events)

	// Should generate 3 alerts.
	totalAlerts := 0
	for _, call := range indexer.alertCalls() {
		totalAlerts += len(call.Events)
	}
	if totalAlerts != 3 {
		t.Errorf("expected 3 alerts, got %d", totalAlerts)
	}
}

func TestPipelineMixedMatchAndNonMatch(t *testing.T) {
	ruleEngine := buildTestRuleEngine()

	// Use a custom parser that alternates between matching and non-matching events.
	reg := normalize.NewRegistry()
	reg.Register(&mixedParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "akeso", nil, ruleEngine, nil)

	events := []json.RawMessage{
		makeTestEvent("akeso_edr"),
		makeTestEvent("akeso_edr"),
	}
	pipeline.Handle(events)

	// mixedParser alternates: first call → malware.exe (match), second → notepad.exe (no match).
	totalAlerts := 0
	for _, call := range indexer.alertCalls() {
		totalAlerts += len(call.Events)
	}
	if totalAlerts != 1 {
		t.Errorf("expected 1 alert (1 match, 1 non-match), got %d", totalAlerts)
	}
}

// mixedParser alternates between matching and non-matching events.
type mixedParser struct {
	mu    sync.Mutex
	count int
}

func (p *mixedParser) SourceType() string { return "akeso_edr" }

func (p *mixedParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	p.mu.Lock()
	c := p.count
	p.count++
	p.mu.Unlock()

	processName := "notepad.exe"
	if c%2 == 0 {
		processName = "malware.exe"
	}
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			PID:  1234,
			Name: processName,
		},
	}, nil
}

func TestPipelineAlertSeverityLevels(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"informational", 1},
		{"low", 2},
		{"medium", 3},
		{"high", 4},
		{"critical", 5},
		{"unknown", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			got := levelToSeverity(tc.level)
			if got != tc.expected {
				t.Errorf("levelToSeverity(%q) = %d, want %d", tc.level, got, tc.expected)
			}
		})
	}
}

func TestAlertToDocument(t *testing.T) {
	event := &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			PID:  666,
			Name: "malware.exe",
		},
	}

	alert := correlate.Alert{
		RuleID:      "rule-123",
		Title:       "Test Alert",
		Level:       "high",
		Tags:        []string{"attack.execution", "attack.t1059"},
		Description: "Detects suspicious process",
		Author:      "test-author",
		Ruleset:     "sigma_single",
		Event:       event,
	}

	doc := alertToDocument(alert)

	// Check alert event metadata.
	if doc.Event.Kind != "alert" {
		t.Errorf("kind = %q, want 'alert'", doc.Event.Kind)
	}
	if doc.Event.Severity != 4 {
		t.Errorf("severity = %d, want 4 (high)", doc.Event.Severity)
	}
	if doc.SourceType != "sigma_alert" {
		t.Errorf("source_type = %q, want 'sigma_alert'", doc.SourceType)
	}

	// Check rule metadata (ECS rule.* fields).
	if doc.Rule == nil {
		t.Fatal("rule fields are nil")
	}
	if doc.Rule.ID != "rule-123" {
		t.Errorf("rule.id = %q, want 'rule-123'", doc.Rule.ID)
	}
	if doc.Rule.Name != "Test Alert" {
		t.Errorf("rule.name = %q, want 'Test Alert'", doc.Rule.Name)
	}
	if doc.Rule.Severity != "high" {
		t.Errorf("rule.severity = %q, want 'high'", doc.Rule.Severity)
	}
	if doc.Rule.Category != "sigma" {
		t.Errorf("rule.category = %q, want 'sigma'", doc.Rule.Category)
	}
	if doc.Rule.Ruleset != "sigma_single" {
		t.Errorf("rule.ruleset = %q, want 'sigma_single'", doc.Rule.Ruleset)
	}
	if doc.Rule.Description != "Detects suspicious process" {
		t.Errorf("rule.description = %q, want 'Detects suspicious process'", doc.Rule.Description)
	}
	if doc.Rule.Author != "test-author" {
		t.Errorf("rule.author = %q, want 'test-author'", doc.Rule.Author)
	}
	if len(doc.Rule.Tags) != 2 || doc.Rule.Tags[0] != "attack.execution" {
		t.Errorf("rule.tags = %v, want [attack.execution, attack.t1059]", doc.Rule.Tags)
	}

	// Observer identifies the detection system (no rule-specific data).
	if doc.Observer == nil {
		t.Fatal("observer is nil")
	}
	if doc.Observer.Type != "sigma" {
		t.Errorf("observer.type = %q, want 'sigma'", doc.Observer.Type)
	}

	// Check tags also preserved in threat.technique.
	if doc.Threat == nil || len(doc.Threat.Technique) != 2 {
		t.Errorf("threat.technique length = %d, want 2", len(doc.Threat.Technique))
	}

	// Original process data should be preserved.
	if doc.Process == nil || doc.Process.Name != "malware.exe" {
		t.Error("original process data should be preserved")
	}
}

func TestAlertToDocumentEmptyRuleID(t *testing.T) {
	alert := correlate.Alert{
		Title: "No ID Rule",
		Level: "low",
		Event: &common.ECSEvent{
			Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		},
	}

	doc := alertToDocument(alert)
	if doc.Rule == nil {
		t.Fatal("rule should not be nil")
	}
	// With empty RuleID, rule.id should be empty string.
	if doc.Rule.ID != "" {
		t.Errorf("rule.id = %q, want empty", doc.Rule.ID)
	}
	if doc.Rule.Name != "No ID Rule" {
		t.Errorf("rule.name = %q, want 'No ID Rule'", doc.Rule.Name)
	}
}

func TestPipelineAlertIndexNaming(t *testing.T) {
	ruleEngine := buildTestRuleEngine()
	reg := normalize.NewRegistry()
	reg.Register(&matchingParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "myprefix", nil, ruleEngine, nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("akeso_edr")})

	alertCalls := indexer.alertCalls()
	if len(alertCalls) == 0 {
		t.Fatal("expected alert index calls")
	}

	// Alert index should use custom prefix.
	for _, call := range alertCalls {
		if !strings.HasPrefix(call.Index, "myprefix-alerts-") {
			t.Errorf("alert index = %q, want prefix 'myprefix-alerts-'", call.Index)
		}
		// Should contain date pattern.
		if !strings.Contains(call.Index, "2026.03.14") {
			t.Errorf("alert index = %q, should contain date '2026.03.14'", call.Index)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
