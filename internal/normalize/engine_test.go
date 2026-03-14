package normalize

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
)

// mockParser is a test parser that returns a fixed ECSEvent.
type mockParser struct {
	sourceType string
}

func (m *mockParser) SourceType() string { return m.sourceType }

func (m *mockParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			PID:  1234,
			Name: "mock.exe",
		},
	}, nil
}

func TestRouteToRegisteredParser(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockParser{sourceType: "sentineledr"})
	engine := NewEngine(reg)

	raw := json.RawMessage(`{"source_type":"sentineledr","pid":1234}`)
	event, err := engine.Normalize(raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if event.Event.Kind != "event" {
		t.Errorf("event.kind: got %q, want %q", event.Event.Kind, "event")
	}
	if event.Process == nil || event.Process.Name != "mock.exe" {
		t.Error("expected mock parser to populate process.name")
	}
	if event.Raw == nil {
		t.Error("expected raw to be preserved")
	}
}

func TestUnknownSourceTypePreservesRaw(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg)

	raw := json.RawMessage(`{"source_type":"unknown_device","data":"test"}`)
	event, err := engine.Normalize(raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if event.Event == nil || event.Event.Kind != "event" {
		t.Error("expected event.kind to be set to 'event'")
	}
	if event.Raw == nil {
		t.Error("expected raw to be preserved")
	}
	if string(event.Raw) != `{"source_type":"unknown_device","data":"test"}` {
		t.Errorf("raw mismatch: got %s", string(event.Raw))
	}
}

func TestMissingSourceTypePreservesRaw(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg)

	raw := json.RawMessage(`{"data":"no source type field"}`)
	event, err := engine.Normalize(raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if event.Event == nil || event.Event.Kind != "event" {
		t.Error("expected event.kind to be set")
	}
	if event.Raw == nil {
		t.Error("expected raw to be preserved")
	}
}

func TestMalformedJSON(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg)

	raw := json.RawMessage(`{broken json`)
	_, err := engine.Normalize(raw)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestNormalizeBatch(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockParser{sourceType: "sentineledr"})
	engine := NewEngine(reg)

	rawEvents := []json.RawMessage{
		json.RawMessage(`{"source_type":"sentineledr","seq":1}`),
		json.RawMessage(`{broken`),
		json.RawMessage(`{"source_type":"sentineledr","seq":2}`),
		json.RawMessage(`{"source_type":"unknown","seq":3}`),
	}

	events, errs := engine.NormalizeBatch(rawEvents)

	// 3 successful (2 sentineledr + 1 unknown), 1 error (broken JSON).
	if len(events) != 3 {
		t.Errorf("events: got %d, want 3", len(events))
	}
	if len(errs) != 1 {
		t.Errorf("errors: got %d, want 1", len(errs))
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockParser{sourceType: "edr"})

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	reg.Register(&mockParser{sourceType: "edr"})
}

func TestRegistrySourceTypes(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockParser{sourceType: "edr"})
	reg.Register(&mockParser{sourceType: "av"})

	types := reg.SourceTypes()
	if len(types) != 2 {
		t.Errorf("source types: got %d, want 2", len(types))
	}
}
