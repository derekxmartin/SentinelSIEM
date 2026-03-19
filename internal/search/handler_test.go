package search

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// mockSearcher returns canned results for testing.
type mockSearcher struct {
	results map[string]*SearchRawResult // keyed by index pattern
}

func (m *mockSearcher) SearchRaw(_ context.Context, index string, _ map[string]any) (*SearchRawResult, error) {
	if r, ok := m.results[index]; ok {
		return r, nil
	}
	return &SearchRawResult{}, nil
}

func TestHandleSearch_IPEntity(t *testing.T) {
	alertDoc := `{"_id":"alert-1","@timestamp":"2026-03-17T10:00:00Z","rule":{"name":"Brute Force","severity":"high"}}`
	hostDoc := `{"host.ip":"10.1.2.45","host.name":"web-01","ndr.host_score.threat":80,"ndr.host_score.certainty":90,"ndr.host_score.quadrant":"critical"}`

	mock := &mockSearcher{
		results: map[string]*SearchRawResult{
			"akeso-events-*": {
				Total: 42,
				Aggs:  json.RawMessage(`{"by_source":{"buckets":[{"key":"process","doc_count":30},{"key":"network","doc_count":12}]}}`),
			},
			"akeso-alerts-*": {
				Total: 1,
				Hits:  []json.RawMessage{json.RawMessage(alertDoc)},
			},
			"akeso-cases":           {},
			"akeso-ndr-host-scores": {Total: 1, Hits: []json.RawMessage{json.RawMessage(hostDoc)}},
		},
	}

	rules := []*correlate.SigmaRule{
		{ID: "r1", Title: "IP Scan Detection", Description: "Detects port scans", Level: "medium"},
	}

	h := NewHandler(mock, rules, "akeso")

	body := `{"query":"10.1.2.45","entity_type":"ip"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.HandleSearch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SearchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// Events
	if resp.Events.Total != 42 {
		t.Errorf("events.total = %d, want 42", resp.Events.Total)
	}
	if resp.Events.BySource["process"] != 30 {
		t.Errorf("events.by_source[process] = %d, want 30", resp.Events.BySource["process"])
	}

	// Alerts
	if resp.Alerts.Total != 1 {
		t.Errorf("alerts.total = %d, want 1", resp.Alerts.Total)
	}
	if len(resp.Alerts.Items) != 1 || resp.Alerts.Items[0].RuleName != "Brute Force" {
		t.Errorf("alerts.items unexpected: %+v", resp.Alerts.Items)
	}

	// Host scores (IP only)
	if len(resp.HostScores) != 1 {
		t.Fatalf("host_scores length = %d, want 1", len(resp.HostScores))
	}
	if resp.HostScores[0].Quadrant != "critical" {
		t.Errorf("host_scores[0].quadrant = %q, want critical", resp.HostScores[0].Quadrant)
	}
}

func TestHandleSearch_FreeText_NoHostScores(t *testing.T) {
	mock := &mockSearcher{
		results: map[string]*SearchRawResult{
			"akeso-events-*": {Total: 5},
			"akeso-alerts-*": {},
			"akeso-cases":    {},
		},
	}

	rules := []*correlate.SigmaRule{
		{ID: "r1", Title: "Mimikatz Detection", Description: "Detects mimikatz usage", Level: "critical"},
		{ID: "r2", Title: "PowerShell Download", Description: "Download cradle", Level: "high"},
	}

	h := NewHandler(mock, rules, "akeso")

	body := `{"query":"mimikatz","entity_type":"freetext"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.HandleSearch(w, req)

	var resp SearchResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Host scores should be empty for non-IP searches.
	if len(resp.HostScores) != 0 {
		t.Errorf("host_scores should be empty for freetext, got %d", len(resp.HostScores))
	}

	// Rules should match mimikatz.
	if len(resp.Rules) != 1 || resp.Rules[0].Name != "Mimikatz Detection" {
		t.Errorf("rules unexpected: %+v", resp.Rules)
	}
}

func TestHandleSearch_EmptyQuery(t *testing.T) {
	h := NewHandler(&mockSearcher{results: map[string]*SearchRawResult{}}, nil, "akeso")

	body := `{"query":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.HandleSearch(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty query, got %d", w.Code)
	}
}

func TestSearchRules(t *testing.T) {
	rules := []*correlate.SigmaRule{
		{ID: "1", Title: "Brute Force Login", Description: "Multiple failed logins", Level: "medium"},
		{ID: "2", Title: "Mimikatz Usage", Description: "Credential dumping tool", Level: "critical"},
		{ID: "3", Title: "PowerShell Download", Description: "Download cradle detected", Level: "high"},
	}

	results := SearchRules(rules, "brute", 10)
	if len(results) != 1 || results[0].ID != "1" {
		t.Errorf("expected 1 result for 'brute', got %+v", results)
	}

	results = SearchRules(rules, "credential", 10)
	if len(results) != 1 || results[0].ID != "2" {
		t.Errorf("expected 1 result for 'credential' (description match), got %+v", results)
	}

	results = SearchRules(rules, "nonexistent", 10)
	if len(results) != 0 {
		t.Errorf("expected 0 results for 'nonexistent', got %d", len(results))
	}
}
