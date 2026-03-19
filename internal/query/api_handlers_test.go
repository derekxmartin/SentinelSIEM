package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockSearcher implements Searcher for testing.
type mockSearcher struct {
	result *SearchRawResult
	err    error
	// Captured args for assertion.
	lastIndex string
	lastBody  map[string]any
}

func (m *mockSearcher) SearchRaw(_ context.Context, index string, body map[string]any) (*SearchRawResult, error) {
	m.lastIndex = index
	m.lastBody = body
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func newMockSearcher(total int, hits ...string) *mockSearcher {
	rawHits := make([]json.RawMessage, len(hits))
	for i, h := range hits {
		rawHits[i] = json.RawMessage(h)
	}
	return &mockSearcher{
		result: &SearchRawResult{
			Total:  total,
			Hits:   rawHits,
			TookMs: 5,
		},
	}
}

func TestHandleQuery_SimpleEquals(t *testing.T) {
	mock := newMockSearcher(1, `{"process.name":"cmd.exe"}`)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "process.name = \"cmd.exe\""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp QueryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Total != 1 {
		t.Errorf("expected total=1, got %d", resp.Total)
	}
	if len(resp.Hits) != 1 {
		t.Errorf("expected 1 hit, got %d", len(resp.Hits))
	}
	if resp.Size != defaultSize {
		t.Errorf("expected default size=%d, got %d", defaultSize, resp.Size)
	}

	// Verify the translated DSL was sent to ES.
	if mock.lastIndex != "akeso-events-*" {
		t.Errorf("expected default index, got %q", mock.lastIndex)
	}
	queryDSL := mock.lastBody["query"].(map[string]any)
	if _, ok := queryDSL["term"]; !ok {
		t.Errorf("expected term query in DSL, got %v", queryDSL)
	}
}

func TestHandleQuery_CustomIndex(t *testing.T) {
	mock := newMockSearcher(0)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok", "index": "custom-index-*"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.lastIndex != "custom-index-*" {
		t.Errorf("expected custom-index-*, got %q", mock.lastIndex)
	}
}

func TestHandleQuery_Pagination(t *testing.T) {
	mock := newMockSearcher(500)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok", "from": 100, "size": 25}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.From != 100 {
		t.Errorf("expected from=100, got %d", resp.From)
	}
	if resp.Size != 25 {
		t.Errorf("expected size=25, got %d", resp.Size)
	}

	// Verify from/size sent to ES.
	if mock.lastBody["from"] != 100 {
		t.Errorf("expected from=100 in ES body, got %v", mock.lastBody["from"])
	}
	if mock.lastBody["size"] != 25 {
		t.Errorf("expected size=25 in ES body, got %v", mock.lastBody["size"])
	}
}

func TestHandleQuery_SizeClamp(t *testing.T) {
	mock := newMockSearcher(0)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok", "size": 99999}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Size != maxSize {
		t.Errorf("expected size clamped to %d, got %d", maxSize, resp.Size)
	}
}

func TestHandleQuery_EmptyQuery(t *testing.T) {
	handler := NewAPIHandler(newMockSearcher(0), "akeso-events-*")

	body := `{"query": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, "required") {
		t.Errorf("expected 'required' in error, got %q", resp.Error)
	}
}

func TestHandleQuery_InvalidQuery(t *testing.T) {
	handler := NewAPIHandler(newMockSearcher(0), "akeso-events-*")

	body := `{"query": "??? !!!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, "parse error") {
		t.Errorf("expected 'parse error' in error, got %q", resp.Error)
	}
}

func TestHandleQuery_InvalidJSON(t *testing.T) {
	handler := NewAPIHandler(newMockSearcher(0), "akeso-events-*")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleQuery_MethodNotAllowed(t *testing.T) {
	handler := NewAPIHandler(newMockSearcher(0), "akeso-events-*")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query", nil)
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleQuery_ESError(t *testing.T) {
	mock := &mockSearcher{
		err: fmt.Errorf("connection refused"),
	}
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}

	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, "elasticsearch error") {
		t.Errorf("expected 'elasticsearch error' in error, got %q", resp.Error)
	}
}

func TestHandleQuery_WithPipes(t *testing.T) {
	mock := newMockSearcher(10, `{"user":"admin"}`)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "user.name = admin | sort @timestamp desc | head 10 | fields user.name, host.name"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify sort, size, and source were sent to ES.
	if _, ok := mock.lastBody["sort"]; !ok {
		t.Error("expected sort in ES body")
	}
	if mock.lastBody["size"] != 10 {
		t.Errorf("expected size=10, got %v", mock.lastBody["size"])
	}
	if _, ok := mock.lastBody["_source"]; !ok {
		t.Error("expected _source in ES body")
	}
}

func TestHandleQuery_Aggregation(t *testing.T) {
	mock := &mockSearcher{
		result: &SearchRawResult{
			Total:  0,
			Aggs:   json.RawMessage(`{"group_by_user.name":{"buckets":[{"key":"admin","doc_count":42}]}}`),
			TookMs: 3,
		},
	}
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "count() by user.name where host.name = srv01"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Aggs == nil {
		t.Error("expected aggregations in response")
	}

	// Verify aggs were sent to ES.
	if _, ok := mock.lastBody["aggs"]; !ok {
		t.Error("expected aggs in ES body")
	}
}

func TestHandleQuery_NullHitsBecomesEmptyArray(t *testing.T) {
	mock := &mockSearcher{
		result: &SearchRawResult{
			Total:  0,
			Hits:   nil,
			TookMs: 1,
		},
	}
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "nonexistent.field = nothing"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Verify hits is [] not null in JSON.
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"hits":[]`)) {
		t.Errorf("expected empty hits array, got %s", rec.Body.String())
	}
}

func TestHandleQuery_QueryDSLInResponse(t *testing.T) {
	mock := newMockSearcher(0)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "process.name = cmd.exe"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.QueryDSL == nil {
		t.Error("expected query_dsl in response for debugging")
	}
	if _, ok := resp.QueryDSL["query"]; !ok {
		t.Error("expected 'query' key in query_dsl")
	}
}

func TestHandleHealth(t *testing.T) {
	handler := NewAPIHandler(newMockSearcher(0), "akeso-events-*")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	handler.HandleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
	if resp["service"] != "akeso-query" {
		t.Errorf("expected service=akeso-query, got %q", resp["service"])
	}
}

func TestHandleQuery_ComplexBoolQuery(t *testing.T) {
	mock := newMockSearcher(5)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "(process.name = cmd.exe OR process.name = powershell.exe) AND host.name = srv01"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify bool query structure was sent to ES.
	queryDSL := mock.lastBody["query"].(map[string]any)
	boolClause, ok := queryDSL["bool"].(map[string]any)
	if !ok {
		t.Fatalf("expected bool query, got %v", queryDSL)
	}
	must, ok := boolClause["must"].([]any)
	if !ok {
		t.Fatalf("expected must clause, got %v", boolClause)
	}
	if len(must) != 2 {
		t.Errorf("expected 2 must clauses, got %d", len(must))
	}
}

func TestHandleQuery_WildcardQuery(t *testing.T) {
	mock := newMockSearcher(3)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "process.name = cmd*"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	queryDSL := mock.lastBody["query"].(map[string]any)
	if _, ok := queryDSL["wildcard"]; !ok {
		t.Errorf("expected wildcard query, got %v", queryDSL)
	}
}

func TestHandleQuery_PaginationFromOverride(t *testing.T) {
	// Verify request-level from overrides pipe-level settings.
	mock := newMockSearcher(100)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok | head 20", "from": 40}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.From != 40 {
		t.Errorf("expected from=40, got %d", resp.From)
	}
	if resp.Size != 20 {
		t.Errorf("expected size=20 from head pipe, got %d", resp.Size)
	}
}

func TestClampSize(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, defaultSize},
		{-5, defaultSize},
		{1, 1},
		{100, 100},
		{10000, 10000},
		{10001, 10000},
		{99999, 10000},
	}

	for _, tt := range tests {
		got := clampSize(tt.input)
		if got != tt.expected {
			t.Errorf("clampSize(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestHandleQuery_ContentTypeJSON(t *testing.T) {
	mock := newMockSearcher(0)
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHandleQuery_TookMsPropagated(t *testing.T) {
	mock := &mockSearcher{
		result: &SearchRawResult{
			Total:  0,
			TookMs: 42,
		},
	}
	handler := NewAPIHandler(mock, "akeso-events-*")

	body := `{"query": "status = ok"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.HandleQuery(rec, req)

	var resp QueryResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.TookMs != 42 {
		t.Errorf("expected took_ms=42, got %d", resp.TookMs)
	}
}
