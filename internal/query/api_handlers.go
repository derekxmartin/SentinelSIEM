package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Searcher is the interface for executing Elasticsearch queries.
// Implementations include the real ES store and test mocks.
type Searcher interface {
	SearchRaw(ctx context.Context, index string, body map[string]any) (*SearchRawResult, error)
}

// SearchRawResult mirrors store.SearchRawResult to avoid import cycles.
// The real store result is mapped to this at the adapter boundary.
type SearchRawResult struct {
	Total  int
	Hits   []json.RawMessage
	Aggs   json.RawMessage
	TookMs int
}

// QueryRequest is the JSON body for POST /api/v1/query.
type QueryRequest struct {
	Query string `json:"query"`          // AkesoSIEM query language string
	Index string `json:"index"`          // ES index pattern (optional, defaults to prefix-*)
	From  int    `json:"from,omitempty"` // pagination offset
	Size  int    `json:"size,omitempty"` // page size (default 100, max 10000)
}

// QueryResponse is the JSON response for POST /api/v1/query.
type QueryResponse struct {
	Total   int               `json:"total"`
	Hits    []json.RawMessage `json:"hits"`
	Aggs    json.RawMessage   `json:"aggs,omitempty"`
	From    int               `json:"from"`
	Size    int               `json:"size"`
	TookMs  int               `json:"took_ms"`
	QueryDSL map[string]any   `json:"query_dsl,omitempty"` // translated ES DSL for debugging
}

// ErrorResponse is a standard error JSON body.
type ErrorResponse struct {
	Error string `json:"error"`
}

const (
	defaultSize = 100
	maxSize     = 10000
	queryTimeout = 30 * time.Second
)

// APIHandler holds dependencies for the query REST API.
type APIHandler struct {
	searcher     Searcher
	defaultIndex string
}

// NewAPIHandler creates a new APIHandler with the given searcher and default index pattern.
func NewAPIHandler(searcher Searcher, defaultIndex string) *APIHandler {
	return &APIHandler{
		searcher:     searcher,
		defaultIndex: defaultIndex,
	}
}

// HandleQuery handles POST /api/v1/query requests.
// It parses the query string, translates to ES DSL, executes, and returns results.
func (h *APIHandler) HandleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse request body.
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}

	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query field is required")
		return
	}

	// Parse the query string into an AST.
	ast, err := Parse(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("query parse error: %v", err))
		return
	}

	// Translate AST to ES DSL.
	translated, err := Translate(ast)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("query translation error: %v", err))
		return
	}

	// Apply request-level pagination overrides.
	if req.From > 0 {
		translated.From = req.From
	}
	if req.Size > 0 {
		translated.Size = clampSize(req.Size)
	}

	// Apply defaults.
	if translated.Size == 0 {
		translated.Size = defaultSize
	}

	// Build the full ES search body.
	esBody := BuildSearchBody(translated)

	// Determine index.
	index := req.Index
	if index == "" {
		index = h.defaultIndex
	}

	// Execute against Elasticsearch.
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()

	result, err := h.searcher.SearchRaw(ctx, index, esBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("elasticsearch error: %v", err))
		return
	}

	// Build response.
	resp := QueryResponse{
		Total:    result.Total,
		Hits:     result.Hits,
		Aggs:     result.Aggs,
		From:     translated.From,
		Size:     translated.Size,
		TookMs:   result.TookMs,
		QueryDSL: esBody,
	}

	// Ensure hits is never null in JSON.
	if resp.Hits == nil {
		resp.Hits = []json.RawMessage{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleHealth handles GET /api/v1/health for the query service.
func (h *APIHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "akeso-query"})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}

func clampSize(size int) int {
	if size < 1 {
		return defaultSize
	}
	if size > maxSize {
		return maxSize
	}
	return size
}
