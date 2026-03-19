package sources

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/normalize"
)

// APIHandler holds dependencies for the source management REST API.
type APIHandler struct {
	service *Service
	engine  *normalize.Engine
}

// NewAPIHandler creates a new source API handler.
func NewAPIHandler(service *Service, engine *normalize.Engine) *APIHandler {
	return &APIHandler{
		service: service,
		engine:  engine,
	}
}

// HandleCreate handles POST /api/v1/sources.
func (h *APIHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	resp, err := h.service.Create(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// HandleList handles GET /api/v1/sources.
func (h *APIHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	sources, err := h.service.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sources": sources,
		"total":   len(sources),
	})
}

// HandleGet handles GET /api/v1/sources/{id}.
func (h *APIHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id is required")
		return
	}

	src, err := h.service.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"source": src})
}

// HandleUpdate handles PUT /api/v1/sources/{id}.
func (h *APIHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id is required")
		return
	}

	var req UpdateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	src, err := h.service.Update(r.Context(), id, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"source": src})
}

// HandleDelete handles DELETE /api/v1/sources/{id}.
func (h *APIHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id is required")
		return
	}

	if err := h.service.Decommission(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "decommissioned"})
}

// HandleTestParser handles POST /api/v1/sources/{id}/test-parser.
func (h *APIHandler) HandleTestParser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id is required")
		return
	}

	// Get the source to know which parser to use.
	src, err := h.service.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var req TestParserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.SampleLog == "" {
		writeError(w, http.StatusBadRequest, "sample_log is required")
		return
	}

	// Wrap the sample log with the source's parser type so the engine routes it correctly.
	testEvent := map[string]any{
		"source_type": src.Parser,
		"raw_log":     req.SampleLog,
	}
	testJSON, err := json.Marshal(testEvent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build test event")
		return
	}

	// Run through the normalization engine.
	ecsEvent, err := h.engine.Normalize(testJSON)
	if err != nil {
		writeJSON(w, http.StatusOK, TestParserResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, TestParserResponse{
		Success:   true,
		ECSOutput: ecsEvent,
	})
}

// HandleSnippet handles GET /api/v1/sources/{id}/snippet.
func (h *APIHandler) HandleSnippet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "source id is required")
		return
	}

	src, err := h.service.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "toml"
	}

	snippet, err := GenerateSnippet(src, format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"format":  format,
		"snippet": snippet,
	})
}

// Routes registers all source API routes on the given chi router.
func (h *APIHandler) Routes(r chi.Router) {
	r.Post("/api/v1/sources", h.HandleCreate)
	r.Get("/api/v1/sources", h.HandleList)
	r.Get("/api/v1/sources/{id}", h.HandleGet)
	r.Put("/api/v1/sources/{id}", h.HandleUpdate)
	r.Delete("/api/v1/sources/{id}", h.HandleDelete)
	r.Post("/api/v1/sources/{id}/test-parser", h.HandleTestParser)
	r.Get("/api/v1/sources/{id}/snippet", h.HandleSnippet)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
