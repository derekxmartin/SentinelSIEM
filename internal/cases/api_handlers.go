package cases

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/auth"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// CaseAPIHandler holds dependencies for the case management REST API.
type CaseAPIHandler struct {
	caseSvc       *Service
	escalationSvc *EscalationService
}

// NewCaseAPIHandler creates a new case API handler.
func NewCaseAPIHandler(caseSvc *Service, escalationSvc *EscalationService) *CaseAPIHandler {
	return &CaseAPIHandler{
		caseSvc:       caseSvc,
		escalationSvc: escalationSvc,
	}
}

// Routes registers all case API routes on the given chi router.
func (h *CaseAPIHandler) Routes(r chi.Router) {
	r.Post("/api/v1/cases", h.HandleCreate)
	r.Get("/api/v1/cases", h.HandleList)
	r.Get("/api/v1/cases/stats", h.HandleStats)
	r.Get("/api/v1/cases/{id}", h.HandleGet)
	r.Put("/api/v1/cases/{id}", h.HandleUpdate)
	r.Post("/api/v1/cases/{id}/merge", h.HandleMerge)
	r.Post("/api/v1/cases/{id}/comments", h.HandleAddComment)
	r.Post("/api/v1/cases/{id}/observables", h.HandleAddObservable)
}

// authorFromRequest extracts the username from the authenticated JWT claims.
func authorFromRequest(r *http.Request) string {
	claims := auth.ClaimsFromContext(r.Context())
	if claims != nil {
		return claims.Username
	}
	return "unknown"
}

// HandleCreate handles POST /api/v1/cases.
func (h *CaseAPIHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	c, err := h.caseSvc.Create(r.Context(), &req, authorFromRequest(r))
	if err != nil {
		caseWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusCreated, map[string]any{"case": c})
}

// HandleList handles GET /api/v1/cases with filters, pagination, and sorting.
func (h *CaseAPIHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := ListOptions{
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Assignee: q.Get("assignee"),
		SortBy:   q.Get("sort_by"),
		SortDir:  q.Get("sort_dir"),
	}

	if s := q.Get("size"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			opts.Size = v
		}
	}
	if f := q.Get("from"); f != "" {
		if v, err := strconv.Atoi(f); err == nil {
			opts.From = v
		}
	}

	cases, total, err := h.caseSvc.List(r.Context(), opts)
	if err != nil {
		caseWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{
		"cases": cases,
		"total": total,
	})
}

// HandleGet handles GET /api/v1/cases/{id}.
func (h *CaseAPIHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		caseWriteError(w, http.StatusBadRequest, "case id is required")
		return
	}

	c, err := h.caseSvc.Get(r.Context(), id)
	if err != nil {
		caseWriteError(w, http.StatusNotFound, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{"case": c})
}

// HandleUpdate handles PUT /api/v1/cases/{id}.
func (h *CaseAPIHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		caseWriteError(w, http.StatusBadRequest, "case id is required")
		return
	}

	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	c, err := h.caseSvc.Update(r.Context(), id, &req, authorFromRequest(r))
	if err != nil {
		if err == store.ErrConflict {
			caseWriteError(w, http.StatusConflict, err.Error())
			return
		}
		caseWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{"case": c})
}

// mergeRequest holds the fields for merging alerts into an existing case.
type mergeRequest struct {
	AlertIDs []string `json:"alert_ids"`
}

// HandleMerge handles POST /api/v1/cases/{id}/merge.
func (h *CaseAPIHandler) HandleMerge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		caseWriteError(w, http.StatusBadRequest, "case id is required")
		return
	}

	var req mergeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if len(req.AlertIDs) == 0 {
		caseWriteError(w, http.StatusBadRequest, "at least one alert_id is required")
		return
	}

	c, err := h.escalationSvc.EscalateToExisting(r.Context(), id, req.AlertIDs, authorFromRequest(r))
	if err != nil {
		if err == store.ErrConflict {
			caseWriteError(w, http.StatusConflict, err.Error())
			return
		}
		caseWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{"case": c})
}

// commentRequest holds the fields for adding a comment.
type commentRequest struct {
	Text string `json:"text"`
}

// HandleAddComment handles POST /api/v1/cases/{id}/comments.
func (h *CaseAPIHandler) HandleAddComment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		caseWriteError(w, http.StatusBadRequest, "case id is required")
		return
	}

	var req commentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.Text == "" {
		caseWriteError(w, http.StatusBadRequest, "text is required")
		return
	}

	c, err := h.caseSvc.AddComment(r.Context(), id, authorFromRequest(r), req.Text)
	if err != nil {
		caseWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{"case": c})
}

// addObservableRequest holds the fields for manually adding an observable.
type addObservableRequest struct {
	Type   string   `json:"type"`
	Value  string   `json:"value"`
	Tags   []string `json:"tags,omitempty"`
}

// HandleAddObservable handles POST /api/v1/cases/{id}/observables.
func (h *CaseAPIHandler) HandleAddObservable(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		caseWriteError(w, http.StatusBadRequest, "case id is required")
		return
	}

	var req addObservableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.Type == "" || req.Value == "" {
		caseWriteError(w, http.StatusBadRequest, "type and value are required")
		return
	}
	if !IsValidObservableType(req.Type) {
		caseWriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid observable type: %q", req.Type))
		return
	}

	c, err := h.caseSvc.AddObservable(r.Context(), id, Observable{
		Type:   req.Type,
		Value:  req.Value,
		Source: "manual",
		Tags:   req.Tags,
	}, authorFromRequest(r))
	if err != nil {
		caseWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, map[string]any{"case": c})
}

// HandleStats handles GET /api/v1/cases/stats.
func (h *CaseAPIHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.caseSvc.Stats(r.Context())
	if err != nil {
		caseWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	caseWriteJSON(w, http.StatusOK, stats)
}

// --- Helpers ---

func caseWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func caseWriteError(w http.ResponseWriter, status int, msg string) {
	caseWriteJSON(w, status, map[string]string{"error": msg})
}
