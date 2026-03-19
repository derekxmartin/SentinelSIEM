package cases

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/auth"
)

// withClaims returns a context with auth claims set.
func withClaims(ctx context.Context, username string) context.Context {
	claims := &auth.Claims{Username: username}
	return context.WithValue(ctx, auth.ContextKeyClaims, claims)
}

func newTestHandler() (*CaseAPIHandler, *mockBackend, *mockAlertBackend) {
	caseMock := newMockBackend()
	caseSvc := NewService(caseMock, "test-cases")
	alertMock := newMockAlertBackend()
	escSvc := NewEscalationService(caseSvc, alertMock, "test-alerts-*")
	handler := NewCaseAPIHandler(caseSvc, escSvc)
	return handler, caseMock, alertMock
}

func TestHandleCreateCase(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{"title":"Test Case","severity":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(body))
	req = req.WithContext(withClaims(req.Context(), "analyst1"))
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &resp)
	var c Case
	json.Unmarshal(resp["case"], &c)

	if c.Title != "Test Case" {
		t.Errorf("expected title %q, got %q", "Test Case", c.Title)
	}
	if c.Severity != SeverityHigh {
		t.Errorf("expected severity %q, got %q", SeverityHigh, c.Severity)
	}
}

func TestHandleCreateCaseMissingTitle(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{"severity":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(body))
	req = req.WithContext(withClaims(req.Context(), "analyst1"))
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleGetCase(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create a case first.
	createBody := `{"title":"Get Test","severity":"low"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(createBody))
	createReq = createReq.WithContext(withClaims(createReq.Context(), "analyst1"))
	createW := httptest.NewRecorder()
	handler.HandleCreate(createW, createReq)

	var createResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(createW.Body.Bytes(), &createResp)
	caseID := createResp.Case.ID

	// Now get it via chi router context.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", caseID)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/cases/"+caseID, nil)
	getReq = getReq.WithContext(context.WithValue(
		withClaims(getReq.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	getW := httptest.NewRecorder()
	handler.HandleGet(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getW.Code, getW.Body.String())
	}

	var getResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(getW.Body.Bytes(), &getResp)
	if getResp.Case.Title != "Get Test" {
		t.Errorf("expected title %q, got %q", "Get Test", getResp.Case.Title)
	}
}

func TestHandleGetCaseNotFound(t *testing.T) {
	handler, _, _ := newTestHandler()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nonexistent")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases/nonexistent", nil)
	req = req.WithContext(context.WithValue(
		withClaims(req.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	w := httptest.NewRecorder()
	handler.HandleGet(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleUpdateCase(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create a case.
	createBody := `{"title":"Update Test","severity":"low"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(createBody))
	createReq = createReq.WithContext(withClaims(createReq.Context(), "analyst1"))
	createW := httptest.NewRecorder()
	handler.HandleCreate(createW, createReq)

	var createResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(createW.Body.Bytes(), &createResp)
	caseID := createResp.Case.ID

	// Update severity.
	updateBody := `{"severity":"critical"}`
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", caseID)
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+caseID, bytes.NewBufferString(updateBody))
	updateReq = updateReq.WithContext(context.WithValue(
		withClaims(updateReq.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	updateW := httptest.NewRecorder()
	handler.HandleUpdate(updateW, updateReq)

	if updateW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateW.Code, updateW.Body.String())
	}

	var updateResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(updateW.Body.Bytes(), &updateResp)
	if updateResp.Case.Severity != SeverityCritical {
		t.Errorf("expected severity %q, got %q", SeverityCritical, updateResp.Case.Severity)
	}
}

func TestHandleAddComment(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create a case.
	createBody := `{"title":"Comment Test"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(createBody))
	createReq = createReq.WithContext(withClaims(createReq.Context(), "analyst1"))
	createW := httptest.NewRecorder()
	handler.HandleCreate(createW, createReq)

	var createResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(createW.Body.Bytes(), &createResp)
	caseID := createResp.Case.ID

	// Add comment.
	commentBody := `{"text":"This is suspicious"}`
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", caseID)
	commentReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+caseID+"/comments", bytes.NewBufferString(commentBody))
	commentReq = commentReq.WithContext(context.WithValue(
		withClaims(commentReq.Context(), "analyst2"),
		chi.RouteCtxKey, rctx,
	))
	commentW := httptest.NewRecorder()
	handler.HandleAddComment(commentW, commentReq)

	if commentW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", commentW.Code, commentW.Body.String())
	}

	var resp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(commentW.Body.Bytes(), &resp)

	// Should have 2 timeline entries: creation + comment.
	commentCount := 0
	for _, entry := range resp.Case.Timeline {
		if entry.ActionType == ActionComment {
			commentCount++
		}
	}
	if commentCount != 1 {
		t.Errorf("expected 1 comment timeline entry, got %d", commentCount)
	}
}

func TestHandleAddCommentEmptyText(t *testing.T) {
	handler, _, _ := newTestHandler()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "some-id")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/some-id/comments", bytes.NewBufferString(`{"text":""}`))
	req = req.WithContext(context.WithValue(
		withClaims(req.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	w := httptest.NewRecorder()
	handler.HandleAddComment(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleAddObservable(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create a case.
	createBody := `{"title":"Observable Test"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(createBody))
	createReq = createReq.WithContext(withClaims(createReq.Context(), "analyst1"))
	createW := httptest.NewRecorder()
	handler.HandleCreate(createW, createReq)

	var createResp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(createW.Body.Bytes(), &createResp)
	caseID := createResp.Case.ID

	// Add observable.
	obsBody := `{"type":"ip","value":"10.0.0.1"}`
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", caseID)
	obsReq := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+caseID+"/observables", bytes.NewBufferString(obsBody))
	obsReq = obsReq.WithContext(context.WithValue(
		withClaims(obsReq.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	obsW := httptest.NewRecorder()
	handler.HandleAddObservable(obsW, obsReq)

	if obsW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", obsW.Code, obsW.Body.String())
	}

	var resp struct {
		Case Case `json:"case"`
	}
	json.Unmarshal(obsW.Body.Bytes(), &resp)

	assertHasObservable(t, resp.Case.Observables, ObservableIP, "10.0.0.1")
}

func TestHandleAddObservableInvalidType(t *testing.T) {
	handler, _, _ := newTestHandler()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "some-id")
	body := `{"type":"invalid_type","value":"foo"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/some-id/observables", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(
		withClaims(req.Context(), "analyst1"),
		chi.RouteCtxKey, rctx,
	))
	w := httptest.NewRecorder()
	handler.HandleAddObservable(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleList(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create two cases.
	for _, title := range []string{"Case A", "Case B"} {
		body := `{"title":"` + title + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(body))
		req = req.WithContext(withClaims(req.Context(), "analyst1"))
		w := httptest.NewRecorder()
		handler.HandleCreate(w, req)
	}

	// List all.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/cases", nil)
	listReq = listReq.WithContext(withClaims(listReq.Context(), "analyst1"))
	listW := httptest.NewRecorder()
	handler.HandleList(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listW.Code, listW.Body.String())
	}

	var resp struct {
		Cases []*Case `json:"cases"`
		Total int     `json:"total"`
	}
	json.Unmarshal(listW.Body.Bytes(), &resp)

	if resp.Total != 2 {
		t.Errorf("expected 2 total, got %d", resp.Total)
	}
}

func TestHandleStats(t *testing.T) {
	handler, _, _ := newTestHandler()

	// Create a case so stats has something.
	body := `{"title":"Stats Test","severity":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(body))
	req = req.WithContext(withClaims(req.Context(), "analyst1"))
	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	// Get stats.
	statsReq := httptest.NewRequest(http.MethodGet, "/api/v1/cases/stats", nil)
	statsReq = statsReq.WithContext(withClaims(statsReq.Context(), "analyst1"))
	statsW := httptest.NewRecorder()
	handler.HandleStats(statsW, statsReq)

	if statsW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", statsW.Code, statsW.Body.String())
	}

	var stats CaseStats
	json.Unmarshal(statsW.Body.Bytes(), &stats)

	if stats.Total != 1 {
		t.Errorf("expected total 1, got %d", stats.Total)
	}
}

func TestHandleCreateInvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString(`{invalid`))
	req = req.WithContext(withClaims(req.Context(), "analyst1"))
	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuthorFromRequestWithClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(withClaims(req.Context(), "testuser"))
	author := authorFromRequest(req)
	if author != "testuser" {
		t.Errorf("expected %q, got %q", "testuser", author)
	}
}

func TestAuthorFromRequestNoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	author := authorFromRequest(req)
	if author != "unknown" {
		t.Errorf("expected %q, got %q", "unknown", author)
	}
}
