package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/config"
)

const testAPIKey = "test-key-12345"

func newTestListener(handler EventHandler) *HTTPListener {
	cfg := config.IngestConfig{
		HTTPAddr:  "127.0.0.1",
		HTTPPort:  0,
		RateLimit: 10000,
		APIKeys:   []string{testAPIKey},
	}
	return NewHTTPListener(cfg, handler)
}

func TestHealthEndpoint(t *testing.T) {
	l := newTestListener(nil)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIngestValidKey(t *testing.T) {
	var received []json.RawMessage
	var mu sync.Mutex

	l := newTestListener(func(events []json.RawMessage) {
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
	})

	body := `{"source_type":"edr","data":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(body))
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusAccepted)
	}

	mu.Lock()
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
	mu.Unlock()
}

func TestIngestInvalidKey(t *testing.T) {
	l := newTestListener(nil)

	body := `{"data":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(body))
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIngestNoKey(t *testing.T) {
	l := newTestListener(nil)

	body := `{"data":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(body))
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIngestNDJSON(t *testing.T) {
	var received []json.RawMessage
	var mu sync.Mutex

	l := newTestListener(func(events []json.RawMessage) {
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
	})

	// Build 100-event NDJSON body.
	var lines strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&lines, `{"source_type":"edr","seq":%d}`, i)
		lines.WriteByte('\n')
	}

	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(lines.String()))
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusAccepted)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if accepted, ok := resp["accepted"].(float64); !ok || int(accepted) != 100 {
		t.Errorf("accepted: got %v, want 100", resp["accepted"])
	}

	mu.Lock()
	if len(received) != 100 {
		t.Errorf("received %d events, want 100", len(received))
	}
	mu.Unlock()
}

func TestIngestJSONArray(t *testing.T) {
	var received []json.RawMessage
	var mu sync.Mutex

	l := newTestListener(func(events []json.RawMessage) {
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
	})

	body := `[{"seq":1},{"seq":2},{"seq":3}]`
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(body))
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusAccepted)
	}

	mu.Lock()
	if len(received) != 3 {
		t.Errorf("received %d events, want 3", len(received))
	}
	mu.Unlock()
}

func TestIngestRateLimit(t *testing.T) {
	cfg := config.IngestConfig{
		HTTPAddr:  "127.0.0.1",
		HTTPPort:  0,
		RateLimit: 1, // 1 event per second
		APIKeys:   []string{testAPIKey},
	}
	l := NewHTTPListener(cfg, nil)

	// First request should succeed.
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(`{"data":"1"}`))
	req.Header.Set("X-API-Key", testAPIKey)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("first request: got %d, want %d", w.Code, http.StatusAccepted)
	}

	// Second request should be rate limited.
	req = httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(`{"data":"2"}`))
	req.Header.Set("X-API-Key", testAPIKey)
	req.RemoteAddr = "192.168.1.1:12345"
	w = httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("second request: got %d, want %d", w.Code, http.StatusTooManyRequests)
	}
}

func TestIngestEmptyBody(t *testing.T) {
	l := newTestListener(nil)

	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(""))
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIngestInvalidJSON(t *testing.T) {
	l := newTestListener(nil)

	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(`{broken`))
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	l.Router().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}
