package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/config"
)

// EventHandler is called with each batch of raw events received by the listener.
// Downstream consumers (normalize → store) plug in here.
type EventHandler func(events []json.RawMessage)

// HTTPListener is the HTTP ingestion server.
type HTTPListener struct {
	router    chi.Router
	cfg       config.IngestConfig
	apiKeys   map[string]bool
	handler   EventHandler
	limiters  map[string]*rateLimiter
	limiterMu sync.Mutex
}

// rateLimiter implements a simple token bucket per source IP.
type rateLimiter struct {
	tokens    float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func (rl *rateLimiter) allow() bool {
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = now

	if rl.tokens < 1 {
		return false
	}
	rl.tokens--
	return true
}

// NewHTTPListener creates a new HTTP ingestion listener.
func NewHTTPListener(cfg config.IngestConfig, handler EventHandler) *HTTPListener {
	keys := make(map[string]bool, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		keys[k] = true
	}

	l := &HTTPListener{
		router:   chi.NewRouter(),
		cfg:      cfg,
		apiKeys:  keys,
		handler:  handler,
		limiters: make(map[string]*rateLimiter),
	}

	l.router.Post("/api/v1/ingest", l.handleIngest)
	l.router.Get("/api/v1/health", l.handleHealth)

	// WEF collector — shares auth and handler with main ingest endpoint.
	wef := NewWEFCollector(handler)
	l.router.Post("/api/v1/ingest/wef", l.withAuth(wef.HandleWEF))

	return l
}

// withAuth wraps a handler with API key authentication.
func (l *HTTPListener) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" || !l.apiKeys[key] {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Router returns the chi router for use with http.Server.
func (l *HTTPListener) Router() http.Handler {
	return l.router
}

// Post registers an additional POST route on the listener's router.
func (l *HTTPListener) Post(pattern string, handler http.HandlerFunc) {
	l.router.Post(pattern, handler)
}

// Get registers an additional GET route on the listener's router.
func (l *HTTPListener) Get(pattern string, handler http.HandlerFunc) {
	l.router.Get(pattern, handler)
}

// ListenAddr returns the configured listen address string.
func (l *HTTPListener) ListenAddr() string {
	return fmt.Sprintf("%s:%d", l.cfg.HTTPAddr, l.cfg.HTTPPort)
}

func (l *HTTPListener) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (l *HTTPListener) handleIngest(w http.ResponseWriter, r *http.Request) {
	// API key auth.
	key := r.Header.Get("X-API-Key")
	if key == "" || !l.apiKeys[key] {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Rate limiting by remote IP.
	if l.cfg.RateLimit > 0 {
		ip := r.RemoteAddr
		if !l.allowRequest(ip) {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
	}

	// Read body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, `{"error":"empty body"}`, http.StatusBadRequest)
		return
	}

	// Parse as NDJSON or single JSON.
	events, err := parseEvents(body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Deliver to handler.
	if l.handler != nil {
		l.handler(events)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"accepted": len(events),
	})
}

func (l *HTTPListener) allowRequest(ip string) bool {
	l.limiterMu.Lock()
	defer l.limiterMu.Unlock()

	rl, ok := l.limiters[ip]
	if !ok {
		rl = &rateLimiter{
			tokens:     float64(l.cfg.RateLimit),
			maxTokens:  float64(l.cfg.RateLimit),
			refillRate: float64(l.cfg.RateLimit),
			lastRefill: time.Now(),
		}
		l.limiters[ip] = rl
	}
	return rl.allow()
}

// parseEvents handles both single JSON objects and NDJSON (newline-delimited JSON).
func parseEvents(body []byte) ([]json.RawMessage, error) {
	// Try single JSON object/array first.
	trimmed := trimLeftSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	// If it starts with '[', it's a JSON array.
	if trimmed[0] == '[' {
		var events []json.RawMessage
		if err := json.Unmarshal(trimmed, &events); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		return events, nil
	}

	// Try NDJSON: scan line by line.
	var events []json.RawMessage
	scanner := bufio.NewScanner(bytesReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB per line
	for scanner.Scan() {
		line := trimLeftSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("invalid JSON on line %d", len(events)+1)
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		events = append(events, cp)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading NDJSON: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no events found in body")
	}

	return events, nil
}

func trimLeftSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

type byteReaderWrapper struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) io.Reader {
	return &byteReaderWrapper{data: data}
}

func (r *byteReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
