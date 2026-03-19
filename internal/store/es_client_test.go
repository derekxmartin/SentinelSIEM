package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/config"
)

// esAvailable checks if Elasticsearch is reachable at localhost:9200.
func esAvailable() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:9200")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func skipIfNoES(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if !esAvailable() {
		t.Skip("skipping: Elasticsearch not available at localhost:9200")
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	cfg := config.ElasticsearchConfig{
		Addresses:   []string{"http://localhost:9200"},
		IndexPrefix: "test-akeso",
	}
	store, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return store
}

func TestHealth(t *testing.T) {
	skipIfNoES(t)
	store := newTestStore(t)

	status, err := store.Health(context.Background())
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if status != "green" && status != "yellow" {
		t.Errorf("unexpected health status: %q", status)
	}
}

func TestEnsureTemplate(t *testing.T) {
	skipIfNoES(t)
	store := newTestStore(t)

	err := store.EnsureTemplate(context.Background())
	if err != nil {
		t.Fatalf("ensure template failed: %v", err)
	}

	// Verify template exists by calling it again (idempotent).
	err = store.EnsureTemplate(context.Background())
	if err != nil {
		t.Fatalf("second ensure template failed: %v", err)
	}
}

func TestBulkIndexAndSearch(t *testing.T) {
	skipIfNoES(t)
	store := newTestStore(t)
	ctx := context.Background()

	// Ensure template is in place.
	if err := store.EnsureTemplate(ctx); err != nil {
		t.Fatalf("ensure template: %v", err)
	}

	// Use a unique index to avoid collisions between test runs.
	index := fmt.Sprintf("test-akeso-events-%d", time.Now().UnixNano())

	// Generate 100 events.
	events := make([]common.ECSEvent, 100)
	for i := range events {
		events[i] = common.ECSEvent{
			Timestamp: time.Now().UTC(),
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"process"},
				Type:     []string{"start"},
				Action:   fmt.Sprintf("test-action-%d", i),
				Severity: (i % 4) + 1,
			},
			Process: &common.ProcessFields{
				PID:        i + 1000,
				Name:       "test.exe",
				Executable: `C:\test\test.exe`,
			},
			Host: &common.HostFields{
				Name: "TEST-HOST",
			},
		}
	}

	// Bulk index.
	if err := store.BulkIndex(ctx, index, events); err != nil {
		t.Fatalf("bulk index failed: %v", err)
	}

	// ES needs a refresh to make documents searchable.
	store.client.Indices.Refresh(
		store.client.Indices.Refresh.WithIndex(index),
	)

	// Search — match all.
	result, err := store.Search(ctx, index, map[string]any{"match_all": map[string]any{}}, 200)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if result.Total != 100 {
		t.Errorf("expected 100 hits, got %d", result.Total)
	}
	if len(result.Hits) != 100 {
		t.Errorf("expected 100 hit documents, got %d", len(result.Hits))
	}

	// Verify a hit can be decoded back to ECSEvent.
	var decoded common.ECSEvent
	if err := json.Unmarshal(result.Hits[0], &decoded); err != nil {
		t.Fatalf("failed to decode hit: %v", err)
	}
	if decoded.Event.Kind != "event" {
		t.Errorf("decoded event.kind: got %q, want %q", decoded.Event.Kind, "event")
	}
	if decoded.Host.Name != "TEST-HOST" {
		t.Errorf("decoded host.name: got %q, want %q", decoded.Host.Name, "TEST-HOST")
	}

	// Cleanup: delete test index.
	store.client.Indices.Delete([]string{index})
}
