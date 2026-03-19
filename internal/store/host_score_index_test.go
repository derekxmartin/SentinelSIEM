package store

import (
	"context"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

func TestExtractHostIP(t *testing.T) {
	tests := []struct {
		name     string
		event    *common.ECSEvent
		expected string
	}{
		{
			name:     "host.ip present",
			event:    &common.ECSEvent{Host: &common.HostFields{IP: []string{"10.0.0.1"}}},
			expected: "10.0.0.1",
		},
		{
			name:     "source.ip fallback",
			event:    &common.ECSEvent{Source: &common.EndpointFields{IP: "10.0.0.2"}},
			expected: "10.0.0.2",
		},
		{
			name: "host.ip preferred over source.ip",
			event: &common.ECSEvent{
				Host:   &common.HostFields{IP: []string{"10.0.0.1"}},
				Source: &common.EndpointFields{IP: "10.0.0.2"},
			},
			expected: "10.0.0.1",
		},
		{
			name:     "no IP available",
			event:    &common.ECSEvent{},
			expected: "",
		},
		{
			name:     "nil host and source",
			event:    &common.ECSEvent{Host: nil, Source: nil},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHostIP(tc.event)
			if got != tc.expected {
				t.Errorf("extractHostIP() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestHostScoreDocumentFields(t *testing.T) {
	event := &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Host:      &common.HostFields{Name: "DC01", IP: []string{"10.1.1.5"}},
		User:      &common.UserFields{Name: "admin"},
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{
				Threat:    85,
				Certainty: 90,
				Quadrant:  "high_high",
			},
		},
	}

	doc := HostScoreDocument{
		HostIP:    extractHostIP(event),
		HostName:  event.Host.Name,
		Threat:    event.NDR.HostScore.Threat,
		Certainty: event.NDR.HostScore.Certainty,
		Quadrant:  event.NDR.HostScore.Quadrant,
		UserName:  event.User.Name,
		UpdatedAt: event.Timestamp,
	}

	if doc.HostIP != "10.1.1.5" {
		t.Errorf("HostIP = %q, want 10.1.1.5", doc.HostIP)
	}
	if doc.HostName != "DC01" {
		t.Errorf("HostName = %q, want DC01", doc.HostName)
	}
	if doc.Threat != 85 {
		t.Errorf("Threat = %d, want 85", doc.Threat)
	}
	if doc.Certainty != 90 {
		t.Errorf("Certainty = %d, want 90", doc.Certainty)
	}
	if doc.Quadrant != "high_high" {
		t.Errorf("Quadrant = %q, want high_high", doc.Quadrant)
	}
}

func TestHostScoreIndexMappings(t *testing.T) {
	m := hostScoreIndexMappings()

	mappings, ok := m["mappings"].(map[string]any)
	if !ok {
		t.Fatal("missing mappings key")
	}

	props, ok := mappings["properties"].(map[string]any)
	if !ok {
		t.Fatal("missing properties key")
	}

	requiredFields := []string{
		"host.ip", "host.name",
		"ndr.host_score.threat", "ndr.host_score.certainty", "ndr.host_score.quadrant",
		"user.name", "updated_at",
	}

	for _, field := range requiredFields {
		if _, ok := props[field]; !ok {
			t.Errorf("missing field mapping: %s", field)
		}
	}
}

func TestHostScoreIndexName(t *testing.T) {
	store := &Store{prefix: "akeso"}
	if got := store.hostScoreIndexName(); got != "akeso-ndr-host-scores" {
		t.Errorf("hostScoreIndexName() = %q, want akeso-ndr-host-scores", got)
	}

	store2 := &Store{prefix: "myorg"}
	if got := store2.hostScoreIndexName(); got != "myorg-ndr-host-scores" {
		t.Errorf("hostScoreIndexName() = %q, want myorg-ndr-host-scores", got)
	}
}

func TestUpsertHostScoreValidation(t *testing.T) {
	store := &Store{prefix: "test"}

	// Nil event.
	err := store.UpsertHostScore(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil event")
	}

	// Missing NDR fields.
	err = store.UpsertHostScore(context.Background(), &common.ECSEvent{})
	if err == nil {
		t.Error("expected error for missing NDR fields")
	}

	// Missing host_score.
	err = store.UpsertHostScore(context.Background(), &common.ECSEvent{
		NDR: &common.NDRFields{},
	})
	if err == nil {
		t.Error("expected error for missing host_score")
	}

	// Missing host IP.
	err = store.UpsertHostScore(context.Background(), &common.ECSEvent{
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{Threat: 50, Certainty: 60, Quadrant: "medium_medium"},
		},
	})
	if err == nil {
		t.Error("expected error for missing host IP")
	}
}

// Integration test — requires running Elasticsearch.
func TestUpsertHostScoreIntegration(t *testing.T) {
	skipIfNoES(t)
	store := newTestStore(t)
	ctx := context.Background()

	// Ensure index exists.
	if err := store.EnsureHostScoreIndex(ctx); err != nil {
		t.Fatalf("ensure host score index: %v", err)
	}

	// Upsert a host score.
	event1 := &common.ECSEvent{
		Timestamp: time.Now().UTC(),
		Host:      &common.HostFields{Name: "HOST-A", IP: []string{"10.99.99.1"}},
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{
				Threat:    50,
				Certainty: 60,
				Quadrant:  "medium_medium",
			},
		},
	}

	if err := store.UpsertHostScore(ctx, event1); err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}

	// Upsert again with higher scores — should update, not duplicate.
	event2 := &common.ECSEvent{
		Timestamp: time.Now().UTC(),
		Host:      &common.HostFields{Name: "HOST-A", IP: []string{"10.99.99.1"}},
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{
				Threat:    90,
				Certainty: 95,
				Quadrant:  "high_high",
			},
		},
	}

	if err := store.UpsertHostScore(ctx, event2); err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}

	// Refresh and search to verify only 1 document exists.
	store.client.Indices.Refresh(
		store.client.Indices.Refresh.WithIndex(store.hostScoreIndexName()),
	)

	result, err := store.Search(ctx, store.hostScoreIndexName(), map[string]any{
		"term": map[string]any{"host.ip": "10.99.99.1"},
	}, 10)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("expected 1 document (upsert), got %d", result.Total)
	}

	// Cleanup.
	store.client.Indices.Delete([]string{store.hostScoreIndexName()})
}

// Integration test for EnsureHostScoreIndex idempotency.
func TestEnsureHostScoreIndexIdempotent(t *testing.T) {
	skipIfNoES(t)
	store := newTestStore(t)
	ctx := context.Background()

	// Create.
	if err := store.EnsureHostScoreIndex(ctx); err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	// Create again — should be idempotent.
	if err := store.EnsureHostScoreIndex(ctx); err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	// Cleanup.
	store.client.Indices.Delete([]string{store.hostScoreIndexName()})
}
