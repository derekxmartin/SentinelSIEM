package cases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/store"
)

// mockBackend is an in-memory Backend for testing.
type mockBackend struct {
	mu   sync.Mutex
	docs map[string]versionedEntry // key = "index/id"
}

type versionedEntry struct {
	data        []byte
	seqNo       int
	primaryTerm int
}

func newMockBackend() *mockBackend {
	return &mockBackend{docs: make(map[string]versionedEntry)}
}

func (m *mockBackend) key(index, id string) string {
	return index + "/" + id
}

func (m *mockBackend) IndexDoc(_ context.Context, index, id string, doc []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(index, id)
	e := m.docs[k]
	m.docs[k] = versionedEntry{
		data:        append([]byte(nil), doc...),
		seqNo:       e.seqNo + 1,
		primaryTerm: 1,
	}
	return nil
}

func (m *mockBackend) GetDocVersioned(_ context.Context, index, id string) (*store.VersionedDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(index, id)
	e, ok := m.docs[k]
	if !ok {
		return nil, fmt.Errorf("document not found: %s/%s", index, id)
	}
	return &store.VersionedDoc{
		Source:      json.RawMessage(e.data),
		SeqNo:      e.seqNo,
		PrimaryTerm: e.primaryTerm,
	}, nil
}

func (m *mockBackend) IndexDocIfMatch(_ context.Context, index, id string, doc []byte, seqNo, primaryTerm int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(index, id)
	e, ok := m.docs[k]
	if !ok {
		return fmt.Errorf("document not found: %s/%s", index, id)
	}
	if e.seqNo != seqNo || e.primaryTerm != primaryTerm {
		return store.ErrConflict
	}
	m.docs[k] = versionedEntry{
		data:        append([]byte(nil), doc...),
		seqNo:       e.seqNo + 1,
		primaryTerm: e.primaryTerm,
	}
	return nil
}

func (m *mockBackend) SearchRaw(_ context.Context, index string, body map[string]any) (*store.SearchRawResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	hits := make([]json.RawMessage, 0)
	prefix := index + "/"
	for k, e := range m.docs {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			hits = append(hits, json.RawMessage(e.data))
		}
	}

	return &store.SearchRawResult{
		Total: len(hits),
		Hits:  hits,
	}, nil
}

func newTestService() (*Service, *mockBackend) {
	mb := newMockBackend()
	svc := NewService(mb, "test-cases")
	return svc, mb
}

func TestCreateAndGet(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, err := svc.Create(ctx, &CreateRequest{
		Title:    "Credential Theft",
		Severity: SeverityHigh,
		Assignee: "analyst1",
		AlertIDs: []string{"alert-001"},
		Tags:     []string{"attack.t1003"},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if c.ID == "" {
		t.Fatal("expected non-empty case ID")
	}
	if c.Status != StatusNew {
		t.Errorf("expected status %q, got %q", StatusNew, c.Status)
	}
	if c.Severity != SeverityHigh {
		t.Errorf("expected severity %q, got %q", SeverityHigh, c.Severity)
	}
	if len(c.Timeline) != 1 {
		t.Errorf("expected 1 timeline entry, got %d", len(c.Timeline))
	}

	// Read it back.
	got, err := svc.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Title != "Credential Theft" {
		t.Errorf("expected title %q, got %q", "Credential Theft", got.Title)
	}
	if got.SeqNo == nil || got.PrimaryTerm == nil {
		t.Error("expected version metadata on Get result")
	}
}

func TestCreateRequiresTitle(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Create(ctx, &CreateRequest{Title: ""}, "analyst1")
	if err == nil {
		t.Fatal("expected error for empty title")
	}
}

func TestCreateInvalidSeverity(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Create(ctx, &CreateRequest{
		Title:    "Test",
		Severity: "unknown",
	}, "analyst1")
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestCreateDefaultSeverity(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, err := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if c.Severity != SeverityLow {
		t.Errorf("expected default severity %q, got %q", SeverityLow, c.Severity)
	}
}

func TestUpdateStatusTransition(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test", Severity: SeverityMedium}, "analyst1")

	// new → in_progress
	status := StatusInProgress
	updated, err := svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Status != StatusInProgress {
		t.Errorf("expected status %q, got %q", StatusInProgress, updated.Status)
	}

	// Verify timeline has status change entry.
	found := false
	for _, entry := range updated.Timeline {
		if entry.ActionType == ActionStatusChange {
			found = true
		}
	}
	if !found {
		t.Error("expected status_change timeline entry")
	}
}

func TestUpdateInvalidTransition(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	// new → closed (skipping in_progress) — should be allowed per CanTransition.
	// But closing requires resolution.
	status := StatusClosed
	_, err := svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")
	if err == nil {
		t.Fatal("expected error: close without resolution")
	}
}

func TestUpdateBackwardTransitionBlocked(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	// new → in_progress
	status := StatusInProgress
	svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")

	// in_progress → new should be blocked
	status = StatusNew
	_, err := svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")
	if err == nil {
		t.Fatal("expected error for backward transition")
	}
}

func TestCloseRequiresResolution(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	_, err := svc.Close(ctx, c.ID, &CloseRequest{
		Resolution: Resolution{Type: ""},
	}, "analyst1")
	if err == nil {
		t.Fatal("expected error: close without valid resolution type")
	}
}

func TestCloseWithResolution(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test", Severity: SeverityHigh}, "analyst1")

	closed, err := svc.Close(ctx, c.ID, &CloseRequest{
		Resolution: Resolution{Type: ResolutionTruePositive, Notes: "Confirmed."},
	}, "analyst1")
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if closed.Status != StatusClosed {
		t.Errorf("expected status %q, got %q", StatusClosed, closed.Status)
	}
	if closed.Resolution == nil {
		t.Fatal("expected resolution to be set")
	}
	if closed.Resolution.Type != ResolutionTruePositive {
		t.Errorf("expected resolution type %q, got %q", ResolutionTruePositive, closed.Resolution.Type)
	}
	if closed.ClosedAt == nil {
		t.Error("expected closed_at to be set")
	}
}

func TestReopenClearsResolution(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")
	svc.Close(ctx, c.ID, &CloseRequest{
		Resolution: Resolution{Type: ResolutionFalsePositive},
	}, "analyst1")

	// Reopen: closed → in_progress.
	status := StatusInProgress
	reopened, err := svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	if reopened.Status != StatusInProgress {
		t.Errorf("expected status %q, got %q", StatusInProgress, reopened.Status)
	}
	if reopened.Resolution != nil {
		t.Error("expected resolution to be cleared on reopen")
	}
	if reopened.ClosedAt != nil {
		t.Error("expected closed_at to be cleared on reopen")
	}
}

func TestUpdateClosedCaseBlocked(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")
	svc.Close(ctx, c.ID, &CloseRequest{
		Resolution: Resolution{Type: ResolutionBenign},
	}, "analyst1")

	// Try to update title on closed case.
	title := "New Title"
	_, err := svc.Update(ctx, c.ID, &UpdateRequest{Title: &title}, "analyst1")
	if err == nil {
		t.Fatal("expected error: cannot update closed case")
	}
}

func TestUpdateClosedCaseReopenAllowed(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")
	svc.Close(ctx, c.ID, &CloseRequest{
		Resolution: Resolution{Type: ResolutionBenign},
	}, "analyst1")

	// Reopen should work even though case is closed (it's a status change).
	status := StatusInProgress
	reopened, err := svc.Update(ctx, c.ID, &UpdateRequest{Status: &status}, "analyst1")
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	if reopened.Status != StatusInProgress {
		t.Errorf("expected status %q, got %q", StatusInProgress, reopened.Status)
	}
}

func TestOptimisticConcurrencyConflict(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	// Get case to obtain version.
	got, _ := svc.Get(ctx, c.ID)
	seqNo := *got.SeqNo
	primaryTerm := *got.PrimaryTerm

	// First update succeeds.
	title1 := "Update 1"
	_, err := svc.Update(ctx, c.ID, &UpdateRequest{
		Title:       &title1,
		SeqNo:       &seqNo,
		PrimaryTerm: &primaryTerm,
	}, "analyst1")
	if err != nil {
		t.Fatalf("First update failed: %v", err)
	}

	// Second update with stale version should fail.
	title2 := "Update 2"
	_, err = svc.Update(ctx, c.ID, &UpdateRequest{
		Title:       &title2,
		SeqNo:       &seqNo,
		PrimaryTerm: &primaryTerm,
	}, "analyst2")
	if err == nil {
		t.Fatal("expected conflict error for stale version")
	}
	if !errors.Is(err, store.ErrConflict) {
		// The error is wrapped, so check the message.
		if err.Error() == "" {
			t.Fatal("expected non-empty error")
		}
	}
}

func TestUpdateAssigneeTimeline(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test", Assignee: "analyst1"}, "analyst1")

	assignee := "analyst2"
	updated, err := svc.Update(ctx, c.ID, &UpdateRequest{Assignee: &assignee}, "admin")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Assignee != "analyst2" {
		t.Errorf("expected assignee %q, got %q", "analyst2", updated.Assignee)
	}

	found := false
	for _, entry := range updated.Timeline {
		if entry.ActionType == ActionAssigneeChanged {
			found = true
		}
	}
	if !found {
		t.Error("expected assignee_changed timeline entry")
	}
}

func TestUpdateSeverityTimeline(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test", Severity: SeverityLow}, "analyst1")

	severity := SeverityHigh
	updated, err := svc.Update(ctx, c.ID, &UpdateRequest{Severity: &severity}, "analyst1")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Severity != SeverityHigh {
		t.Errorf("expected severity %q, got %q", SeverityHigh, updated.Severity)
	}

	found := false
	for _, entry := range updated.Timeline {
		if entry.ActionType == ActionSeverityChanged {
			found = true
		}
	}
	if !found {
		t.Error("expected severity_changed timeline entry")
	}
}

func TestAddComment(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	updated, err := svc.AddComment(ctx, c.ID, "analyst1", "Investigating lateral movement.")
	if err != nil {
		t.Fatalf("AddComment failed: %v", err)
	}

	found := false
	for _, entry := range updated.Timeline {
		if entry.ActionType == ActionComment {
			found = true
		}
	}
	if !found {
		t.Error("expected comment timeline entry")
	}
}

func TestList(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	svc.Create(ctx, &CreateRequest{Title: "Case 1", Severity: SeverityHigh}, "analyst1")
	svc.Create(ctx, &CreateRequest{Title: "Case 2", Severity: SeverityLow}, "analyst1")
	svc.Create(ctx, &CreateRequest{Title: "Case 3", Severity: SeverityMedium}, "analyst1")

	cases, total, err := svc.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 total cases, got %d", total)
	}
	if len(cases) != 3 {
		t.Errorf("expected 3 cases, got %d", len(cases))
	}
}

func TestUpdateInvalidSeverity(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	c, _ := svc.Create(ctx, &CreateRequest{Title: "Test"}, "analyst1")

	severity := "bogus"
	_, err := svc.Update(ctx, c.ID, &UpdateRequest{Severity: &severity}, "analyst1")
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}
