package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// mockDLQIndexer captures bulk-indexed events for test assertions.
type mockDLQIndexer struct {
	mu      sync.Mutex
	indexed map[string][]common.ECSEvent
	err     error // if set, BulkIndex returns this error
}

func newMockDLQIndexer() *mockDLQIndexer {
	return &mockDLQIndexer{indexed: make(map[string][]common.ECSEvent)}
}

func (m *mockDLQIndexer) BulkIndex(_ context.Context, index string, events []common.ECSEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.indexed[index] = append(m.indexed[index], events...)
	return nil
}

func (m *mockDLQIndexer) totalIndexed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, events := range m.indexed {
		total += len(events)
	}
	return total
}

func TestDLQSendAndFlush(t *testing.T) {
	indexer := newMockDLQIndexer()
	dlq := NewDeadLetterQueue(indexer, "test",
		WithDLQFlushInterval(50*time.Millisecond),
		WithDLQMaxBufferSize(100),
	)
	defer dlq.Stop()

	// Send a malformed event.
	raw := json.RawMessage(`{"bad": "event"}`)
	dlq.SendRaw(raw, fmt.Errorf("invalid source_type"))

	// Send an index failure.
	dlq.Send(DLQReasonIndexFailure, "akeso_edr", json.RawMessage(`{"edr": true}`),
		fmt.Errorf("bulk index timeout"), 0, "test-events-edr-2026.03.17")

	// Wait for flush.
	time.Sleep(200 * time.Millisecond)

	total := indexer.totalIndexed()
	if total != 2 {
		t.Errorf("expected 2 DLQ entries indexed, got %d", total)
	}
}

func TestDLQMaxBufferFlush(t *testing.T) {
	indexer := newMockDLQIndexer()
	dlq := NewDeadLetterQueue(indexer, "test",
		WithDLQFlushInterval(1*time.Hour), // long interval, won't trigger
		WithDLQMaxBufferSize(5),
	)
	defer dlq.Stop()

	// Send enough events to trigger a forced flush.
	for i := 0; i < 5; i++ {
		dlq.SendRaw(json.RawMessage(fmt.Sprintf(`{"i": %d}`, i)),
			fmt.Errorf("bad event %d", i))
	}

	// Give a moment for the forced flush to complete.
	time.Sleep(100 * time.Millisecond)

	total := indexer.totalIndexed()
	if total < 5 {
		t.Errorf("expected at least 5 DLQ entries after max buffer flush, got %d", total)
	}
}

func TestDLQStopFlushesRemaining(t *testing.T) {
	indexer := newMockDLQIndexer()
	dlq := NewDeadLetterQueue(indexer, "test",
		WithDLQFlushInterval(1*time.Hour), // long interval
		WithDLQMaxBufferSize(1000),
	)

	// Send events but don't wait for periodic flush.
	dlq.SendRaw(json.RawMessage(`{"a": 1}`), fmt.Errorf("err1"))
	dlq.SendRaw(json.RawMessage(`{"b": 2}`), fmt.Errorf("err2"))

	// Verify they're still buffered.
	if dlq.Len() != 2 {
		t.Fatalf("expected 2 buffered entries, got %d", dlq.Len())
	}

	// Stop should flush remaining.
	dlq.Stop()

	total := indexer.totalIndexed()
	if total != 2 {
		t.Errorf("expected 2 DLQ entries after Stop, got %d", total)
	}
}

func TestDLQFlushError(t *testing.T) {
	indexer := newMockDLQIndexer()
	indexer.err = fmt.Errorf("ES unavailable")

	dlq := NewDeadLetterQueue(indexer, "test",
		WithDLQFlushInterval(50*time.Millisecond),
	)

	// Send an event — flush will fail.
	dlq.SendRaw(json.RawMessage(`{"lost": true}`), fmt.Errorf("normalization failed"))

	// Wait for flush attempt.
	time.Sleep(200 * time.Millisecond)

	// Buffer should be empty (flushed, even though indexing failed).
	if dlq.Len() != 0 {
		t.Errorf("expected buffer to be drained after failed flush, got %d", dlq.Len())
	}

	dlq.Stop()
}

func TestDLQSendAlert(t *testing.T) {
	indexer := newMockDLQIndexer()
	dlq := NewDeadLetterQueue(indexer, "test",
		WithDLQFlushInterval(50*time.Millisecond),
	)
	defer dlq.Stop()

	// SendAlert should create an entry with DLQReasonAlertFailure.
	dlq.SendAlert("test-alerts-2026.03.17",
		json.RawMessage(`{"alert": true}`),
		fmt.Errorf("index timeout"),
		3)

	time.Sleep(200 * time.Millisecond)

	total := indexer.totalIndexed()
	if total != 1 {
		t.Errorf("expected 1 DLQ entry for alert, got %d", total)
	}
}

func TestDLQDefaultPrefix(t *testing.T) {
	indexer := newMockDLQIndexer()
	dlq := NewDeadLetterQueue(indexer, "",
		WithDLQFlushInterval(50*time.Millisecond),
	)

	dlq.SendRaw(json.RawMessage(`{}`), fmt.Errorf("test"))
	time.Sleep(200 * time.Millisecond)
	dlq.Stop()

	// Check that the default "akeso" prefix was used.
	indexer.mu.Lock()
	defer indexer.mu.Unlock()
	found := false
	for idx := range indexer.indexed {
		if len(idx) > 0 && idx[:8] == "akeso" {
			found = true
		}
	}
	if !found {
		t.Error("expected index with 'akeso' prefix")
	}
}
