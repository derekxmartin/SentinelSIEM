package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// failNIndexer fails the first N calls to BulkIndex, then succeeds.
type failNIndexer struct {
	mu        sync.Mutex
	failCount int
	calls     int
	indexed   map[string][]common.ECSEvent
}

func newFailNIndexer(failCount int) *failNIndexer {
	return &failNIndexer{
		failCount: failCount,
		indexed:   make(map[string][]common.ECSEvent),
	}
}

func (f *failNIndexer) BulkIndex(_ context.Context, index string, events []common.ECSEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failCount {
		return fmt.Errorf("transient error (call %d)", f.calls)
	}
	f.indexed[index] = append(f.indexed[index], events...)
	return nil
}

func (f *failNIndexer) totalIndexed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, events := range f.indexed {
		total += len(events)
	}
	return total
}

func (f *failNIndexer) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// mockDLQSender tracks alerts sent to the DLQ.
type mockDLQSender struct {
	mu    sync.Mutex
	items []dlqItem
}

type dlqItem struct {
	Index      string
	Data       json.RawMessage
	Err        error
	RetryCount int
}

func (m *mockDLQSender) SendAlert(index string, data json.RawMessage, err error, retryCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, dlqItem{Index: index, Data: data, Err: err, RetryCount: retryCount})
}

func (m *mockDLQSender) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

func TestRetryQueueSuccessOnRetry(t *testing.T) {
	// Fail first call (retry attempt 2), succeed on 2nd call (retry attempt 3).
	indexer := newFailNIndexer(1)

	rq := NewRetryQueue(indexer, nil,
		WithMaxRetries(3),
		WithBaseDelay(50*time.Millisecond),
		WithRetryInterval(30*time.Millisecond),
	)

	events := []common.ECSEvent{
		{Timestamp: time.Now(), SourceType: "test"},
	}
	rq.Enqueue("test-alerts-2026.03.17", events, fmt.Errorf("initial failure"))

	// Wait for retries to process.
	time.Sleep(500 * time.Millisecond)
	rq.Stop()

	if indexer.totalIndexed() != 1 {
		t.Errorf("expected 1 alert indexed after retry, got %d", indexer.totalIndexed())
	}
}

func TestRetryQueueExhaustedToDLQ(t *testing.T) {
	// Always fail.
	indexer := newFailNIndexer(100)
	dlqSender := &mockDLQSender{}

	rq := NewRetryQueue(indexer, dlqSender,
		WithMaxRetries(3),
		WithBaseDelay(20*time.Millisecond),
		WithMaxDelay(50*time.Millisecond),
		WithRetryInterval(15*time.Millisecond),
	)

	events := []common.ECSEvent{
		{Timestamp: time.Now(), SourceType: "test"},
	}
	rq.Enqueue("test-alerts-2026.03.17", events, fmt.Errorf("persistent failure"))

	// Wait for all retries to exhaust.
	time.Sleep(500 * time.Millisecond)
	rq.Stop()

	if dlqSender.count() != 1 {
		t.Errorf("expected 1 alert sent to DLQ, got %d", dlqSender.count())
	}

	if indexer.totalIndexed() != 0 {
		t.Errorf("expected 0 alerts indexed, got %d", indexer.totalIndexed())
	}
}

func TestRetryQueueNoDLQSender(t *testing.T) {
	// Always fail, no DLQ configured.
	indexer := newFailNIndexer(100)

	rq := NewRetryQueue(indexer, nil,
		WithMaxRetries(2),
		WithBaseDelay(20*time.Millisecond),
		WithRetryInterval(15*time.Millisecond),
	)

	events := []common.ECSEvent{
		{Timestamp: time.Now(), SourceType: "test"},
	}
	rq.Enqueue("test-alerts-2026.03.17", events, fmt.Errorf("persistent failure"))

	// Should complete without panic even without DLQ.
	time.Sleep(300 * time.Millisecond)
	rq.Stop()
}

func TestRetryQueueDrainOnStop(t *testing.T) {
	// Never retry (very long delay), stop should drain to DLQ.
	indexer := newFailNIndexer(100)
	dlqSender := &mockDLQSender{}

	rq := NewRetryQueue(indexer, dlqSender,
		WithMaxRetries(3),
		WithBaseDelay(1*time.Hour),    // won't retry naturally
		WithRetryInterval(1*time.Hour), // won't process naturally
	)

	events := []common.ECSEvent{
		{Timestamp: time.Now(), SourceType: "test1"},
		{Timestamp: time.Now(), SourceType: "test2"},
	}
	rq.Enqueue("test-alerts-2026.03.17", events, fmt.Errorf("queued"))

	// Stop immediately — should drain to DLQ.
	rq.Stop()

	if dlqSender.count() != 2 {
		t.Errorf("expected 2 alerts sent to DLQ on drain, got %d", dlqSender.count())
	}
}

func TestRetryQueueBackoff(t *testing.T) {
	rq := &RetryQueue{
		baseDelay: 1 * time.Second,
		maxDelay:  10 * time.Second,
	}

	// attempt 1 → 1s, attempt 2 → 2s, attempt 3 → 4s, attempt 4 → 8s, attempt 5 → 10s (capped)
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 10 * time.Second}, // capped at maxDelay
	}

	for _, tc := range tests {
		got := rq.backoffDelay(tc.attempt)
		if got != tc.expected {
			t.Errorf("backoffDelay(%d) = %v, want %v", tc.attempt, got, tc.expected)
		}
	}
}

func TestRetryQueueLen(t *testing.T) {
	indexer := newFailNIndexer(100)

	rq := NewRetryQueue(indexer, nil,
		WithMaxRetries(3),
		WithBaseDelay(1*time.Hour),
		WithRetryInterval(1*time.Hour),
	)

	if rq.Len() != 0 {
		t.Fatalf("expected empty queue, got %d", rq.Len())
	}

	events := []common.ECSEvent{{Timestamp: time.Now()}}
	rq.Enqueue("idx", events, fmt.Errorf("err"))

	if rq.Len() != 1 {
		t.Errorf("expected 1 item in queue, got %d", rq.Len())
	}

	rq.Stop()
}

func TestRetryQueueConcurrentEnqueue(t *testing.T) {
	indexer := newFailNIndexer(100)
	dlqSender := &mockDLQSender{}
	var enqueued atomic.Int64

	rq := NewRetryQueue(indexer, dlqSender,
		WithMaxRetries(2),
		WithBaseDelay(10*time.Millisecond),
		WithRetryInterval(10*time.Millisecond),
	)

	// Enqueue from multiple goroutines.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			events := []common.ECSEvent{{Timestamp: time.Now(), SourceType: fmt.Sprintf("src-%d", n)}}
			rq.Enqueue(fmt.Sprintf("idx-%d", n), events, fmt.Errorf("err-%d", n))
			enqueued.Add(1)
		}(i)
	}
	wg.Wait()

	// Wait for retries to exhaust.
	time.Sleep(500 * time.Millisecond)
	rq.Stop()

	if dlqSender.count() != 10 {
		t.Errorf("expected 10 alerts in DLQ, got %d", dlqSender.count())
	}
}
