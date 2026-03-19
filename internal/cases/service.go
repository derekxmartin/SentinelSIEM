package cases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/store"
)

// Backend is the interface for case storage operations.
type Backend interface {
	IndexDoc(ctx context.Context, index, id string, doc []byte) error
	GetDocVersioned(ctx context.Context, index, id string) (*store.VersionedDoc, error)
	IndexDocIfMatch(ctx context.Context, index, id string, doc []byte, seqNo, primaryTerm int) error
	SearchRaw(ctx context.Context, index string, body map[string]any) (*store.SearchRawResult, error)
}

// Service manages case CRUD operations with status validation and
// optimistic concurrency control.
type Service struct {
	backend Backend
	index   string
}

// NewService creates a new case management service.
func NewService(backend Backend, index string) *Service {
	return &Service{backend: backend, index: index}
}

// CreateRequest holds the fields for creating a new case.
type CreateRequest struct {
	Title       string       `json:"title"`
	Severity    string       `json:"severity"`
	Assignee    string       `json:"assignee"`
	AlertIDs    []string     `json:"alert_ids"`
	Observables []Observable `json:"observables"`
	Tags        []string     `json:"tags"`
}

// UpdateRequest holds optional fields for updating an existing case.
type UpdateRequest struct {
	Title      *string  `json:"title,omitempty"`
	Severity   *string  `json:"severity,omitempty"`
	Assignee   *string  `json:"assignee,omitempty"`
	Status     *string  `json:"status,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Resolution *Resolution `json:"resolution,omitempty"`
	// SeqNo and PrimaryTerm for optimistic concurrency.
	SeqNo       *int `json:"_seq_no,omitempty"`
	PrimaryTerm *int `json:"_primary_term,omitempty"`
}

// CloseRequest holds the required resolution for closing a case.
type CloseRequest struct {
	Resolution Resolution `json:"resolution"`
	// SeqNo and PrimaryTerm for optimistic concurrency.
	SeqNo       *int `json:"_seq_no,omitempty"`
	PrimaryTerm *int `json:"_primary_term,omitempty"`
}

// ListOptions holds filtering and pagination options for listing cases.
type ListOptions struct {
	Status   string
	Severity string
	Assignee string
	Size     int
	From     int
	SortBy   string
	SortDir  string
}

// Create creates a new case with status "new".
func (s *Service) Create(ctx context.Context, req *CreateRequest, author string) (*Case, error) {
	if req.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if req.Severity == "" {
		req.Severity = SeverityLow
	}
	if !IsValidSeverity(req.Severity) {
		return nil, fmt.Errorf("invalid severity: %q", req.Severity)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating case ID: %w", err)
	}

	now := time.Now().UTC()
	c := &Case{
		ID:          hex.EncodeToString(idBytes),
		Title:       req.Title,
		Status:      StatusNew,
		Severity:    req.Severity,
		Assignee:    req.Assignee,
		AlertIDs:    req.AlertIDs,
		Observables: req.Observables,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
		Timeline: []TimelineEntry{
			{
				Timestamp:  now,
				Author:     author,
				ActionType: ActionEscalation,
				Content:    json.RawMessage(`{"message":"Case created"}`),
			},
		},
	}

	// Ensure slices are non-nil for clean JSON.
	if c.AlertIDs == nil {
		c.AlertIDs = []string{}
	}
	if c.Observables == nil {
		c.Observables = []Observable{}
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}

	doc, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshaling case: %w", err)
	}

	if err := s.backend.IndexDoc(ctx, s.index, c.ID, doc); err != nil {
		return nil, fmt.Errorf("storing case: %w", err)
	}

	return c, nil
}

// Get retrieves a case by ID, including version metadata for concurrency control.
func (s *Service) Get(ctx context.Context, id string) (*Case, error) {
	vdoc, err := s.backend.GetDocVersioned(ctx, s.index, id)
	if err != nil {
		return nil, fmt.Errorf("getting case %q: %w", id, err)
	}

	var c Case
	if err := json.Unmarshal(vdoc.Source, &c); err != nil {
		return nil, fmt.Errorf("decoding case: %w", err)
	}

	c.SeqNo = &vdoc.SeqNo
	c.PrimaryTerm = &vdoc.PrimaryTerm
	return &c, nil
}

// Update modifies an existing case with optimistic concurrency control.
func (s *Service) Update(ctx context.Context, id string, req *UpdateRequest, author string) (*Case, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// If caller provided version info, use it; otherwise use what we just read.
	seqNo := *c.SeqNo
	primaryTerm := *c.PrimaryTerm
	if req.SeqNo != nil && req.PrimaryTerm != nil {
		seqNo = *req.SeqNo
		primaryTerm = *req.PrimaryTerm
	}

	// Block non-status updates on closed cases. Status changes (reopens) are still allowed.
	if c.Status == StatusClosed && req.Status == nil {
		return nil, fmt.Errorf("cannot update a closed case; reopen it first")
	}

	now := time.Now().UTC()

	if req.Title != nil && *req.Title != c.Title {
		c.Title = *req.Title
	}

	if req.Severity != nil && *req.Severity != c.Severity {
		if !IsValidSeverity(*req.Severity) {
			return nil, fmt.Errorf("invalid severity: %q", *req.Severity)
		}
		oldSeverity := c.Severity
		c.Severity = *req.Severity
		c.Timeline = append(c.Timeline, TimelineEntry{
			Timestamp:  now,
			Author:     author,
			ActionType: ActionSeverityChanged,
			Content:    json.RawMessage(fmt.Sprintf(`{"from":%q,"to":%q}`, oldSeverity, c.Severity)),
		})
	}

	if req.Assignee != nil && *req.Assignee != c.Assignee {
		oldAssignee := c.Assignee
		c.Assignee = *req.Assignee
		c.Timeline = append(c.Timeline, TimelineEntry{
			Timestamp:  now,
			Author:     author,
			ActionType: ActionAssigneeChanged,
			Content:    json.RawMessage(fmt.Sprintf(`{"from":%q,"to":%q}`, oldAssignee, c.Assignee)),
		})
	}

	if req.Status != nil && *req.Status != c.Status {
		if !CanTransition(c.Status, *req.Status) {
			return nil, fmt.Errorf("invalid status transition: %s → %s", c.Status, *req.Status)
		}

		// Closing requires a resolution (use CloseRequest instead).
		if *req.Status == StatusClosed {
			if req.Resolution == nil {
				return nil, fmt.Errorf("resolution is required when closing a case")
			}
			if !IsValidResolution(req.Resolution.Type) {
				return nil, fmt.Errorf("invalid resolution type: %q", req.Resolution.Type)
			}
			c.Resolution = req.Resolution
			c.ClosedAt = &now
			c.Timeline = append(c.Timeline, TimelineEntry{
				Timestamp:  now,
				Author:     author,
				ActionType: ActionResolution,
				Content:    json.RawMessage(fmt.Sprintf(`{"type":%q,"notes":%q}`, req.Resolution.Type, req.Resolution.Notes)),
			})
		}

		oldStatus := c.Status
		c.Status = *req.Status
		c.Timeline = append(c.Timeline, TimelineEntry{
			Timestamp:  now,
			Author:     author,
			ActionType: ActionStatusChange,
			Content:    json.RawMessage(fmt.Sprintf(`{"from":%q,"to":%q}`, oldStatus, c.Status)),
		})

		// Clear resolution on reopen.
		if *req.Status == StatusInProgress && (oldStatus == StatusResolved || oldStatus == StatusClosed) {
			c.Resolution = nil
			c.ClosedAt = nil
		}
	}

	if req.Tags != nil {
		c.Tags = req.Tags
	}

	c.UpdatedAt = now

	// Strip version metadata before marshaling.
	c.SeqNo = nil
	c.PrimaryTerm = nil

	doc, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshaling case: %w", err)
	}

	if err := s.backend.IndexDocIfMatch(ctx, s.index, id, doc, seqNo, primaryTerm); err != nil {
		return nil, fmt.Errorf("updating case: %w", err)
	}

	return c, nil
}

// Close closes a case with a required resolution.
func (s *Service) Close(ctx context.Context, id string, req *CloseRequest, author string) (*Case, error) {
	if !IsValidResolution(req.Resolution.Type) {
		return nil, fmt.Errorf("invalid resolution type: %q", req.Resolution.Type)
	}

	status := StatusClosed
	updateReq := &UpdateRequest{
		Status:      &status,
		Resolution:  &req.Resolution,
		SeqNo:       req.SeqNo,
		PrimaryTerm: req.PrimaryTerm,
	}

	return s.Update(ctx, id, updateReq, author)
}

// List returns cases matching the given filter/sort/pagination options.
func (s *Service) List(ctx context.Context, opts ListOptions) ([]*Case, int, error) {
	if opts.Size <= 0 {
		opts.Size = 20
	}
	if opts.Size > 200 {
		opts.Size = 200
	}
	if opts.SortBy == "" {
		opts.SortBy = "updated_at"
	}
	if opts.SortDir == "" {
		opts.SortDir = "desc"
	}

	// Build filter clauses.
	filters := []map[string]any{}
	if opts.Status != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"status": opts.Status}})
	}
	if opts.Severity != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"severity": opts.Severity}})
	}
	if opts.Assignee != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"assignee": opts.Assignee}})
	}

	var query map[string]any
	if len(filters) > 0 {
		query = map[string]any{
			"bool": map[string]any{"filter": filters},
		}
	} else {
		query = map[string]any{"match_all": map[string]any{}}
	}

	body := map[string]any{
		"query": query,
		"size":  opts.Size,
		"from":  opts.From,
		"sort":  []map[string]any{{opts.SortBy: map[string]any{"order": opts.SortDir}}},
	}

	result, err := s.backend.SearchRaw(ctx, s.index, body)
	if err != nil {
		return nil, 0, fmt.Errorf("listing cases: %w", err)
	}

	cases := make([]*Case, 0, len(result.Hits))
	for _, hit := range result.Hits {
		var c Case
		if err := json.Unmarshal(hit, &c); err != nil {
			continue
		}
		cases = append(cases, &c)
	}

	return cases, result.Total, nil
}

// AddComment adds a comment to the case timeline.
func (s *Service) AddComment(ctx context.Context, id, author, text string) (*Case, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	seqNo := *c.SeqNo
	primaryTerm := *c.PrimaryTerm

	now := time.Now().UTC()
	c.Timeline = append(c.Timeline, TimelineEntry{
		Timestamp:  now,
		Author:     author,
		ActionType: ActionComment,
		Content:    json.RawMessage(fmt.Sprintf(`{"text":%q}`, text)),
	})
	c.UpdatedAt = now

	c.SeqNo = nil
	c.PrimaryTerm = nil

	doc, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshaling case: %w", err)
	}

	if err := s.backend.IndexDocIfMatch(ctx, s.index, id, doc, seqNo, primaryTerm); err != nil {
		return nil, fmt.Errorf("adding comment: %w", err)
	}

	return c, nil
}

// AddObservable adds a manually-created observable to a case.
func (s *Service) AddObservable(ctx context.Context, id string, obs Observable, author string) (*Case, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	seqNo := *c.SeqNo
	primaryTerm := *c.PrimaryTerm

	now := time.Now().UTC()
	c.Observables = MergeObservables(c.Observables, []Observable{obs})
	c.Timeline = append(c.Timeline, TimelineEntry{
		Timestamp:  now,
		Author:     author,
		ActionType: ActionObservableAdded,
		Content:    json.RawMessage(fmt.Sprintf(`{"type":%q,"value":%q}`, obs.Type, obs.Value)),
	})
	c.UpdatedAt = now

	c.SeqNo = nil
	c.PrimaryTerm = nil

	doc, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshaling case: %w", err)
	}

	if err := s.backend.IndexDocIfMatch(ctx, s.index, id, doc, seqNo, primaryTerm); err != nil {
		return nil, fmt.Errorf("adding observable: %w", err)
	}

	return c, nil
}

// CaseStats holds aggregate metrics for the dashboard.
type CaseStats struct {
	Total      int            `json:"total"`
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"`
}

// Stats returns aggregate case metrics.
func (s *Service) Stats(ctx context.Context) (*CaseStats, error) {
	body := map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_status": map[string]any{
				"terms": map[string]any{"field": "status"},
			},
			"by_severity": map[string]any{
				"terms": map[string]any{"field": "severity"},
			},
		},
	}

	result, err := s.backend.SearchRaw(ctx, s.index, body)
	if err != nil {
		return nil, fmt.Errorf("case stats: %w", err)
	}

	stats := &CaseStats{
		Total:      result.Total,
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
	}

	if result.Aggs != nil {
		var aggs struct {
			ByStatus struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_status"`
			BySeverity struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_severity"`
		}
		if err := json.Unmarshal(result.Aggs, &aggs); err == nil {
			for _, b := range aggs.ByStatus.Buckets {
				stats.ByStatus[b.Key] = b.DocCount
			}
			for _, b := range aggs.BySeverity.Buckets {
				stats.BySeverity[b.Key] = b.DocCount
			}
		}
	}

	return stats, nil
}
