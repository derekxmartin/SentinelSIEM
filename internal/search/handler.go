package search

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

const searchTimeout = 10 * time.Second

// Handler serves POST /api/v1/search.
type Handler struct {
	searcher Searcher
	rules    []*correlate.SigmaRule
	prefix   string // ES index prefix, e.g. "akeso"
}

// NewHandler creates a global search handler.
func NewHandler(searcher Searcher, rules []*correlate.SigmaRule, prefix string) *Handler {
	return &Handler{
		searcher: searcher,
		rules:    rules,
		prefix:   prefix,
	}
}

// HandleSearch handles POST /api/v1/search requests.
func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query field is required")
		return
	}
	if req.EntityType == "" {
		req.EntityType = EntityFreeText
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
	defer cancel()

	var resp SearchResponse
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fan-out: events
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := h.searchEvents(ctx, req)
		if err != nil {
			log.Printf("[search] events query error: %v", err)
			return
		}
		mu.Lock()
		resp.Events = result
		mu.Unlock()
	}()

	// Fan-out: alerts
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := h.searchAlerts(ctx, req)
		if err != nil {
			log.Printf("[search] alerts query error: %v", err)
			return
		}
		mu.Lock()
		resp.Alerts = result
		mu.Unlock()
	}()

	// Fan-out: cases
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := h.searchCases(ctx, req)
		if err != nil {
			log.Printf("[search] cases query error: %v", err)
			return
		}
		mu.Lock()
		resp.Cases = result
		mu.Unlock()
	}()

	// Fan-out: host scores (IP searches only)
	if req.EntityType == EntityIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := h.searchHostScores(ctx, req)
			if err != nil {
				log.Printf("[search] host scores query error: %v", err)
				return
			}
			mu.Lock()
			resp.HostScores = result
			mu.Unlock()
		}()
	}

	// Rules search (in-memory, synchronous — fast enough)
	resp.Rules = SearchRules(h.rules, req.Query, 10)

	wg.Wait()

	// Ensure non-nil slices for clean JSON.
	if resp.Alerts.Items == nil {
		resp.Alerts.Items = []AlertResult{}
	}
	if resp.Cases.Items == nil {
		resp.Cases.Items = []CaseResult{}
	}
	if resp.Events.BySource == nil {
		resp.Events.BySource = map[string]int{}
	}
	if resp.Rules == nil {
		resp.Rules = []RuleResult{}
	}

	resp.TookMs = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) searchEvents(ctx context.Context, req SearchRequest) (EventResults, error) {
	body := BuildEventQuery(req.Query, req.EntityType, req.TimeFrom, req.TimeTo)
	index := h.prefix + "-events-*"
	result, err := h.searcher.SearchRaw(ctx, index, body)
	if err != nil {
		return EventResults{}, err
	}

	events := EventResults{
		Total:    result.Total,
		BySource: map[string]int{},
	}

	// Parse aggregation buckets.
	if result.Aggs != nil {
		var aggs struct {
			BySource struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_source"`
		}
		if err := json.Unmarshal(result.Aggs, &aggs); err == nil {
			for _, b := range aggs.BySource.Buckets {
				events.BySource[b.Key] = b.DocCount
			}
		}
	}

	return events, nil
}

func (h *Handler) searchAlerts(ctx context.Context, req SearchRequest) (AlertResults, error) {
	body := BuildAlertQuery(req.Query, req.EntityType, req.TimeFrom, req.TimeTo)
	index := h.prefix + "-alerts-*"
	result, err := h.searcher.SearchRaw(ctx, index, body)
	if err != nil {
		return AlertResults{}, err
	}

	alerts := AlertResults{Total: result.Total}
	for _, hit := range result.Hits {
		var doc struct {
			ID        string `json:"_id"`
			Timestamp string `json:"@timestamp"`
			Rule      struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"rule"`
			Event struct {
				Severity int `json:"severity"`
			} `json:"event"`
		}
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}
		severity := doc.Rule.Severity
		if severity == "" {
			severity = severityFromInt(doc.Event.Severity)
		}
		alerts.Items = append(alerts.Items, AlertResult{
			ID:        doc.ID,
			Severity:  severity,
			RuleName:  doc.Rule.Name,
			Timestamp: doc.Timestamp,
		})
	}
	return alerts, nil
}

func (h *Handler) searchCases(ctx context.Context, req SearchRequest) (CaseResults, error) {
	body := BuildCaseQuery(req.Query, req.EntityType)
	index := h.prefix + "-cases"
	result, err := h.searcher.SearchRaw(ctx, index, body)
	if err != nil {
		return CaseResults{}, err
	}

	cases := CaseResults{Total: result.Total}
	for _, hit := range result.Hits {
		var doc struct {
			ID       string `json:"_id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
		}
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}
		cases.Items = append(cases.Items, CaseResult{
			ID:       doc.ID,
			Title:    doc.Title,
			Severity: doc.Severity,
			Status:   doc.Status,
		})
	}
	return cases, nil
}

func (h *Handler) searchHostScores(ctx context.Context, req SearchRequest) ([]HostScoreResult, error) {
	body := BuildHostScoreQuery(req.Query)
	index := h.prefix + "-ndr-host-scores"
	result, err := h.searcher.SearchRaw(ctx, index, body)
	if err != nil {
		return nil, err
	}

	var scores []HostScoreResult
	for _, hit := range result.Hits {
		var doc struct {
			HostIP    string `json:"host.ip"`
			HostName  string `json:"host.name"`
			Threat    int    `json:"ndr.host_score.threat"`
			Certainty int    `json:"ndr.host_score.certainty"`
			Quadrant  string `json:"ndr.host_score.quadrant"`
		}
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}
		scores = append(scores, HostScoreResult{
			HostIP:    doc.HostIP,
			HostName:  doc.HostName,
			Threat:    doc.Threat,
			Certainty: doc.Certainty,
			Quadrant:  doc.Quadrant,
		})
	}
	return scores, nil
}

func severityFromInt(s int) string {
	switch {
	case s >= 4:
		return "critical"
	case s == 3:
		return "high"
	case s == 2:
		return "medium"
	default:
		return "low"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
