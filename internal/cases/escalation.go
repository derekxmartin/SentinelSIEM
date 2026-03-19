package cases

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// AlertBackend is the interface for fetching and updating alert documents.
type AlertBackend interface {
	GetDocVersioned(ctx context.Context, index, id string) (*store.VersionedDoc, error)
	UpdateFields(ctx context.Context, index, id string, fields map[string]any) error
	SearchRaw(ctx context.Context, index string, body map[string]any) (*store.SearchRawResult, error)
}

// EscalationService handles alert-to-case escalation.
type EscalationService struct {
	caseSvc      *Service
	alertBackend AlertBackend
	alertIndex   string // e.g. "akeso-alerts-*"
}

// NewEscalationService creates a new escalation service.
func NewEscalationService(caseSvc *Service, alertBackend AlertBackend, alertIndex string) *EscalationService {
	return &EscalationService{
		caseSvc:      caseSvc,
		alertBackend: alertBackend,
		alertIndex:   alertIndex,
	}
}

// EscalateRequest holds the parameters for alert escalation.
type EscalateRequest struct {
	AlertIDs []string `json:"alert_ids"`
	Assignee string   `json:"assignee,omitempty"`
	Title    string   `json:"title,omitempty"` // Override auto-generated title.
}

// EscalateResult holds the result of an escalation.
type EscalateResult struct {
	Case         *Case    `json:"case"`
	AlertsLinked int      `json:"alerts_linked"`
	Errors       []string `json:"errors,omitempty"`
}

// alertDoc represents the fields we extract from an alert document.
type alertDoc struct {
	Event   *common.EventFields   `json:"event,omitempty"`
	Rule    *common.RuleFields    `json:"rule,omitempty"`
	Threat  *common.ThreatFields  `json:"threat,omitempty"`
	// Full ECS event for observable extraction.
	raw *common.ECSEvent
}

// Escalate creates a new case from one or more alerts.
// Auto-populates title, severity, observables, and MITRE tags from the alerts.
func (es *EscalationService) Escalate(ctx context.Context, req *EscalateRequest, author string) (*EscalateResult, error) {
	if len(req.AlertIDs) == 0 {
		return nil, fmt.Errorf("at least one alert ID is required")
	}

	// Fetch all alert documents.
	var alerts []alertDoc
	var ecsEvents []*common.ECSEvent
	var severities []string
	var allTags []string
	var errors []string

	for _, alertID := range req.AlertIDs {
		vdoc, err := es.alertBackend.GetDocVersioned(ctx, es.alertIndex, alertID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("alert %s: %v", alertID, err))
			continue
		}

		var event common.ECSEvent
		if err := json.Unmarshal(vdoc.Source, &event); err != nil {
			errors = append(errors, fmt.Sprintf("alert %s: decode error: %v", alertID, err))
			continue
		}

		ad := alertDoc{
			Event: event.Event,
			Rule:  event.Rule,
			Threat: event.Threat,
			raw:   &event,
		}
		alerts = append(alerts, ad)
		ecsEvents = append(ecsEvents, &event)

		// Collect severity from rule.
		if event.Rule != nil && event.Rule.Severity != "" {
			severities = append(severities, mapRuleSeverity(event.Rule.Severity))
		}

		// Collect MITRE tags from rule.
		if event.Rule != nil {
			for _, tag := range event.Rule.Tags {
				allTags = append(allTags, tag)
			}
		}
	}

	if len(alerts) == 0 {
		return nil, fmt.Errorf("no valid alerts found: %s", strings.Join(errors, "; "))
	}

	// Auto-generate title from the first alert's rule name.
	title := req.Title
	if title == "" {
		if alerts[0].Rule != nil && alerts[0].Rule.Name != "" {
			title = alerts[0].Rule.Name
			if len(alerts) > 1 {
				title = fmt.Sprintf("%s (+%d related alerts)", title, len(alerts)-1)
			}
		} else {
			title = fmt.Sprintf("Escalated alert(s) — %d alert(s)", len(alerts))
		}
	}

	// Determine highest severity.
	severity := HighestSeverity(severities)

	// Extract and deduplicate observables from all alert events.
	var allObs []Observable
	for i, event := range ecsEvents {
		alertID := req.AlertIDs[i]
		obs := ExtractObservables(event, alertID)
		allObs = append(allObs, obs...)
	}
	allObs = DeduplicateObservables(allObs)

	// Deduplicate tags.
	allTags = deduplicateStrings(allTags)

	// Create the case.
	caseReq := &CreateRequest{
		Title:       title,
		Severity:    severity,
		Assignee:    req.Assignee,
		AlertIDs:    req.AlertIDs[:len(alerts)], // Only include successfully fetched alerts.
		Observables: allObs,
		Tags:        allTags,
	}

	newCase, err := es.caseSvc.Create(ctx, caseReq, author)
	if err != nil {
		return nil, fmt.Errorf("creating case: %w", err)
	}

	// Update alert documents with escalation status and case back-reference.
	for _, alertID := range req.AlertIDs[:len(alerts)] {
		if err := es.markAlertEscalated(ctx, alertID, newCase.ID); err != nil {
			errors = append(errors, fmt.Sprintf("marking alert %s: %v", alertID, err))
		}
	}

	return &EscalateResult{
		Case:         newCase,
		AlertsLinked: len(alerts),
		Errors:       errors,
	}, nil
}

// markAlertEscalated updates an alert document with escalation metadata.
func (es *EscalationService) markAlertEscalated(ctx context.Context, alertID, caseID string) error {
	fields := map[string]any{
		"event": map[string]any{
			"outcome": "escalated",
		},
		"case_id": caseID,
	}
	return es.alertBackend.UpdateFields(ctx, es.alertIndex, alertID, fields)
}

// mapRuleSeverity maps Sigma severity levels to case severity levels.
func mapRuleSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// deduplicateStrings removes duplicate strings, preserving order.
func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, s)
	}
	return result
}

// severityFromECS maps ECS numeric severity to case severity string.
func severityFromECS(sev int) string {
	switch {
	case sev >= 5:
		return SeverityCritical
	case sev >= 4:
		return SeverityHigh
	case sev >= 3:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// EscalateToExisting merges additional alerts into an existing case.
func (es *EscalationService) EscalateToExisting(ctx context.Context, caseID string, alertIDs []string, author string) (*Case, error) {
	if len(alertIDs) == 0 {
		return nil, fmt.Errorf("at least one alert ID is required")
	}

	c, err := es.caseSvc.Get(ctx, caseID)
	if err != nil {
		return nil, err
	}

	seqNo := *c.SeqNo
	primaryTerm := *c.PrimaryTerm

	now := time.Now().UTC()
	var newObs []Observable

	for _, alertID := range alertIDs {
		// Skip if alert already linked.
		alreadyLinked := false
		for _, existing := range c.AlertIDs {
			if existing == alertID {
				alreadyLinked = true
				break
			}
		}
		if alreadyLinked {
			continue
		}

		vdoc, err := es.alertBackend.GetDocVersioned(ctx, es.alertIndex, alertID)
		if err != nil {
			continue
		}

		var event common.ECSEvent
		if err := json.Unmarshal(vdoc.Source, &event); err != nil {
			continue
		}

		c.AlertIDs = append(c.AlertIDs, alertID)
		obs := ExtractObservables(&event, alertID)
		newObs = append(newObs, obs...)

		// Collect tags.
		if event.Rule != nil {
			for _, tag := range event.Rule.Tags {
				c.Tags = deduplicateStrings(append(c.Tags, tag))
			}
		}

		// Mark alert as escalated.
		es.markAlertEscalated(ctx, alertID, caseID)
	}

	// Merge observables.
	c.Observables = MergeObservables(c.Observables, newObs)

	// Log merge to timeline.
	content, _ := json.Marshal(map[string]any{"alert_ids": alertIDs})
	c.Timeline = append(c.Timeline, TimelineEntry{
		Timestamp:  now,
		Author:     author,
		ActionType: ActionAlertMerged,
		Content:    content,
	})
	c.UpdatedAt = now

	// Strip version metadata before marshaling.
	c.SeqNo = nil
	c.PrimaryTerm = nil

	doc, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshaling case: %w", err)
	}

	if err := es.caseSvc.backend.IndexDocIfMatch(ctx, es.caseSvc.index, caseID, doc, seqNo, primaryTerm); err != nil {
		return nil, fmt.Errorf("updating case: %w", err)
	}

	return c, nil
}
