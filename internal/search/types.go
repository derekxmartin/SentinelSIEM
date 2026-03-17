package search

import (
	"context"
	"encoding/json"
)

// Entity type constants sent by the frontend.
const (
	EntityIP          = "ip"
	EntitySHA256      = "sha256"
	EntitySHA1        = "sha1"
	EntityMD5JA3      = "md5_ja3"
	EntityCommunityID = "community_id"
	EntityDomain      = "domain"
	EntityPath        = "path"
	EntityCaseID      = "case_id"
	EntityAlertID     = "alert_id"
	EntityUsername    = "username"
	EntityFreeText   = "freetext"
)

// Searcher is the interface for executing Elasticsearch queries.
type Searcher interface {
	SearchRaw(ctx context.Context, index string, body map[string]any) (*SearchRawResult, error)
}

// SearchRawResult mirrors the store result to avoid import cycles.
type SearchRawResult struct {
	Total  int
	Hits   []json.RawMessage
	Aggs   json.RawMessage
	TookMs int
}

// SearchRequest is the JSON body for POST /api/v1/search.
type SearchRequest struct {
	Query      string `json:"query"`
	EntityType string `json:"entity_type"`
	TimeFrom   string `json:"time_from,omitempty"`
	TimeTo     string `json:"time_to,omitempty"`
}

// SearchResponse is the JSON response for POST /api/v1/search.
type SearchResponse struct {
	HostScores []HostScoreResult `json:"host_scores,omitempty"`
	Alerts     AlertResults      `json:"alerts"`
	Cases      CaseResults       `json:"cases"`
	Events     EventResults      `json:"events"`
	Rules      []RuleResult      `json:"rules"`
	TookMs     int64             `json:"took_ms"`
}

// HostScoreResult represents an NDR host score match.
type HostScoreResult struct {
	HostIP    string `json:"host_ip"`
	HostName  string `json:"host_name,omitempty"`
	Threat    int    `json:"threat"`
	Certainty int    `json:"certainty"`
	Quadrant  string `json:"quadrant"`
}

// AlertResults holds alert search results.
type AlertResults struct {
	Total int           `json:"total"`
	Items []AlertResult `json:"items"`
}

// AlertResult represents a single alert match.
type AlertResult struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	RuleName  string `json:"rule_name"`
	Timestamp string `json:"timestamp"`
}

// CaseResults holds case search results.
type CaseResults struct {
	Total int          `json:"total"`
	Items []CaseResult `json:"items"`
}

// CaseResult represents a single case match.
type CaseResult struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

// EventResults holds event search results (counts only, no documents).
type EventResults struct {
	Total    int            `json:"total"`
	BySource map[string]int `json:"by_source"`
}

// RuleResult represents a matching Sigma rule.
type RuleResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}
