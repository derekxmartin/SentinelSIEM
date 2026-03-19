package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// HostScoreIndexer is the interface for upserting NDR host scores.
// The dedicated index stores the latest score per host IP (not time-series).
type HostScoreIndexer interface {
	UpsertHostScore(ctx context.Context, event *common.ECSEvent) error
}

// Verify Store implements HostScoreIndexer at compile time.
var _ HostScoreIndexer = (*Store)(nil)

// HostScoreDocument is the Elasticsearch document written to the dedicated
// akeso-ndr-host-scores index. Each document is keyed by host IP so that
// subsequent upserts replace the previous score rather than creating duplicates.
type HostScoreDocument struct {
	HostIP    string    `json:"host.ip"`
	HostName  string    `json:"host.name,omitempty"`
	Threat    int       `json:"ndr.host_score.threat"`
	Certainty int       `json:"ndr.host_score.certainty"`
	Quadrant  string    `json:"ndr.host_score.quadrant"`
	UserName  string    `json:"user.name,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// hostScoreIndexName returns the dedicated host score index name.
func (s *Store) hostScoreIndexName() string {
	return s.prefix + "-ndr-host-scores"
}

// UpsertHostScore indexes or updates a host score document in the dedicated
// akeso-ndr-host-scores index, keyed by host IP. If a document for this
// host IP already exists, it is replaced with the latest score.
func (s *Store) UpsertHostScore(ctx context.Context, event *common.ECSEvent) error {
	if event == nil {
		return fmt.Errorf("host score upsert: nil event")
	}
	if event.NDR == nil || event.NDR.HostScore == nil {
		return fmt.Errorf("host score upsert: missing ndr.host_score fields")
	}

	// Extract host IP for the document ID.
	hostIP := extractHostIP(event)
	if hostIP == "" {
		return fmt.Errorf("host score upsert: no host IP available")
	}

	doc := HostScoreDocument{
		HostIP:    hostIP,
		Threat:    event.NDR.HostScore.Threat,
		Certainty: event.NDR.HostScore.Certainty,
		Quadrant:  event.NDR.HostScore.Quadrant,
		UpdatedAt: event.Timestamp,
	}

	// Include optional fields if present.
	if event.Host != nil {
		doc.HostName = event.Host.Name
	}
	if event.User != nil {
		doc.UserName = event.User.Name
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("host score upsert: marshal: %w", err)
	}

	// Use the host IP as the document ID for upsert semantics.
	// ES Index API with a doc ID creates or replaces the document.
	indexName := s.hostScoreIndexName()
	docID := hostIP

	res, err := s.client.Index(
		indexName,
		bytes.NewReader(body),
		s.client.Index.WithContext(ctx),
		s.client.Index.WithDocumentID(docID),
	)
	if err != nil {
		return fmt.Errorf("host score upsert: index request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("host score upsert: %s", res.String())
	}

	return nil
}

// extractHostIP gets the host IP from the event, checking host.ip first,
// then falling back to source.ip.
func extractHostIP(event *common.ECSEvent) string {
	if event.Host != nil && len(event.Host.IP) > 0 {
		return event.Host.IP[0]
	}
	if event.Source != nil && event.Source.IP != "" {
		return event.Source.IP
	}
	return ""
}

// EnsureHostScoreIndex creates the dedicated host score index with appropriate
// mappings if it doesn't already exist. Unlike time-series event indices, this
// index is not date-rotated and has no ILM policy.
func (s *Store) EnsureHostScoreIndex(ctx context.Context) error {
	indexName := s.hostScoreIndexName()

	// Check if index already exists.
	res, err := s.client.Indices.Exists([]string{indexName},
		s.client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("checking host score index: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		// Index exists, nothing to do.
		return nil
	}

	// Create with mappings.
	mappings := hostScoreIndexMappings()
	body, err := json.Marshal(mappings)
	if err != nil {
		return fmt.Errorf("marshaling host score index mappings: %w", err)
	}

	res, err = s.client.Indices.Create(
		indexName,
		s.client.Indices.Create.WithContext(ctx),
		s.client.Indices.Create.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating host score index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("host score index creation: %s", res.String())
	}

	return nil
}

// hostScoreIndexMappings returns the index creation body with field mappings
// for the dedicated host score index.
func hostScoreIndexMappings() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"host.ip":                  mapping("ip"),
				"host.name":               mapping("keyword"),
				"ndr.host_score.threat":    mapping("integer"),
				"ndr.host_score.certainty": mapping("integer"),
				"ndr.host_score.quadrant":  mapping("keyword"),
				"user.name":               mapping("keyword"),
				"updated_at":              mapping("date"),
			},
		},
	}
}
