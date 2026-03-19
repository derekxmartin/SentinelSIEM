package sources

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// Backend is the interface for persisting source configs to storage.
type Backend interface {
	IndexDoc(ctx context.Context, index, id string, doc []byte) error
	GetDoc(ctx context.Context, index, id string) ([]byte, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]json.RawMessage, error)
	UpdateDoc(ctx context.Context, index, id string, doc []byte) error
	DeleteDoc(ctx context.Context, index, id string) error
}

// Service manages source configuration CRUD with API key integration.
type Service struct {
	backend  Backend
	keyStore *common.APIKeyStore
	index    string
}

// NewService creates a new source management service.
func NewService(backend Backend, keyStore *common.APIKeyStore, indexName string) *Service {
	return &Service{
		backend:  backend,
		keyStore: keyStore,
		index:    indexName,
	}
}

// Create registers a new source, generates an API key, and persists both.
func (s *Service) Create(ctx context.Context, req *CreateSourceRequest) (*SourceResponse, error) {
	if msg := req.Validate(); msg != "" {
		return nil, fmt.Errorf("validation: %s", msg)
	}

	// Generate source ID.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating source ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// Generate API key with ingest scope for this source.
	keyName := fmt.Sprintf("source-%s-%s", req.Name, id[:8])
	keyResult, err := s.keyStore.Create(ctx, keyName, []string{"ingest"}, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("creating API key: %w", err)
	}

	now := time.Now().UTC()
	src := &SourceConfig{
		ID:            id,
		Name:          req.Name,
		Type:          req.Type,
		Protocol:      req.Protocol,
		Port:          req.Port,
		Parser:        req.Parser,
		ExpectedHosts: req.ExpectedHosts,
		APIKeyID:      keyResult.Key.ID,
		Status:        "active",
		Description:   req.Description,
		Tags:          req.Tags,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	doc, err := json.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("marshaling source: %w", err)
	}

	if err := s.backend.IndexDoc(ctx, s.index, id, doc); err != nil {
		return nil, fmt.Errorf("storing source: %w", err)
	}

	return &SourceResponse{
		Source:       src,
		PlaintextKey: keyResult.PlaintextKey,
	}, nil
}

// Get retrieves a source by ID.
func (s *Service) Get(ctx context.Context, id string) (*SourceConfig, error) {
	doc, err := s.backend.GetDoc(ctx, s.index, id)
	if err != nil {
		return nil, fmt.Errorf("getting source %q: %w", id, err)
	}

	var src SourceConfig
	if err := json.Unmarshal(doc, &src); err != nil {
		return nil, fmt.Errorf("decoding source: %w", err)
	}

	return &src, nil
}

// List returns all sources.
func (s *Service) List(ctx context.Context) ([]*SourceConfig, error) {
	query := map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
		"size":  1000,
		"sort":  []map[string]any{{"name": map[string]any{"order": "asc"}}},
	}

	docs, err := s.backend.SearchDocs(ctx, s.index, query)
	if err != nil {
		return nil, fmt.Errorf("listing sources: %w", err)
	}

	sources := make([]*SourceConfig, 0, len(docs))
	for _, doc := range docs {
		var src SourceConfig
		if err := json.Unmarshal(doc, &src); err != nil {
			continue
		}
		sources = append(sources, &src)
	}

	return sources, nil
}

// Update modifies an existing source config.
func (s *Service) Update(ctx context.Context, id string, req *UpdateSourceRequest) (*SourceConfig, error) {
	src, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if src.Status == "decommissioned" {
		return nil, fmt.Errorf("cannot update decommissioned source")
	}

	// Apply updates.
	if req.Name != nil {
		src.Name = *req.Name
	}
	if req.Protocol != nil {
		if !ValidProtocols[*req.Protocol] {
			return nil, fmt.Errorf("validation: invalid protocol")
		}
		src.Protocol = *req.Protocol
	}
	if req.Port != nil {
		src.Port = *req.Port
	}
	if req.Parser != nil {
		src.Parser = *req.Parser
	}
	if req.ExpectedHosts != nil {
		src.ExpectedHosts = req.ExpectedHosts
	}
	if req.Status != nil {
		if !ValidStatuses[*req.Status] {
			return nil, fmt.Errorf("validation: invalid status")
		}
		src.Status = *req.Status
	}
	if req.Description != nil {
		src.Description = *req.Description
	}
	if req.Tags != nil {
		src.Tags = req.Tags
	}
	src.UpdatedAt = time.Now().UTC()

	doc, err := json.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("marshaling source: %w", err)
	}

	if err := s.backend.UpdateDoc(ctx, s.index, id, doc); err != nil {
		return nil, fmt.Errorf("updating source: %w", err)
	}

	return src, nil
}

// Decommission soft-deletes a source and revokes its API key.
func (s *Service) Decommission(ctx context.Context, id string) error {
	src, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if src.Status == "decommissioned" {
		return fmt.Errorf("source already decommissioned")
	}

	// Revoke the linked API key.
	if src.APIKeyID != "" {
		if err := s.keyStore.Revoke(ctx, src.APIKeyID); err != nil {
			return fmt.Errorf("revoking API key: %w", err)
		}
	}

	// Update source status.
	src.Status = "decommissioned"
	src.UpdatedAt = time.Now().UTC()

	doc, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("marshaling source: %w", err)
	}

	if err := s.backend.UpdateDoc(ctx, s.index, id, doc); err != nil {
		return fmt.Errorf("updating source: %w", err)
	}

	return nil
}
