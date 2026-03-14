package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/config"
)

// Store wraps the Elasticsearch client with SIEM-specific operations.
type Store struct {
	client *elasticsearch.Client
	prefix string
}

// New creates a new Store from the Elasticsearch config section.
func New(cfg config.ElasticsearchConfig) (*Store, error) {
	esCfg := elasticsearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
	}

	client, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return nil, fmt.Errorf("creating elasticsearch client: %w", err)
	}

	prefix := cfg.IndexPrefix
	if prefix == "" {
		prefix = "sentinel"
	}

	return &Store{client: client, prefix: prefix}, nil
}

// Health returns the cluster health status ("green", "yellow", "red") or an error.
func (s *Store) Health(ctx context.Context) (string, error) {
	res, err := s.client.Cluster.Health(
		s.client.Cluster.Health.WithContext(ctx),
	)
	if err != nil {
		return "", fmt.Errorf("cluster health request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return "", fmt.Errorf("cluster health: %s", res.String())
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding health response: %w", err)
	}

	return body.Status, nil
}

// EnsureTemplate creates or updates an index template with ECS mappings.
func (s *Store) EnsureTemplate(ctx context.Context) error {
	tmpl := ECSIndexTemplate(s.prefix)
	body, err := json.Marshal(tmpl)
	if err != nil {
		return fmt.Errorf("marshaling index template: %w", err)
	}

	templateName := s.prefix + "-events"
	res, err := s.client.Indices.PutIndexTemplate(
		templateName,
		bytes.NewReader(body),
		s.client.Indices.PutIndexTemplate.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("creating index template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("index template creation: %s", res.String())
	}

	return nil
}

// BulkIndex indexes a batch of ECS events into the specified index.
func (s *Store) BulkIndex(ctx context.Context, index string, events []common.ECSEvent) error {
	indexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client: s.client,
		Index:  index,
	})
	if err != nil {
		return fmt.Errorf("creating bulk indexer: %w", err)
	}

	var indexErr error
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshaling event: %w", err)
		}

		err = indexer.Add(ctx, esutil.BulkIndexerItem{
			Action: "index",
			Body:   bytes.NewReader(data),
			OnFailure: func(_ context.Context, _ esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
				if err != nil {
					indexErr = err
				} else {
					indexErr = fmt.Errorf("bulk index error: %s: %s", res.Error.Type, res.Error.Reason)
				}
			},
		})
		if err != nil {
			return fmt.Errorf("adding item to bulk indexer: %w", err)
		}
	}

	if err := indexer.Close(ctx); err != nil {
		return fmt.Errorf("closing bulk indexer: %w", err)
	}

	stats := indexer.Stats()
	if stats.NumFailed > 0 {
		if indexErr != nil {
			return indexErr
		}
		return fmt.Errorf("bulk index: %d of %d events failed", stats.NumFailed, stats.NumAdded)
	}

	return nil
}

// SearchResult holds the raw hits returned from an ES search.
type SearchResult struct {
	Total int
	Hits  []json.RawMessage
}

// Search executes a query string search against an index and returns raw hits.
func (s *Store) Search(ctx context.Context, index string, query map[string]any, size int) (*SearchResult, error) {
	body, err := json.Marshal(map[string]any{
		"query": query,
		"size":  size,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling search query: %w", err)
	}

	res, err := s.client.Search(
		s.client.Search.WithContext(ctx),
		s.client.Search.WithIndex(index),
		s.client.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading search response: %w", err)
	}

	var parsed struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}

	result := &SearchResult{
		Total: parsed.Hits.Total.Value,
	}
	for _, hit := range parsed.Hits.Hits {
		result.Hits = append(result.Hits, hit.Source)
	}

	return result, nil
}
