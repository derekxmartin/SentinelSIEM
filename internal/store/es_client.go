package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/config"
)

// Indexer is the interface used by the ingest pipeline to write events to storage.
// Implementations include the Elasticsearch Store and test mocks.
type Indexer interface {
	BulkIndex(ctx context.Context, index string, events []common.ECSEvent) error
}

// Verify Store implements Indexer at compile time.
var _ Indexer = (*Store)(nil)

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
		prefix = "akeso"
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

// SearchRawResult holds the full response from a raw ES search body,
// including aggregation results.
type SearchRawResult struct {
	Total int
	Hits  []json.RawMessage
	Aggs  json.RawMessage // raw "aggregations" block, nil if none
	TookMs int            // server-side time in milliseconds
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

// SearchRaw executes a full search body against an index and returns
// hits plus optional aggregation results. The body is the complete
// Elasticsearch search request (query, sort, size, aggs, etc.).
func (s *Store) SearchRaw(ctx context.Context, index string, body map[string]any) (*SearchRawResult, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling search body: %w", err)
	}

	res, err := s.client.Search(
		s.client.Search.WithContext(ctx),
		s.client.Search.WithIndex(index),
		s.client.Search.WithBody(bytes.NewReader(bodyBytes)),
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
		Took int `json:"took"`
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations json.RawMessage `json:"aggregations"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}

	result := &SearchRawResult{
		Total:  parsed.Hits.Total.Value,
		TookMs: parsed.Took,
		Aggs:   parsed.Aggregations,
	}
	for _, hit := range parsed.Hits.Hits {
		result.Hits = append(result.Hits, hit.Source)
	}

	return result, nil
}

// --- APIKeyBackend implementation ---
// These methods implement common.APIKeyBackend so the Store can be used
// as the backing store for API key management.

// IndexDoc indexes a single JSON document with the given ID.
func (s *Store) IndexDoc(ctx context.Context, index, id string, doc []byte) error {
	res, err := s.client.Index(
		index,
		bytes.NewReader(doc),
		s.client.Index.WithContext(ctx),
		s.client.Index.WithDocumentID(id),
		s.client.Index.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("index doc: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("index doc error: %s", res.String())
	}
	return nil
}

// GetDoc retrieves a single document by ID.
func (s *Store) GetDoc(ctx context.Context, index, id string) ([]byte, error) {
	res, err := s.client.Get(
		index,
		id,
		s.client.Get.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("get doc: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("get doc error: %s", res.String())
	}

	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading get response: %w", err)
	}

	var parsed struct {
		Source json.RawMessage `json:"_source"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding get response: %w", err)
	}

	return parsed.Source, nil
}

// VersionedDoc holds a document source along with its ES sequence number
// and primary term, used for optimistic concurrency control.
type VersionedDoc struct {
	Source      json.RawMessage
	SeqNo      int
	PrimaryTerm int
}

// GetDocVersioned retrieves a document by ID along with its _seq_no and
// _primary_term for use with optimistic concurrency control.
func (s *Store) GetDocVersioned(ctx context.Context, index, id string) (*VersionedDoc, error) {
	res, err := s.client.Get(
		index,
		id,
		s.client.Get.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("get doc: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		return nil, fmt.Errorf("document not found: %s/%s", index, id)
	}

	if res.IsError() {
		return nil, fmt.Errorf("get doc error: %s", res.String())
	}

	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading get response: %w", err)
	}

	var parsed struct {
		Source      json.RawMessage `json:"_source"`
		SeqNo      int             `json:"_seq_no"`
		PrimaryTerm int            `json:"_primary_term"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding get response: %w", err)
	}

	return &VersionedDoc{
		Source:      parsed.Source,
		SeqNo:      parsed.SeqNo,
		PrimaryTerm: parsed.PrimaryTerm,
	}, nil
}

// IndexDocIfMatch indexes a document only if the current _seq_no and
// _primary_term match. Returns ErrConflict if they don't match.
func (s *Store) IndexDocIfMatch(ctx context.Context, index, id string, doc []byte, seqNo, primaryTerm int) error {
	res, err := s.client.Index(
		index,
		bytes.NewReader(doc),
		s.client.Index.WithContext(ctx),
		s.client.Index.WithDocumentID(id),
		s.client.Index.WithRefresh("true"),
		s.client.Index.WithIfSeqNo(seqNo),
		s.client.Index.WithIfPrimaryTerm(primaryTerm),
	)
	if err != nil {
		return fmt.Errorf("index doc: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 409 {
		return ErrConflict
	}

	if res.IsError() {
		return fmt.Errorf("index doc error: %s", res.String())
	}
	return nil
}

// ErrConflict is returned when an optimistic concurrency check fails.
var ErrConflict = fmt.Errorf("version conflict: document was modified by another request")

// SearchDocs executes a search and returns the raw _source of each hit.
func (s *Store) SearchDocs(ctx context.Context, index string, query map[string]any) ([]json.RawMessage, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshaling search: %w", err)
	}

	res, err := s.client.Search(
		s.client.Search.WithContext(ctx),
		s.client.Search.WithIndex(index),
		s.client.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, fmt.Errorf("search docs: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search docs error: %s", res.String())
	}

	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading search response: %w", err)
	}

	var parsed struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}

	docs := make([]json.RawMessage, len(parsed.Hits.Hits))
	for i, hit := range parsed.Hits.Hits {
		docs[i] = hit.Source
	}
	return docs, nil
}

// UpdateDoc updates a document by ID (full document replace).
func (s *Store) UpdateDoc(ctx context.Context, index, id string, doc []byte) error {
	return s.IndexDoc(ctx, index, id, doc)
}

// UpdateFields performs a partial update on a document, merging the given
// fields into the existing document. Used for adding escalation metadata
// to alert documents without replacing the full document.
func (s *Store) UpdateFields(ctx context.Context, index, id string, fields map[string]any) error {
	body, err := json.Marshal(map[string]any{"doc": fields})
	if err != nil {
		return fmt.Errorf("marshaling partial update: %w", err)
	}

	res, err := s.client.Update(
		index,
		id,
		bytes.NewReader(body),
		s.client.Update.WithContext(ctx),
		s.client.Update.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("partial update: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("partial update error: %s", res.String())
	}
	return nil
}

// Prefix returns the configured index prefix.
func (s *Store) Prefix() string {
	return s.prefix
}
