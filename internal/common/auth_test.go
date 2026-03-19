package common

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- APIKey unit tests ---

func TestGenerateAPIKey(t *testing.T) {
	result, err := GenerateAPIKey("test-key", []string{"ingest"}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(result.PlaintextKey, "sk_") {
		t.Errorf("expected key to start with 'sk_', got %q", result.PlaintextKey[:10])
	}

	// sk_ + 64 hex chars = 67 total
	if len(result.PlaintextKey) != 67 {
		t.Errorf("expected key length 67, got %d", len(result.PlaintextKey))
	}

	if result.Key.Name != "test-key" {
		t.Errorf("expected name 'test-key', got %q", result.Key.Name)
	}

	if result.Key.ID == "" {
		t.Error("expected non-empty ID")
	}

	if result.Key.Prefix != result.PlaintextKey[:11] {
		t.Errorf("expected prefix %q, got %q", result.PlaintextKey[:11], result.Key.Prefix)
	}

	if result.Key.Hash == "" {
		t.Error("expected non-empty hash")
	}

	if result.Key.Hash == result.PlaintextKey {
		t.Error("hash should not equal plaintext key")
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	r1, _ := GenerateAPIKey("key1", nil, time.Time{})
	r2, _ := GenerateAPIKey("key2", nil, time.Time{})

	if r1.PlaintextKey == r2.PlaintextKey {
		t.Error("two generated keys should not be identical")
	}
	if r1.Key.ID == r2.Key.ID {
		t.Error("two generated key IDs should not be identical")
	}
	if r1.Key.Hash == r2.Key.Hash {
		t.Error("two generated key hashes should not be identical")
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	h1 := HashAPIKey("sk_abc123")
	h2 := HashAPIKey("sk_abc123")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}

	h3 := HashAPIKey("sk_different")
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	// No expiration.
	k := &APIKey{}
	if k.IsExpired() {
		t.Error("key with zero expiration should not be expired")
	}

	// Future expiration.
	k.ExpiresAt = time.Now().UTC().Add(1 * time.Hour)
	if k.IsExpired() {
		t.Error("key with future expiration should not be expired")
	}

	// Past expiration.
	k.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	if !k.IsExpired() {
		t.Error("key with past expiration should be expired")
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	k := &APIKey{}
	if !k.IsValid() {
		t.Error("fresh key should be valid")
	}

	k.Revoked = true
	if k.IsValid() {
		t.Error("revoked key should not be valid")
	}

	k.Revoked = false
	k.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	if k.IsValid() {
		t.Error("expired key should not be valid")
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	// Empty scopes = all access.
	k := &APIKey{}
	if !k.HasScope("ingest") {
		t.Error("empty scopes should grant all access")
	}

	k.Scopes = []string{"ingest", "query"}
	if !k.HasScope("ingest") {
		t.Error("should have ingest scope")
	}
	if !k.HasScope("query") {
		t.Error("should have query scope")
	}
	if k.HasScope("admin") {
		t.Error("should not have admin scope")
	}
}

func TestAPIKey_JSONRoundtrip(t *testing.T) {
	result, _ := GenerateAPIKey("roundtrip", []string{"ingest"}, time.Now().UTC().Add(24*time.Hour))
	data, err := json.Marshal(result.Key)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded APIKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ID != result.Key.ID {
		t.Errorf("ID mismatch: %q vs %q", decoded.ID, result.Key.ID)
	}
	if decoded.Name != result.Key.Name {
		t.Errorf("Name mismatch: %q vs %q", decoded.Name, result.Key.Name)
	}
	if decoded.Hash != result.Key.Hash {
		t.Errorf("Hash mismatch")
	}
	if !decoded.ExpiresAt.Equal(result.Key.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch")
	}
}

// --- Mock backend for APIKeyStore tests ---

type mockBackend struct {
	docs map[string]map[string][]byte // index → id → doc
}

func newMockBackend() *mockBackend {
	return &mockBackend{docs: make(map[string]map[string][]byte)}
}

func (m *mockBackend) IndexDoc(_ context.Context, index, id string, doc []byte) error {
	if m.docs[index] == nil {
		m.docs[index] = make(map[string][]byte)
	}
	m.docs[index][id] = doc
	return nil
}

func (m *mockBackend) GetDoc(_ context.Context, index, id string) ([]byte, error) {
	if m.docs[index] == nil {
		return nil, fmt.Errorf("not found")
	}
	doc, ok := m.docs[index][id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return doc, nil
}

func (m *mockBackend) SearchDocs(_ context.Context, index string, _ map[string]any) ([]json.RawMessage, error) {
	var results []json.RawMessage
	if m.docs[index] != nil {
		for _, doc := range m.docs[index] {
			results = append(results, json.RawMessage(doc))
		}
	}
	return results, nil
}

func (m *mockBackend) UpdateDoc(ctx context.Context, index, id string, doc []byte) error {
	return m.IndexDoc(ctx, index, id, doc)
}

// --- APIKeyStore tests ---

func TestAPIKeyStore_CreateAndAuthenticate(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	result, err := store.Create(context.Background(), "test-key", []string{"ingest"}, time.Time{})
	if err != nil {
		t.Fatalf("create error: %v", err)
	}

	// Authenticate with the plaintext key.
	key := store.Authenticate(result.PlaintextKey)
	if key == nil {
		t.Fatal("expected successful authentication")
	}
	if key.Name != "test-key" {
		t.Errorf("expected name 'test-key', got %q", key.Name)
	}
}

func TestAPIKeyStore_AuthenticateUnknownKey(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	key := store.Authenticate("sk_nonexistent")
	if key != nil {
		t.Error("expected nil for unknown key")
	}
}

func TestAPIKeyStore_Revoke(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	result, _ := store.Create(context.Background(), "revoke-me", nil, time.Time{})

	// Should authenticate before revocation.
	if store.Authenticate(result.PlaintextKey) == nil {
		t.Fatal("expected auth to succeed before revocation")
	}

	// Revoke.
	if err := store.Revoke(context.Background(), result.Key.ID); err != nil {
		t.Fatalf("revoke error: %v", err)
	}

	// Should fail after revocation.
	if store.Authenticate(result.PlaintextKey) != nil {
		t.Error("expected auth to fail after revocation")
	}

	// Key should still be listed.
	key := store.Get(result.Key.ID)
	if key == nil {
		t.Fatal("expected revoked key to still be in store")
	}
	if !key.Revoked {
		t.Error("expected key to be marked as revoked")
	}
	if key.RevokedAt.IsZero() {
		t.Error("expected non-zero revoked_at")
	}
}

func TestAPIKeyStore_RevokeUnknownKey(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	err := store.Revoke(context.Background(), "nonexistent-id")
	if err == nil {
		t.Error("expected error when revoking unknown key")
	}
}

func TestAPIKeyStore_ExpiredKeyFailsAuth(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	// Create a key that's already expired.
	result, _ := store.Create(context.Background(), "expired", nil, time.Now().UTC().Add(-1*time.Hour))

	if store.Authenticate(result.PlaintextKey) != nil {
		t.Error("expected auth to fail for expired key")
	}
}

func TestAPIKeyStore_AuthenticateWithScope(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	result, _ := store.Create(context.Background(), "scoped", []string{"ingest"}, time.Time{})

	if store.AuthenticateWithScope(result.PlaintextKey, "ingest") == nil {
		t.Error("expected auth with ingest scope to succeed")
	}
	if store.AuthenticateWithScope(result.PlaintextKey, "admin") != nil {
		t.Error("expected auth with admin scope to fail")
	}
}

func TestAPIKeyStore_List(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	store.Create(context.Background(), "key1", nil, time.Time{})
	store.Create(context.Background(), "key2", nil, time.Time{})
	store.Create(context.Background(), "key3", nil, time.Time{})

	keys := store.List()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestAPIKeyStore_Count(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	store.Create(context.Background(), "active1", nil, time.Time{})
	r2, _ := store.Create(context.Background(), "active2", nil, time.Time{})
	store.Create(context.Background(), "expired", nil, time.Now().UTC().Add(-1*time.Hour))

	store.Revoke(context.Background(), r2.Key.ID)

	total, active := store.Count()
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
	if active != 1 {
		t.Errorf("expected active=1, got %d", active)
	}
}

func TestAPIKeyStore_LoadAll(t *testing.T) {
	backend := newMockBackend()
	index := "akeso-apikeys"

	// Pre-populate backend with a key.
	key := &APIKey{
		ID:        "preloaded-id",
		Name:      "preloaded",
		Prefix:    "sk_abcdef01",
		Hash:      HashAPIKey("sk_preloaded_key_value_for_testing_only_abcdef0123456789abcdef01234"),
		CreatedAt: time.Now().UTC(),
	}
	doc, _ := json.Marshal(key)
	backend.IndexDoc(context.Background(), index, key.ID, doc)

	// Create store and load.
	store := NewAPIKeyStore(backend, index)
	if err := store.LoadAll(context.Background()); err != nil {
		t.Fatalf("load error: %v", err)
	}

	// Should find the key by ID.
	loaded := store.Get("preloaded-id")
	if loaded == nil {
		t.Fatal("expected to find preloaded key")
	}
	if loaded.Name != "preloaded" {
		t.Errorf("expected name 'preloaded', got %q", loaded.Name)
	}
}

func TestAPIKeyStore_AddStaticKeys(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	store.AddStaticKeys([]string{"my-config-key-1", "my-config-key-2"})

	// Should authenticate with static keys.
	if store.Authenticate("my-config-key-1") == nil {
		t.Error("expected static key 1 to authenticate")
	}
	if store.Authenticate("my-config-key-2") == nil {
		t.Error("expected static key 2 to authenticate")
	}
	if store.Authenticate("wrong-key") != nil {
		t.Error("expected wrong key to fail")
	}

	total, active := store.Count()
	if total != 2 || active != 2 {
		t.Errorf("expected 2 total, 2 active, got %d/%d", total, active)
	}
}

func TestAPIKeyStore_StaticAndDynamicCoexist(t *testing.T) {
	store := NewAPIKeyStore(newMockBackend(), "akeso-apikeys")

	// Add static key.
	store.AddStaticKeys([]string{"static-key"})

	// Create dynamic key.
	result, _ := store.Create(context.Background(), "dynamic", nil, time.Time{})

	// Both should authenticate.
	if store.Authenticate("static-key") == nil {
		t.Error("static key should authenticate")
	}
	if store.Authenticate(result.PlaintextKey) == nil {
		t.Error("dynamic key should authenticate")
	}

	total, _ := store.Count()
	if total != 2 {
		t.Errorf("expected 2 total keys, got %d", total)
	}
}

func TestAPIKeyStore_BackendPersistence(t *testing.T) {
	backend := newMockBackend()
	index := "akeso-apikeys"

	// Create key in store 1.
	store1 := NewAPIKeyStore(backend, index)
	result, _ := store1.Create(context.Background(), "persistent", nil, time.Time{})

	// Load into store 2 from same backend.
	store2 := NewAPIKeyStore(backend, index)
	if err := store2.LoadAll(context.Background()); err != nil {
		t.Fatalf("load error: %v", err)
	}

	// Store 2 should have the key (by hash lookup).
	key := store2.Authenticate(result.PlaintextKey)
	if key == nil {
		t.Fatal("expected key to persist across store instances")
	}
	if key.Name != "persistent" {
		t.Errorf("expected name 'persistent', got %q", key.Name)
	}
}

func TestAPIKeyStore_RevokePersistedToBackend(t *testing.T) {
	backend := newMockBackend()
	index := "akeso-apikeys"

	store1 := NewAPIKeyStore(backend, index)
	result, _ := store1.Create(context.Background(), "to-revoke", nil, time.Time{})
	store1.Revoke(context.Background(), result.Key.ID)

	// Load into new store — revocation should be persisted.
	store2 := NewAPIKeyStore(backend, index)
	store2.LoadAll(context.Background())

	if store2.Authenticate(result.PlaintextKey) != nil {
		t.Error("revoked key should not authenticate after reload")
	}

	loaded := store2.Get(result.Key.ID)
	if loaded == nil {
		t.Fatal("revoked key should still exist in store")
	}
	if !loaded.Revoked {
		t.Error("loaded key should be marked revoked")
	}
}
