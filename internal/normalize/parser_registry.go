package normalize

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
)

// Parser normalizes a raw event into an ECS event.
// Each source type (SentinelEDR, AV, DLP, WinEvt, Syslog) implements this interface.
type Parser interface {
	// SourceType returns the source_type string this parser handles (e.g., "sentineledr").
	SourceType() string

	// Parse normalizes a raw event JSON into an ECSEvent.
	Parse(raw json.RawMessage) (*common.ECSEvent, error)
}

// Registry holds registered parsers keyed by source type.
type Registry struct {
	mu      sync.RWMutex
	parsers map[string]Parser
}

// NewRegistry creates an empty parser registry.
func NewRegistry() *Registry {
	return &Registry{
		parsers: make(map[string]Parser),
	}
}

// Register adds a parser to the registry. Panics on duplicate source type.
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := p.SourceType()
	if _, exists := r.parsers[st]; exists {
		panic(fmt.Sprintf("normalize: duplicate parser registration for source_type %q", st))
	}
	r.parsers[st] = p
}

// Lookup returns the parser for a source type, or nil if not found.
func (r *Registry) Lookup(sourceType string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.parsers[sourceType]
}

// SourceTypes returns all registered source type names.
func (r *Registry) SourceTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.parsers))
	for st := range r.parsers {
		types = append(types, st)
	}
	return types
}
