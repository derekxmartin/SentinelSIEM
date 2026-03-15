package correlate

// SigmaRule represents a parsed Sigma detection rule or correlation rule.
// Single-event rules have a Detection block; correlation rules have Rules,
// GroupBy, Timespan, and a correlation Condition.
type SigmaRule struct {
	// Metadata.
	ID             string   `yaml:"id"`
	Title          string   `yaml:"title"`
	Status         string   `yaml:"status"`
	Description    string   `yaml:"description"`
	Author         string   `yaml:"author"`
	Date           string   `yaml:"date"`
	References     []string `yaml:"references"`
	Tags           []string `yaml:"tags"`
	Level          string   `yaml:"level"`
	FalsePositives []string `yaml:"falsepositives"`

	// Logsource determines which events this rule applies to.
	Logsource SigmaLogsource

	// Detection logic for single-event rules.
	Detection *SigmaDetection

	// Type discriminator: "" = single-event, "correlation" = correlation rule.
	Type string

	// Correlation-specific fields (only set when Type == "correlation"
	// or an explicit subtype like "event_count", "value_count", "temporal").
	CorrelationRules []string       // Rule IDs referenced by this correlation.
	GroupBy          []string       // Fields to group correlated events by.
	Timespan         string         // Duration string, e.g. "5m", "60m".
	Ordered          bool           // Whether the rule order matters.
	CorrelationCond  map[string]int // Correlation condition, e.g. {"gte": 2}.
	ValueField       string         // Field for value_count (distinct values counted).
}

// SigmaLogsource specifies the log source a rule targets.
type SigmaLogsource struct {
	Category string `yaml:"category,omitempty"`
	Product  string `yaml:"product,omitempty"`
	Service  string `yaml:"service,omitempty"`
}

// SigmaDetection holds the detection block of a Sigma rule.
// Selections are named groups of field matchers. The Condition string
// combines them using boolean logic (parsed by the evaluator, not here).
type SigmaDetection struct {
	Selections map[string]SigmaSelection
	Condition  string
}

// SigmaSelection is a list of event matchers. Multiple matchers = OR.
// A single-map detection value becomes a slice of length 1.
type SigmaSelection []SigmaEventMatcher

// SigmaEventMatcher represents a single map of field conditions.
// All field matchers within one event matcher are AND'd together.
type SigmaEventMatcher struct {
	FieldMatchers []SigmaFieldMatcher
}

// SigmaFieldMatcher represents a single field condition within a detection.
// Field is the ECS dotted field path (e.g. "event.action").
// Modifiers are the Sigma modifiers (e.g. ["contains", "all"]).
// Values are the match targets; multiple values = OR (unless "all" modifier).
type SigmaFieldMatcher struct {
	Field     string
	Modifiers []string
	Values    []interface{}
}

// RuleRegistry provides O(1) lookup of parsed Sigma rules by ID.
type RuleRegistry struct {
	rules map[string]*SigmaRule
	all   []*SigmaRule
}

// NewRuleRegistry creates a rule registry from a slice of parsed rules.
// Duplicate IDs are silently overwritten (last writer wins).
func NewRuleRegistry(rules []*SigmaRule) *RuleRegistry {
	reg := &RuleRegistry{
		rules: make(map[string]*SigmaRule, len(rules)),
		all:   rules,
	}
	for _, r := range rules {
		if r.ID != "" {
			reg.rules[r.ID] = r
		}
	}
	return reg
}

// Get returns a rule by ID, or nil if not found.
func (reg *RuleRegistry) Get(id string) *SigmaRule {
	return reg.rules[id]
}

// All returns all registered rules.
func (reg *RuleRegistry) All() []*SigmaRule {
	return reg.all
}

// Count returns the number of registered rules.
func (reg *RuleRegistry) Count() int {
	return len(reg.all)
}

// isCorrelationType returns true if the type string indicates a correlation rule.
func isCorrelationType(t string) bool {
	switch t {
	case "correlation", "event_count", "value_count", "temporal":
		return true
	}
	return false
}

// SingleEventRules returns only non-correlation rules.
func (reg *RuleRegistry) SingleEventRules() []*SigmaRule {
	var result []*SigmaRule
	for _, r := range reg.all {
		if !isCorrelationType(r.Type) {
			result = append(result, r)
		}
	}
	return result
}

// CorrelationRules returns only correlation rules.
func (reg *RuleRegistry) CorrelationRules() []*SigmaRule {
	var result []*SigmaRule
	for _, r := range reg.all {
		if isCorrelationType(r.Type) {
			result = append(result, r)
		}
	}
	return result
}

// ParseError captures a parse failure with context.
type ParseError struct {
	File     string
	DocIndex int
	Err      error
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.File != "" {
		return e.File + ": " + e.Err.Error()
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ParseError) Unwrap() error {
	return e.Err
}
