package correlate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseSigmaYAML parses one or more Sigma rules from a multi-document YAML reader.
// Each YAML document separated by --- becomes a separate rule.
func ParseSigmaYAML(reader io.Reader) ([]*SigmaRule, error) {
	decoder := yaml.NewDecoder(reader)
	var rules []*SigmaRule

	for {
		var doc map[string]interface{}
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return rules, fmt.Errorf("yaml decode: %w", err)
		}
		if doc == nil {
			continue
		}

		rule, err := parseSigmaDocument(doc)
		if err != nil {
			return rules, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// ParseSigmaFile parses all Sigma rules from a YAML file.
func ParseSigmaFile(path string) ([]*SigmaRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	return ParseSigmaYAML(f)
}

// LoadRulesFromDir recursively loads all .yml/.yaml files from a directory.
// Returns all successfully parsed rules and any parse errors encountered.
func LoadRulesFromDir(dir string) ([]*SigmaRule, []ParseError) {
	var allRules []*SigmaRule
	var errors []ParseError

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			errors = append(errors, ParseError{File: path, Err: err})
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		rules, parseErr := ParseSigmaFile(path)
		if parseErr != nil {
			errors = append(errors, ParseError{File: path, Err: parseErr})
			// Still keep any rules parsed before the error.
		}
		allRules = append(allRules, rules...)

		return nil
	})
	if err != nil {
		errors = append(errors, ParseError{Err: fmt.Errorf("walking directory %s: %w", dir, err)})
	}

	return allRules, errors
}

// parseSigmaDocument converts a raw YAML document map into a SigmaRule.
func parseSigmaDocument(doc map[string]interface{}) (*SigmaRule, error) {
	rule := &SigmaRule{}

	// Extract metadata fields.
	rule.ID = getString(doc, "id")
	rule.Title = getString(doc, "title")
	rule.Status = getString(doc, "status")
	rule.Description = getString(doc, "description")
	rule.Author = getString(doc, "author")
	rule.Date = getString(doc, "date")
	rule.Level = getString(doc, "level")
	rule.References = getStringSlice(doc, "references")
	rule.Tags = getStringSlice(doc, "tags")
	rule.FalsePositives = getStringSlice(doc, "falsepositives")

	// Parse logsource.
	if ls, ok := doc["logsource"].(map[string]interface{}); ok {
		rule.Logsource = SigmaLogsource{
			Category: getString(ls, "category"),
			Product:  getString(ls, "product"),
			Service:  getString(ls, "service"),
		}
	}

	// Check if this is a correlation rule (any correlation type).
	rule.Type = getString(doc, "type")
	if isCorrelationType(rule.Type) {
		return parseCorrelationFields(rule, doc)
	}

	// Parse detection block for single-event rules.
	detectionRaw, hasDetection := doc["detection"]
	if !hasDetection {
		// Rules without detection (e.g. top-level metadata-only docs) are valid.
		return rule, nil
	}

	detection, ok := detectionRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rule %q: detection must be a map", rule.ID)
	}

	det, err := parseDetection(detection)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
	}
	rule.Detection = det

	return rule, nil
}

// parseCorrelationFields extracts correlation-specific fields from the document.
func parseCorrelationFields(rule *SigmaRule, doc map[string]interface{}) (*SigmaRule, error) {
	rule.CorrelationRules = getStringSlice(doc, "rules")
	rule.GroupBy = getStringSlice(doc, "group-by")
	rule.Timespan = getString(doc, "timespan")
	rule.Ordered = getBool(doc, "ordered")

	// Parse correlation condition (e.g. {gte: 2, field: "source.ip"}).
	if cond, ok := doc["condition"].(map[string]interface{}); ok {
		rule.CorrelationCond = make(map[string]int)
		for k, v := range cond {
			// "field" is a string value used by value_count rules.
			if k == "field" {
				if s, ok := v.(string); ok {
					rule.ValueField = s
				}
				continue
			}
			if intVal, ok := toInt(v); ok {
				rule.CorrelationCond[k] = intVal
			}
		}
	}

	return rule, nil
}

// parseDetection parses the detection block into selections and condition.
func parseDetection(detection map[string]interface{}) (*SigmaDetection, error) {
	det := &SigmaDetection{
		Selections: make(map[string]SigmaSelection),
	}

	for key, val := range detection {
		if key == "condition" {
			det.Condition = fmt.Sprintf("%v", val)
			continue
		}

		// Everything else is a named selection.
		sel, err := parseSelection(val)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", key, err)
		}
		det.Selections[key] = sel
	}

	if det.Condition == "" {
		return nil, fmt.Errorf("detection missing condition")
	}

	return det, nil
}

// parseSelection parses a selection value, which can be:
// - A map (single event matcher, AND of fields)
// - A list of maps (OR of event matchers)
func parseSelection(val interface{}) (SigmaSelection, error) {
	switch v := val.(type) {
	case map[string]interface{}:
		matcher, err := parseEventMatcher(v)
		if err != nil {
			return nil, err
		}
		return SigmaSelection{matcher}, nil

	case []interface{}:
		var selection SigmaSelection
		for i, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("list item %d: expected map, got %T", i, item)
			}
			matcher, err := parseEventMatcher(m)
			if err != nil {
				return nil, fmt.Errorf("list item %d: %w", i, err)
			}
			selection = append(selection, matcher)
		}
		return selection, nil

	default:
		return nil, fmt.Errorf("expected map or list, got %T", val)
	}
}

// parseEventMatcher parses a single map of field conditions into an event matcher.
func parseEventMatcher(m map[string]interface{}) (SigmaEventMatcher, error) {
	var matchers []SigmaFieldMatcher

	for key, val := range m {
		fm := parseFieldMatcher(key, val)
		matchers = append(matchers, fm)
	}

	return SigmaEventMatcher{FieldMatchers: matchers}, nil
}

// parseFieldMatcher parses a single field key (with optional modifiers) and its value(s).
func parseFieldMatcher(key string, val interface{}) SigmaFieldMatcher {
	parts := strings.Split(key, "|")
	field := parts[0]
	var modifiers []string
	if len(parts) > 1 {
		modifiers = parts[1:]
	}

	values := normalizeValues(val)

	return SigmaFieldMatcher{
		Field:     field,
		Modifiers: modifiers,
		Values:    values,
	}
}

// normalizeValues converts a value (single or list) into a []interface{}.
func normalizeValues(val interface{}) []interface{} {
	if val == nil {
		return []interface{}{nil}
	}

	switch v := val.(type) {
	case []interface{}:
		return v
	case string:
		return []interface{}{v}
	case int:
		return []interface{}{v}
	case int64:
		return []interface{}{v}
	case float64:
		return []interface{}{v}
	case bool:
		return []interface{}{v}
	default:
		return []interface{}{v}
	}
}

// --- Helper functions for extracting typed values from maps ---

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	default:
		return nil
	}
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func toInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	default:
		return 0, false
	}
}
