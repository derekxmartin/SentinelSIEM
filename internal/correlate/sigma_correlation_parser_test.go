package correlate

import (
	"strings"
	"testing"
	"time"
)

// --- ParseCorrelationRule tests ---

func TestParseCorrelationRuleEventCount(t *testing.T) {
	rule := &SigmaRule{
		ID:               "ec-001",
		Title:            "Brute Force Login",
		Level:            "high",
		Type:             "event_count",
		CorrelationRules: []string{"failed-logon-rule"},
		GroupBy:          []string{"user.name"},
		Timespan:         "10m",
		CorrelationCond:  map[string]int{"gte": 5},
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationEventCount {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationEventCount)
	}
	if cr.Timespan != 10*time.Minute {
		t.Errorf("timespan = %v, want 10m", cr.Timespan)
	}
	if cr.Condition != OpGTE {
		t.Errorf("condition = %q, want %q", cr.Condition, OpGTE)
	}
	if cr.Threshold != 5 {
		t.Errorf("threshold = %d, want 5", cr.Threshold)
	}
	if cr.ID != "ec-001" {
		t.Errorf("ID = %q, want 'ec-001'", cr.ID)
	}
}

func TestParseCorrelationRuleValueCount(t *testing.T) {
	rule := &SigmaRule{
		ID:               "vc-001",
		Title:            "Distributed Login Sources",
		Level:            "medium",
		Type:             "value_count",
		CorrelationRules: []string{"logon-rule"},
		GroupBy:          []string{"user.name"},
		Timespan:         "1h",
		CorrelationCond:  map[string]int{"gte": 10},
		ValueField:       "source.ip",
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationValueCount {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationValueCount)
	}
	if cr.ValueField != "source.ip" {
		t.Errorf("value_field = %q, want 'source.ip'", cr.ValueField)
	}
	if cr.Timespan != 1*time.Hour {
		t.Errorf("timespan = %v, want 1h", cr.Timespan)
	}
	if cr.Threshold != 10 {
		t.Errorf("threshold = %d, want 10", cr.Threshold)
	}
}

func TestParseCorrelationRuleTemporal(t *testing.T) {
	rule := &SigmaRule{
		ID:               "temp-001",
		Title:            "Credential Theft Chain",
		Level:            "critical",
		Type:             "temporal",
		CorrelationRules: []string{"rule-a", "rule-b", "rule-c"},
		GroupBy:          []string{"user.name"},
		Timespan:         "15m",
		Ordered:          true,
		CorrelationCond:  map[string]int{"gte": 3},
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationTemporal {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationTemporal)
	}
	if !cr.Ordered {
		t.Error("ordered should be true")
	}
	if len(cr.Rules) != 3 {
		t.Errorf("rules count = %d, want 3", len(cr.Rules))
	}
	if cr.Timespan != 15*time.Minute {
		t.Errorf("timespan = %v, want 15m", cr.Timespan)
	}
}

func TestParseCorrelationRuleGenericInfersTemporal(t *testing.T) {
	rule := &SigmaRule{
		ID:               "infer-temp",
		Title:            "Inferred Temporal",
		Type:             "correlation",
		CorrelationRules: []string{"rule-a", "rule-b"},
		GroupBy:          []string{"source.ip"},
		Timespan:         "30m",
		Ordered:          true,
		CorrelationCond:  map[string]int{"gte": 2},
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationTemporal {
		t.Errorf("inferred type = %q, want %q", cr.Type, CorrelationTemporal)
	}
}

func TestParseCorrelationRuleGenericInfersValueCount(t *testing.T) {
	rule := &SigmaRule{
		ID:               "infer-vc",
		Title:            "Inferred Value Count",
		Type:             "correlation",
		CorrelationRules: []string{"logon-rule"},
		GroupBy:          []string{"user.name"},
		Timespan:         "1h",
		CorrelationCond:  map[string]int{"gte": 10},
		ValueField:       "source.ip",
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationValueCount {
		t.Errorf("inferred type = %q, want %q", cr.Type, CorrelationValueCount)
	}
}

func TestParseCorrelationRuleGenericInfersEventCount(t *testing.T) {
	rule := &SigmaRule{
		ID:               "infer-ec",
		Title:            "Inferred Event Count",
		Type:             "correlation",
		CorrelationRules: []string{"failed-logon"},
		GroupBy:          []string{"user.name"},
		Timespan:         "5m",
		CorrelationCond:  map[string]int{"gte": 5},
	}

	cr, err := ParseCorrelationRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr.Type != CorrelationEventCount {
		t.Errorf("inferred type = %q, want %q", cr.Type, CorrelationEventCount)
	}
}

// --- Validation error tests ---

func TestParseCorrelationRuleNilRule(t *testing.T) {
	_, err := ParseCorrelationRule(nil)
	if err == nil {
		t.Fatal("expected error for nil rule")
	}
}

func TestParseCorrelationRuleMissingTimespan(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-001",
		Title:            "No Timespan",
		Type:             "event_count",
		CorrelationRules: []string{"rule-a"},
		CorrelationCond:  map[string]int{"gte": 1},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for missing timespan")
	}
	if !strings.Contains(err.Error(), "missing timespan") {
		t.Errorf("error = %q, want 'missing timespan'", err.Error())
	}
}

func TestParseCorrelationRuleInvalidTimespan(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-002",
		Title:            "Bad Timespan",
		Type:             "event_count",
		CorrelationRules: []string{"rule-a"},
		Timespan:         "abc",
		CorrelationCond:  map[string]int{"gte": 1},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for invalid timespan")
	}
	if !strings.Contains(err.Error(), "invalid timespan") {
		t.Errorf("error = %q, want 'invalid timespan'", err.Error())
	}
}

func TestParseCorrelationRuleMissingCondition(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-003",
		Title:            "No Condition",
		Type:             "event_count",
		CorrelationRules: []string{"rule-a"},
		Timespan:         "5m",
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for missing condition")
	}
	if !strings.Contains(err.Error(), "missing condition") {
		t.Errorf("error = %q, want 'missing condition'", err.Error())
	}
}

func TestParseCorrelationRuleMissingRules(t *testing.T) {
	rule := &SigmaRule{
		ID:              "bad-004",
		Title:           "No Rules",
		Type:            "event_count",
		Timespan:        "5m",
		CorrelationCond: map[string]int{"gte": 1},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for missing rules")
	}
	if !strings.Contains(err.Error(), "must reference at least one rule") {
		t.Errorf("error = %q, want 'must reference at least one rule'", err.Error())
	}
}

func TestParseCorrelationRuleTemporalNotOrdered(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-005",
		Title:            "Temporal Not Ordered",
		Type:             "temporal",
		CorrelationRules: []string{"rule-a", "rule-b"},
		GroupBy:          []string{"user.name"},
		Timespan:         "15m",
		Ordered:          false,
		CorrelationCond:  map[string]int{"gte": 2},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for temporal without ordered:true")
	}
	if !strings.Contains(err.Error(), "ordered: true") {
		t.Errorf("error = %q, want 'ordered: true'", err.Error())
	}
}

func TestParseCorrelationRuleTemporalSingleRule(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-006",
		Title:            "Temporal Single Rule",
		Type:             "temporal",
		CorrelationRules: []string{"rule-a"},
		GroupBy:          []string{"user.name"},
		Timespan:         "15m",
		Ordered:          true,
		CorrelationCond:  map[string]int{"gte": 1},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for temporal with single rule")
	}
	if !strings.Contains(err.Error(), "at least 2 rule references") {
		t.Errorf("error = %q, want 'at least 2 rule references'", err.Error())
	}
}

func TestParseCorrelationRuleTemporalNoGroupBy(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-007",
		Title:            "Temporal No GroupBy",
		Type:             "temporal",
		CorrelationRules: []string{"rule-a", "rule-b"},
		Timespan:         "15m",
		Ordered:          true,
		CorrelationCond:  map[string]int{"gte": 2},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for temporal without group-by")
	}
	if !strings.Contains(err.Error(), "group-by field") {
		t.Errorf("error = %q, want 'group-by field'", err.Error())
	}
}

func TestParseCorrelationRuleValueCountNoField(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-008",
		Title:            "Value Count No Field",
		Type:             "value_count",
		CorrelationRules: []string{"logon-rule"},
		GroupBy:          []string{"user.name"},
		Timespan:         "1h",
		CorrelationCond:  map[string]int{"gte": 10},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for value_count without field")
	}
	if !strings.Contains(err.Error(), "value field") {
		t.Errorf("error = %q, want 'value field'", err.Error())
	}
}

func TestParseCorrelationRuleUnknownType(t *testing.T) {
	rule := &SigmaRule{
		ID:               "bad-009",
		Title:            "Unknown Type",
		Type:             "nonexistent",
		CorrelationRules: []string{"rule-a"},
		Timespan:         "5m",
		CorrelationCond:  map[string]int{"gte": 1},
	}

	_, err := ParseCorrelationRule(rule)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	if !strings.Contains(err.Error(), "unknown correlation type") {
		t.Errorf("error = %q, want 'unknown correlation type'", err.Error())
	}
}

// --- Timespan parsing tests ---

func TestParseTimespan(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"5m", 5 * time.Minute, false},
		{"10min", 10 * time.Minute, false},
		{"1h", 1 * time.Hour, false},
		{"2hr", 2 * time.Hour, false},
		{"30s", 30 * time.Second, false},
		{"60m", 60 * time.Minute, false},
		{"1d", 24 * time.Hour, false},
		{"120m", 120 * time.Minute, false},
		{"", 0, true},
		{"abc", 0, true},
		{"5x", 0, true},
		{"0m", 0, true},
		{"-5m", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseTimespan(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("parseTimespan(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

// --- Condition parsing tests ---

func TestParseConditionValid(t *testing.T) {
	tests := []struct {
		name      string
		cond      map[string]int
		wantOp    ConditionOp
		wantThres int
	}{
		{"gte", map[string]int{"gte": 5}, OpGTE, 5},
		{"gt", map[string]int{"gt": 10}, OpGT, 10},
		{"lte", map[string]int{"lte": 3}, OpLTE, 3},
		{"lt", map[string]int{"lt": 1}, OpLT, 1},
		{"eq", map[string]int{"eq": 0}, OpEQ, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, threshold, _, err := parseCorrelationCondition(tc.cond)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if op != tc.wantOp {
				t.Errorf("op = %q, want %q", op, tc.wantOp)
			}
			if threshold != tc.wantThres {
				t.Errorf("threshold = %d, want %d", threshold, tc.wantThres)
			}
		})
	}
}

func TestParseConditionEmpty(t *testing.T) {
	_, _, _, err := parseCorrelationCondition(map[string]int{})
	if err == nil {
		t.Fatal("expected error for empty condition")
	}
}

func TestParseConditionMultipleOperators(t *testing.T) {
	_, _, _, err := parseCorrelationCondition(map[string]int{"gte": 5, "lte": 10})
	if err == nil {
		t.Fatal("expected error for multiple operators")
	}
}

// --- YAML round-trip parsing test ---

func TestParseCorrelationRuleFromYAML(t *testing.T) {
	yamlContent := `
title: Brute Force Detection
id: bf-001
type: event_count
rules:
  - failed-logon-rule
group-by:
  - user.name
timespan: 10m
condition:
  gte: 5
level: high
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlContent))
	if err != nil {
		t.Fatalf("YAML parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	sigmaRule := rules[0]
	if sigmaRule.Type != "event_count" {
		t.Fatalf("sigma rule type = %q, want 'event_count'", sigmaRule.Type)
	}

	cr, err := ParseCorrelationRule(sigmaRule)
	if err != nil {
		t.Fatalf("correlation parse error: %v", err)
	}

	if cr.Type != CorrelationEventCount {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationEventCount)
	}
	if cr.Timespan != 10*time.Minute {
		t.Errorf("timespan = %v, want 10m", cr.Timespan)
	}
	if cr.Threshold != 5 {
		t.Errorf("threshold = %d, want 5", cr.Threshold)
	}
}

func TestParseValueCountFromYAML(t *testing.T) {
	yamlContent := `
title: Distributed Login Sources
id: vc-yaml-001
type: value_count
rules:
  - logon-success
group-by:
  - user.name
timespan: 1h
condition:
  field: source.ip
  gte: 10
level: medium
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlContent))
	if err != nil {
		t.Fatalf("YAML parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	cr, err := ParseCorrelationRule(rules[0])
	if err != nil {
		t.Fatalf("correlation parse error: %v", err)
	}

	if cr.Type != CorrelationValueCount {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationValueCount)
	}
	if cr.ValueField != "source.ip" {
		t.Errorf("value_field = %q, want 'source.ip'", cr.ValueField)
	}
	if cr.Threshold != 10 {
		t.Errorf("threshold = %d, want 10", cr.Threshold)
	}
}

func TestParseTemporalFromYAML(t *testing.T) {
	yamlContent := `
title: Credential Theft Chain
id: temp-yaml-001
type: temporal
rules:
  - failed-logon
  - success-logon
  - lsass-access
group-by:
  - user.name
timespan: 15m
ordered: true
condition:
  gte: 3
level: critical
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlContent))
	if err != nil {
		t.Fatalf("YAML parse error: %v", err)
	}

	cr, err := ParseCorrelationRule(rules[0])
	if err != nil {
		t.Fatalf("correlation parse error: %v", err)
	}

	if cr.Type != CorrelationTemporal {
		t.Errorf("type = %q, want %q", cr.Type, CorrelationTemporal)
	}
	if !cr.Ordered {
		t.Error("expected ordered = true")
	}
	if len(cr.Rules) != 3 {
		t.Errorf("rules count = %d, want 3", len(cr.Rules))
	}
	if cr.Timespan != 15*time.Minute {
		t.Errorf("timespan = %v, want 15m", cr.Timespan)
	}
}

func TestParseGenericCorrelationFromYAML(t *testing.T) {
	// Tests that existing "type: correlation" rules still parse correctly.
	yamlContent := `
title: EDR Credential Theft to NDR Lateral Movement Correlation
id: generic-corr-001
type: correlation
rules:
  - rule-a
  - rule-b
group-by:
  - source.ip
timespan: 30m
ordered: true
condition:
  gte: 2
level: critical
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlContent))
	if err != nil {
		t.Fatalf("YAML parse error: %v", err)
	}

	cr, err := ParseCorrelationRule(rules[0])
	if err != nil {
		t.Fatalf("correlation parse error: %v", err)
	}

	// Should be inferred as temporal (ordered: true).
	if cr.Type != CorrelationTemporal {
		t.Errorf("inferred type = %q, want %q", cr.Type, CorrelationTemporal)
	}
}

// --- ParseCorrelationRules batch test ---

func TestParseCorrelationRules(t *testing.T) {
	sigmaRules := []*SigmaRule{
		{
			ID:               "ec-batch",
			Title:            "Event Count",
			Type:             "event_count",
			CorrelationRules: []string{"rule-a"},
			Timespan:         "5m",
			CorrelationCond:  map[string]int{"gte": 3},
		},
		{
			// Invalid — temporal without ordered.
			ID:               "bad-batch",
			Title:            "Bad Temporal",
			Type:             "temporal",
			CorrelationRules: []string{"rule-a", "rule-b"},
			GroupBy:          []string{"user.name"},
			Timespan:         "10m",
			CorrelationCond:  map[string]int{"gte": 2},
		},
		{
			ID:               "temp-batch",
			Title:            "Good Temporal",
			Type:             "temporal",
			CorrelationRules: []string{"rule-a", "rule-b"},
			GroupBy:          []string{"user.name"},
			Timespan:         "10m",
			Ordered:          true,
			CorrelationCond:  map[string]int{"gte": 2},
		},
		{
			// Not a correlation rule — should be filtered out by registry.
			ID:    "single-event",
			Title: "Not Correlation",
			Type:  "",
		},
	}

	registry := NewRuleRegistry(sigmaRules)
	rules, errs := ParseCorrelationRules(registry)

	// Should get 2 valid correlation rules (ec-batch and temp-batch).
	if len(rules) != 2 {
		t.Errorf("expected 2 parsed rules, got %d", len(rules))
	}

	// Should get 1 error (bad-batch).
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

// --- isCorrelationType tests ---

func TestIsCorrelationType(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"correlation", true},
		{"event_count", true},
		{"value_count", true},
		{"temporal", true},
		{"", false},
		{"single", false},
		{"unknown", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := isCorrelationType(tc.input); got != tc.expected {
				t.Errorf("isCorrelationType(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
