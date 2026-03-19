package correlate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Basic parsing tests ---

func TestParseMinimalRule(t *testing.T) {
	yaml := `
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
status: experimental
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: process_create
  condition: selection
level: medium
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Title != "Test Rule" {
		t.Errorf("title = %q, want 'Test Rule'", r.Title)
	}
	if r.ID != "12345678-1234-1234-1234-123456789abc" {
		t.Errorf("id = %q", r.ID)
	}
	if r.Status != "experimental" {
		t.Errorf("status = %q", r.Status)
	}
	if r.Level != "medium" {
		t.Errorf("level = %q", r.Level)
	}
	if r.Logsource.Product != "akeso_edr" {
		t.Errorf("product = %q", r.Logsource.Product)
	}
	if r.Detection == nil {
		t.Fatal("detection is nil")
	}
	if r.Detection.Condition != "selection" {
		t.Errorf("condition = %q", r.Detection.Condition)
	}
	if len(r.Detection.Selections) != 1 {
		t.Fatalf("expected 1 selection, got %d", len(r.Detection.Selections))
	}

	sel, ok := r.Detection.Selections["selection"]
	if !ok {
		t.Fatal("missing 'selection'")
	}
	if len(sel) != 1 {
		t.Fatalf("expected 1 event matcher, got %d", len(sel))
	}
	if len(sel[0].FieldMatchers) != 1 {
		t.Fatalf("expected 1 field matcher, got %d", len(sel[0].FieldMatchers))
	}

	fm := sel[0].FieldMatchers[0]
	if fm.Field != "event.action" {
		t.Errorf("field = %q", fm.Field)
	}
	if len(fm.Modifiers) != 0 {
		t.Errorf("modifiers = %v, want empty", fm.Modifiers)
	}
	if len(fm.Values) != 1 || fm.Values[0] != "process_create" {
		t.Errorf("values = %v", fm.Values)
	}
}

func TestParseMetadataFields(t *testing.T) {
	yaml := `
title: Full Metadata Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: test
description: A test rule with all metadata fields populated.
author: TestAuthor
date: 2026/03/15
references:
  - https://example.com/ref1
  - https://example.com/ref2
tags:
  - attack.execution
  - attack.t1059
level: high
falsepositives:
  - Legitimate admin scripts
  - Penetration testing
logsource:
  category: process_creation
  product: windows
  service: sysmon
detection:
  selection:
    process.name: cmd.exe
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	r := rules[0]
	if r.Author != "TestAuthor" {
		t.Errorf("author = %q", r.Author)
	}
	if r.Date != "2026/03/15" {
		t.Errorf("date = %q", r.Date)
	}
	if len(r.References) != 2 {
		t.Errorf("references count = %d", len(r.References))
	}
	if len(r.Tags) != 2 || r.Tags[0] != "attack.execution" {
		t.Errorf("tags = %v", r.Tags)
	}
	if len(r.FalsePositives) != 2 {
		t.Errorf("falsepositives count = %d", len(r.FalsePositives))
	}
	if r.Logsource.Category != "process_creation" {
		t.Errorf("category = %q", r.Logsource.Category)
	}
	if r.Logsource.Product != "windows" {
		t.Errorf("product = %q", r.Logsource.Product)
	}
	if r.Logsource.Service != "sysmon" {
		t.Errorf("service = %q", r.Logsource.Service)
	}
}

// --- Multi-document tests ---

func TestParseMultiDocYAML(t *testing.T) {
	yaml := `
title: Component Rule 1
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: process_create
  condition: selection
---
title: Component Rule 2
id: 22222222-2222-2222-2222-222222222222
status: experimental
logsource:
  product: akeso_av
detection:
  selection:
    av.scan.result: malicious
  condition: selection
---
title: Correlation Rule
id: 33333333-3333-3333-3333-333333333333
type: correlation
status: experimental
rules:
  - 11111111-1111-1111-1111-111111111111
  - 22222222-2222-2222-2222-222222222222
group-by:
  - host.name
timespan: 5m
condition:
  gte: 2
level: high
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	// First two are single-event rules.
	if rules[0].Type == "correlation" {
		t.Error("rule 0 should not be correlation")
	}
	if rules[1].Type == "correlation" {
		t.Error("rule 1 should not be correlation")
	}

	// Third is correlation.
	corr := rules[2]
	if corr.Type != "correlation" {
		t.Fatalf("rule 2 type = %q, want correlation", corr.Type)
	}
	if len(corr.CorrelationRules) != 2 {
		t.Errorf("correlation rules = %d", len(corr.CorrelationRules))
	}
	if len(corr.GroupBy) != 1 || corr.GroupBy[0] != "host.name" {
		t.Errorf("group-by = %v", corr.GroupBy)
	}
	if corr.Timespan != "5m" {
		t.Errorf("timespan = %q", corr.Timespan)
	}
	if corr.Level != "high" {
		t.Errorf("level = %q", corr.Level)
	}
	if v, ok := corr.CorrelationCond["gte"]; !ok || v != 2 {
		t.Errorf("correlation condition = %v", corr.CorrelationCond)
	}
}

func TestParseCorrelationOrdered(t *testing.T) {
	yaml := `
title: Ordered Correlation
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
type: correlation
status: experimental
rules:
  - 11111111-1111-1111-1111-111111111111
  - 22222222-2222-2222-2222-222222222222
group-by:
  - user.name
timespan: 120m
ordered: true
condition:
  gte: 4
level: critical
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !rules[0].Ordered {
		t.Error("ordered should be true")
	}
	if rules[0].Timespan != "120m" {
		t.Errorf("timespan = %q", rules[0].Timespan)
	}
}

// --- Detection block variations ---

func TestParseMultipleFieldsAND(t *testing.T) {
	yaml := `
title: Multi Field AND
id: 00000000-0000-0000-0000-000000000001
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: process_create
    process.name: cmd.exe
    event.kind: event
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	if len(sel) != 1 {
		t.Fatalf("expected 1 matcher, got %d", len(sel))
	}
	if len(sel[0].FieldMatchers) != 3 {
		t.Errorf("expected 3 field matchers (AND), got %d", len(sel[0].FieldMatchers))
	}
}

func TestParseListValuesOR(t *testing.T) {
	yaml := `
title: List Values OR
id: 00000000-0000-0000-0000-000000000002
logsource:
  product: akeso_edr
detection:
  selection:
    event.action:
      - process_create
      - process_terminate
      - image_load
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm := findFieldMatcher(sel[0], "event.action")
	if fm == nil {
		t.Fatal("missing event.action field matcher")
	}
	if len(fm.Values) != 3 {
		t.Errorf("expected 3 values (OR), got %d", len(fm.Values))
	}
}

func TestParseModifiers(t *testing.T) {
	yaml := `
title: Modifier Test
id: 00000000-0000-0000-0000-000000000003
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|contains:
      - scanner_match
      - rule_engine_alert
    destination.ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
    process.command_line|re: '.*powershell.*-enc.*'
    process.name|startswith: cmd
    file.path|endswith: .exe
    event.action|contains|all:
      - suspicious
      - network
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	em := sel[0]

	tests := []struct {
		field     string
		modifiers []string
		valueLen  int
	}{
		{"event.action", []string{"contains"}, 2},
		{"destination.ip", []string{"cidr"}, 2},
		{"process.command_line", []string{"re"}, 1},
		{"process.name", []string{"startswith"}, 1},
		{"file.path", []string{"endswith"}, 1},
		{"event.action", []string{"contains", "all"}, 2},
	}

	for _, tc := range tests {
		fm := findFieldMatcherWithModifiers(em, tc.field, tc.modifiers)
		if fm == nil {
			t.Errorf("missing field matcher: %s|%s", tc.field, strings.Join(tc.modifiers, "|"))
			continue
		}
		if len(fm.Values) != tc.valueLen {
			t.Errorf("%s|%s: expected %d values, got %d", tc.field, strings.Join(tc.modifiers, "|"), tc.valueLen, len(fm.Values))
		}
	}
}

func TestParseMultipleSelections(t *testing.T) {
	yaml := `
title: Selection with Filter
id: 00000000-0000-0000-0000-000000000004
logsource:
  product: akeso_edr
detection:
  selection:
    event.category: network
    network.direction: outbound
  filter_internal:
    destination.ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and not filter_internal
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	det := rules[0].Detection
	if len(det.Selections) != 2 {
		t.Fatalf("expected 2 selections, got %d", len(det.Selections))
	}

	if _, ok := det.Selections["selection"]; !ok {
		t.Error("missing 'selection'")
	}
	if _, ok := det.Selections["filter_internal"]; !ok {
		t.Error("missing 'filter_internal'")
	}

	if det.Condition != "selection and not filter_internal" {
		t.Errorf("condition = %q", det.Condition)
	}

	// Filter should have CIDR values.
	filter := det.Selections["filter_internal"]
	fm := findFieldMatcher(filter[0], "destination.ip")
	if fm == nil {
		t.Fatal("missing destination.ip in filter")
	}
	if len(fm.Values) != 3 {
		t.Errorf("expected 3 CIDR values, got %d", len(fm.Values))
	}
	if len(fm.Modifiers) != 1 || fm.Modifiers[0] != "cidr" {
		t.Errorf("modifiers = %v", fm.Modifiers)
	}
}

func TestParseSelectionListOfMaps(t *testing.T) {
	yaml := `
title: List of Maps (OR of ANDs)
id: 00000000-0000-0000-0000-000000000005
logsource:
  product: akeso_edr
detection:
  selection:
    - event.action: foo
      process.name: bar
    - event.action: baz
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	if len(sel) != 2 {
		t.Fatalf("expected 2 event matchers (OR), got %d", len(sel))
	}
	if len(sel[0].FieldMatchers) != 2 {
		t.Errorf("first matcher: expected 2 fields (AND), got %d", len(sel[0].FieldMatchers))
	}
	if len(sel[1].FieldMatchers) != 1 {
		t.Errorf("second matcher: expected 1 field, got %d", len(sel[1].FieldMatchers))
	}
}

// --- Adversarial tests ---

func TestParseMissingCondition(t *testing.T) {
	yaml := `
title: No Condition
id: 00000000-0000-0000-0000-000000000010
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: process_create
`
	_, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for missing condition")
	}
}

func TestParseEmptyDocument(t *testing.T) {
	// An empty YAML document should be skipped gracefully.
	yaml := `---
---
title: After Empty
id: 00000000-0000-0000-0000-000000000011
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (empty docs skipped), got %d", len(rules))
	}
}

func TestParseNullValue(t *testing.T) {
	yaml := `
title: Null Value
id: 00000000-0000-0000-0000-000000000012
logsource:
  product: windows
detection:
  selection:
    process.parent.name: null
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm := findFieldMatcher(sel[0], "process.parent.name")
	if fm == nil {
		t.Fatal("missing field matcher")
	}
	// null should be preserved as nil.
	if len(fm.Values) != 1 || fm.Values[0] != nil {
		t.Errorf("expected [nil], got %v", fm.Values)
	}
}

func TestParseIntegerValues(t *testing.T) {
	yaml := `
title: Integer Values
id: 00000000-0000-0000-0000-000000000013
logsource:
  product: windows
detection:
  selection:
    event.severity: 4
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm := findFieldMatcher(sel[0], "event.severity")
	if fm == nil {
		t.Fatal("missing field matcher")
	}
	if len(fm.Values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(fm.Values))
	}
	// yaml.v3 decodes plain integers as int.
	if _, ok := fm.Values[0].(int); !ok {
		t.Errorf("expected int, got %T: %v", fm.Values[0], fm.Values[0])
	}
}

func TestParseBooleanValues(t *testing.T) {
	yaml := `
title: Boolean Values
id: 00000000-0000-0000-0000-000000000014
logsource:
  product: windows
detection:
  selection:
    kerberos.success: true
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm := findFieldMatcher(sel[0], "kerberos.success")
	if fm == nil {
		t.Fatal("missing field matcher")
	}
	if len(fm.Values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(fm.Values))
	}
	if v, ok := fm.Values[0].(bool); !ok || !v {
		t.Errorf("expected true, got %v (%T)", fm.Values[0], fm.Values[0])
	}
}

func TestParseMetadataOnlyDocument(t *testing.T) {
	// Top-level metadata doc (no detection block) should parse without error.
	yaml := `
title: Metadata Only
id: 00000000-0000-0000-0000-000000000015
status: experimental
description: Just metadata, no detection.
level: high
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Detection != nil {
		t.Error("expected nil detection for metadata-only doc")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	yaml := `{not valid yaml: [[[`
	_, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseDeepFieldNames(t *testing.T) {
	yaml := `
title: Deep Fields
id: 00000000-0000-0000-0000-000000000016
logsource:
  product: akeso_edr
detection:
  selection:
    process.parent.name: explorer.exe
    tls.client.server_name: evil.com
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm1 := findFieldMatcher(sel[0], "process.parent.name")
	fm2 := findFieldMatcher(sel[0], "tls.client.server_name")
	if fm1 == nil {
		t.Error("missing process.parent.name")
	}
	if fm2 == nil {
		t.Error("missing tls.client.server_name")
	}
}

func TestParseModifierChain(t *testing.T) {
	yaml := `
title: Modifier Chain
id: 00000000-0000-0000-0000-000000000017
logsource:
  product: windows
detection:
  selection:
    process.command_line|base64|contains: cG93ZXJzaGVsbA==
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sel := rules[0].Detection.Selections["selection"]
	fm := findFieldMatcherWithModifiers(sel[0], "process.command_line", []string{"base64", "contains"})
	if fm == nil {
		t.Fatal("missing field matcher with base64|contains chain")
	}
}

// --- RuleRegistry tests ---

func TestRuleRegistry(t *testing.T) {
	rules := []*SigmaRule{
		{ID: "aaa", Title: "Rule A", Type: ""},
		{ID: "bbb", Title: "Rule B", Type: ""},
		{ID: "ccc", Title: "Rule C", Type: "correlation"},
	}

	reg := NewRuleRegistry(rules)

	if reg.Count() != 3 {
		t.Errorf("count = %d, want 3", reg.Count())
	}

	if r := reg.Get("aaa"); r == nil || r.Title != "Rule A" {
		t.Error("Get('aaa') failed")
	}
	if r := reg.Get("nonexistent"); r != nil {
		t.Error("Get('nonexistent') should return nil")
	}

	single := reg.SingleEventRules()
	if len(single) != 2 {
		t.Errorf("single event rules = %d, want 2", len(single))
	}

	corr := reg.CorrelationRules()
	if len(corr) != 1 {
		t.Errorf("correlation rules = %d, want 1", len(corr))
	}
}

func TestRuleRegistryEmptyID(t *testing.T) {
	rules := []*SigmaRule{
		{Title: "No ID Rule"},
	}
	reg := NewRuleRegistry(rules)

	if reg.Count() != 1 {
		t.Errorf("count = %d", reg.Count())
	}
	// Should not panic on empty-ID lookup.
	if r := reg.Get(""); r != nil {
		t.Error("empty ID lookup should return nil")
	}
}

// --- ParseError tests ---

func TestParseError(t *testing.T) {
	err := &ParseError{
		File:     "test.yml",
		DocIndex: 2,
		Err:      fmt.Errorf("bad field"),
	}
	if !strings.Contains(err.Error(), "test.yml") {
		t.Errorf("error string missing file: %s", err.Error())
	}
	if err.Unwrap().Error() != "bad field" {
		t.Errorf("unwrap failed")
	}
}

// --- Directory loading tests ---

func TestLoadRulesFromDir(t *testing.T) {
	// Create a temp directory with test rule files.
	dir := t.TempDir()

	// Valid rule file.
	writeTestFile(t, dir, "valid.yml", `
title: Valid Rule
id: 00000000-0000-0000-0000-000000000020
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
`)

	// Another valid file with multi-doc.
	writeTestFile(t, dir, "multi.yml", `
title: Multi Rule 1
id: 00000000-0000-0000-0000-000000000021
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
---
title: Multi Rule 2
id: 00000000-0000-0000-0000-000000000022
logsource:
  product: akeso_av
detection:
  selection:
    av.scan.result: malicious
  condition: selection
`)

	// Invalid file.
	writeTestFile(t, dir, "invalid.yml", `{not valid yaml: [[[`)

	// Non-YAML file (should be ignored).
	writeTestFile(t, dir, "readme.txt", "This is not a YAML file.")

	rules, errs := LoadRulesFromDir(dir)

	// Should have 3 rules from 2 valid files.
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}

	// Should have 1 error from the invalid file.
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

func TestLoadRulesFromDirNested(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	os.MkdirAll(subdir, 0755)

	writeTestFile(t, dir, "top.yml", `
title: Top Level
id: 00000000-0000-0000-0000-000000000030
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
`)

	writeTestFile(t, subdir, "nested.yml", `
title: Nested Rule
id: 00000000-0000-0000-0000-000000000031
logsource:
  product: akeso_av
detection:
  selection:
    av.scan.result: malicious
  condition: selection
`)

	rules, errs := LoadRulesFromDir(dir)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules (top + nested), got %d", len(rules))
	}
}

func TestLoadRulesFromDirEmpty(t *testing.T) {
	dir := t.TempDir()

	rules, errs := LoadRulesFromDir(dir)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

// --- Parsing existing project rules ---

func TestParseProjectRules(t *testing.T) {
	// Parse all existing rules in the akeso_portfolio directory.
	rulesDir := filepath.Join("..", "..", "rules", "akeso_portfolio")
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Skip("rules directory not found (expected when running from different working dir)")
	}

	rules, errs := LoadRulesFromDir(rulesDir)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("parse error: %v", e)
		}
	}

	// We have 10 files with multi-doc YAML. Each has 3-5 documents.
	// At minimum we expect 30+ rules.
	if len(rules) < 20 {
		t.Errorf("expected at least 20 rules from akeso_portfolio, got %d", len(rules))
	}

	// Verify we got both single-event and correlation rules.
	reg := NewRuleRegistry(rules)
	single := reg.SingleEventRules()
	corr := reg.CorrelationRules()

	if len(single) == 0 {
		t.Error("expected single-event rules")
	}
	if len(corr) == 0 {
		t.Error("expected correlation rules")
	}

	t.Logf("Parsed %d rules (%d single-event, %d correlation) from akeso_portfolio",
		len(rules), len(single), len(corr))
}

// --- SigmaHQ compatibility test (50+ rules) ---

func TestParseSigmaHQRules(t *testing.T) {
	// Generate 50 SigmaHQ-style rules in a temp directory and parse them all.
	dir := t.TempDir()

	for i := 0; i < 50; i++ {
		rule := generateSigmaHQRule(i)
		writeTestFile(t, dir, fmt.Sprintf("rule_%03d.yml", i), rule)
	}

	rules, errs := LoadRulesFromDir(dir)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("parse error: %v", e)
		}
		t.Fatalf("expected 0 errors parsing SigmaHQ-style rules, got %d", len(errs))
	}

	if len(rules) != 50 {
		t.Fatalf("expected 50 rules, got %d", len(rules))
	}

	// Spot-check a few rules.
	for i, r := range rules {
		if r.ID == "" {
			t.Errorf("rule %d: empty ID", i)
		}
		if r.Title == "" {
			t.Errorf("rule %d: empty title", i)
		}
		if r.Detection == nil {
			t.Errorf("rule %d: nil detection", i)
		}
		if r.Detection != nil && r.Detection.Condition == "" {
			t.Errorf("rule %d: empty condition", i)
		}
		if r.Logsource.Product == "" && r.Logsource.Category == "" {
			t.Errorf("rule %d: no logsource product or category", i)
		}
	}

	t.Logf("Successfully parsed all 50 SigmaHQ-style rules")
}

// --- Helpers ---

func findFieldMatcher(em SigmaEventMatcher, field string) *SigmaFieldMatcher {
	for i := range em.FieldMatchers {
		if em.FieldMatchers[i].Field == field {
			return &em.FieldMatchers[i]
		}
	}
	return nil
}

func findFieldMatcherWithModifiers(em SigmaEventMatcher, field string, modifiers []string) *SigmaFieldMatcher {
	for i := range em.FieldMatchers {
		fm := &em.FieldMatchers[i]
		if fm.Field != field {
			continue
		}
		if len(fm.Modifiers) != len(modifiers) {
			continue
		}
		match := true
		for j := range modifiers {
			if fm.Modifiers[j] != modifiers[j] {
				match = false
				break
			}
		}
		if match {
			return fm
		}
	}
	return nil
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	if err != nil {
		t.Fatalf("writing test file %s: %v", name, err)
	}
}

// generateSigmaHQRule creates a realistic SigmaHQ-style rule YAML string.
// Varies structure across the 50 rules to cover different detection patterns.
func generateSigmaHQRule(index int) string {
	id := fmt.Sprintf("deadbeef-cafe-babe-f00d-%012x", index)

	switch index % 10 {
	case 0: // Simple single selection
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Suspicious Process Creation"
id: %s
status: test
description: Detects suspicious process creation
author: SigmaHQ
date: 2024/01/15
references:
  - https://attack.mitre.org/techniques/T1059/
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name:
      - cmd.exe
      - powershell.exe
      - wscript.exe
  condition: selection
falsepositives:
  - Legitimate admin activity
level: medium
`, index, id)

	case 1: // Selection with filter
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Outbound Connection"
id: %s
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    network.direction: outbound
  filter_local:
    destination.ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and not filter_local
level: low
`, index, id)

	case 2: // Contains modifier
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Encoded PowerShell"
id: %s
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.command_line|contains:
      - "-enc"
      - "-encodedcommand"
      - "frombase64string"
  condition: selection
level: high
`, index, id)

	case 3: // Multiple selections OR
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Credential Access"
id: %s
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_lsass:
    process.name: lsass.exe
    event.action: process_access
  selection_sam:
    process.name: reg.exe
    process.command_line|contains: "\\sam"
  condition: selection_lsass or selection_sam
level: high
`, index, id)

	case 4: // Startswith/endswith
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Suspicious File Drop"
id: %s
status: test
logsource:
  category: file_event
  product: windows
detection:
  selection:
    file.path|startswith:
      - "C:\\Users\\"
      - "C:\\Temp\\"
    file.name|endswith:
      - .exe
      - .dll
      - .scr
  condition: selection
level: medium
`, index, id)

	case 5: // DNS query
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Suspicious DNS Query"
id: %s
status: experimental
logsource:
  category: dns
  product: windows
detection:
  selection:
    dns.question.name|endswith:
      - .onion
      - .bit
      - .bazar
  condition: selection
level: high
`, index, id)

	case 6: // Integer value
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - High Severity Event"
id: %s
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    event.severity: 4
    event.action: logon_failure
  condition: selection
level: medium
`, index, id)

	case 7: // Regex modifier
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Suspicious User Agent"
id: %s
status: experimental
logsource:
  category: proxy
  product: windows
detection:
  selection:
    user_agent.original|re: "(curl|wget|python-requests)/.*"
  condition: selection
level: medium
`, index, id)

	case 8: // List of maps
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Service Install OR Scheduled Task"
id: %s
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    - process.name: sc.exe
      process.command_line|contains: create
    - process.name: schtasks.exe
      process.command_line|contains: /create
  condition: selection
level: medium
`, index, id)

	case 9: // Three selections with complex condition
		return fmt.Sprintf(`
title: "SigmaHQ Rule %d - Lateral Movement Indicators"
id: %s
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_psexec:
    process.name: psexec.exe
  selection_wmi:
    process.name: wmic.exe
    process.command_line|contains: "/node:"
  filter_legitimate:
    user.name|endswith: "$"
  condition: (selection_psexec or selection_wmi) and not filter_legitimate
level: high
`, index, id)
	}

	// Fallback (should never reach here with mod 10).
	return ""
}

// TestLoadAllProjectRules verifies that all rules from both sigma_curated and
// akeso_portfolio directories parse and compile successfully.
// Acceptance criteria: 50 sigma_curated + 10 akeso_portfolio files = 60 total.
func TestLoadAllProjectRules(t *testing.T) {
	projectRoot := filepath.Join("..", "..", "rules")

	// Load sigma_curated rules.
	sigmaRules, sigmaErrs := LoadRulesFromDir(filepath.Join(projectRoot, "sigma_curated"))
	for _, e := range sigmaErrs {
		t.Errorf("sigma_curated parse error: %v", e)
	}
	if len(sigmaRules) != 50 {
		t.Fatalf("expected 50 sigma_curated rules, got %d", len(sigmaRules))
	}

	// Load akeso_portfolio rules.
	portfolioRules, portfolioErrs := LoadRulesFromDir(filepath.Join(projectRoot, "akeso_portfolio"))
	for _, e := range portfolioErrs {
		t.Errorf("akeso_portfolio parse error: %v", e)
	}
	if len(portfolioRules) < 30 {
		t.Fatalf("expected at least 30 akeso_portfolio rules (multi-doc YAML), got %d", len(portfolioRules))
	}

	// Verify all rules compile in the engine.
	allRules := append(sigmaRules, portfolioRules...)
	reg := NewRuleRegistry(allRules)
	single := reg.SingleEventRules()
	corr := reg.CorrelationRules()

	if len(single) == 0 {
		t.Error("expected single-event rules")
	}
	if len(corr) == 0 {
		t.Error("expected correlation rules")
	}

	// Verify each single-event rule with a detection block compiles.
	var compileErrors int
	for _, r := range single {
		if r.Detection == nil {
			continue // Correlation metadata-only documents have no detection.
		}
		if _, err := CompileDetection(r.Detection); err != nil {
			t.Errorf("compile error for %q (%s): %v", r.Title, r.ID, err)
			compileErrors++
		}
	}
	if compileErrors > 0 {
		t.Fatalf("%d rules failed to compile", compileErrors)
	}

	// Verify unique IDs.
	idSet := make(map[string]string)
	for _, r := range allRules {
		if prev, dup := idSet[r.ID]; dup {
			t.Errorf("duplicate rule ID %q: %q and %q", r.ID, prev, r.Title)
		}
		idSet[r.ID] = r.Title
	}

	t.Logf("Loaded %d total rules: %d sigma_curated + %d akeso_portfolio (%d single-event, %d correlation)",
		len(allRules), len(sigmaRules), len(portfolioRules), len(single), len(corr))
}

