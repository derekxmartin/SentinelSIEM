package correlate

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// --- Test helpers ---

// testLogsourceMap returns a LogsourceMap with the standard project mappings.
func testEngineLogsourceMap(t *testing.T) *LogsourceMap {
	t.Helper()
	yamlData := `
mappings:
  - logsource:
      product: akeso_edr
    conditions:
      source_type: akeso_edr
  - logsource:
      product: akeso_av
    conditions:
      source_type: akeso_av
  - logsource:
      product: akeso_dlp
    conditions:
      source_type: akeso_dlp
  - logsource:
      product: akeso_ndr
    conditions:
      source_type: akeso_ndr
  - logsource:
      category: dns
    conditions:
      event.category: network
      event.action: dns_query
  - logsource:
      category: malware
    conditions:
      event.category: malware
  - logsource:
      category: process_creation
    conditions:
      event.category: process
      event.type: start
  - logsource:
      category: network_connection
    conditions:
      event.category: network
      event.type: connection
  - logsource:
      product: windows
      service: sysmon
    conditions:
      source_type: winevt
      winevt.channel: Microsoft-Windows-Sysmon/Operational
  - logsource:
      product: windows
      service: security
    conditions:
      source_type: winevt
      winevt.channel: Security
`
	lsMap, err := ParseLogsourceMap([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse test logsource map: %v", err)
	}
	return lsMap
}

// parseTestRules parses a YAML string into a rule registry.
func parseTestRules(t *testing.T, yamlStr string) *RuleRegistry {
	t.Helper()
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("failed to parse test rules: %v", err)
	}
	return NewRuleRegistry(rules)
}

// --- Happy path tests ---

func TestRuleEngine_SingleRuleMatch(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Alert Detection
id: test-rule-001
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
tags:
  - attack.execution
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "test-rule-001" {
		t.Errorf("expected rule ID test-rule-001, got %q", alerts[0].RuleID)
	}
	if alerts[0].Title != "EDR Alert Detection" {
		t.Errorf("expected title 'EDR Alert Detection', got %q", alerts[0].Title)
	}
	if alerts[0].Level != "high" {
		t.Errorf("expected level high, got %q", alerts[0].Level)
	}
	if len(alerts[0].Tags) != 1 || alerts[0].Tags[0] != "attack.execution" {
		t.Errorf("expected tags [attack.execution], got %v", alerts[0].Tags)
	}
	if alerts[0].Event != event {
		t.Error("expected alert to reference the original event")
	}
}

func TestRuleEngine_SingleRuleNoMatch_WrongLogsource(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Alert Detection
id: test-rule-001
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// DLP event should not trigger EDR rule.
	event := &common.ECSEvent{
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for wrong logsource, got %d", len(alerts))
	}
}

func TestRuleEngine_MultipleRules_SameLogsource(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Rule A
id: test-rule-a
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
---
title: EDR Rule B
id: test-rule-b
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: rule_engine_alert
  condition: selection
level: medium
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// Only rule A should match.
	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "test-rule-a" {
		t.Errorf("expected test-rule-a, got %q", alerts[0].RuleID)
	}
}

func TestRuleEngine_MultipleRules_DifferentLogsources(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Rule
id: edr-rule
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
---
title: AV Rule
id: av-rule
logsource:
  product: akeso_av
detection:
  selection:
    event.action: scan_result
    av.scan.result: malicious
  condition: selection
level: critical
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// AV event should only trigger AV rule.
	event := &common.ECSEvent{
		SourceType: "akeso_av",
		Event:      &common.EventFields{Action: "scan_result"},
		AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "av-rule" {
		t.Errorf("expected av-rule, got %q", alerts[0].RuleID)
	}
}

func TestRuleEngine_CategoryLevel_CrossProduct(t *testing.T) {
	registry := parseTestRules(t, `
title: Process Creation Detection
id: proc-create-rule
logsource:
  category: process_creation
detection:
  selection:
    process.name: powershell.exe
  condition: selection
level: medium
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// EDR process creation event.
	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "powershell.exe"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for EDR process creation, got %d", len(alerts))
	}
	if alerts[0].RuleID != "proc-create-rule" {
		t.Errorf("expected proc-create-rule, got %q", alerts[0].RuleID)
	}

	// Non-process-creation event should not match.
	event2 := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Category: []string{"network"}, Type: []string{"connection"}},
		Process:    &common.ProcessFields{Name: "powershell.exe"},
	}
	alerts2 := engine.Evaluate(event2)
	if len(alerts2) != 0 {
		t.Errorf("expected 0 alerts for non-process-creation event, got %d", len(alerts2))
	}
}

// --- Edge case tests ---

func TestRuleEngine_NoDetectionBlock(t *testing.T) {
	registry := parseTestRules(t, `
title: Metadata Only Document
id: metadata-only
status: experimental
description: This document has no detection block
level: informational
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.RulesCompiled != 0 {
		t.Errorf("expected 0 compiled rules, got %d", stats.RulesCompiled)
	}
	if stats.RulesSkipped != 1 {
		t.Errorf("expected 1 skipped rule, got %d", stats.RulesSkipped)
	}
}

func TestRuleEngine_UnmappedLogsource(t *testing.T) {
	registry := parseTestRules(t, `
title: Unknown Product Rule
id: unknown-rule
logsource:
  product: unknownproduct
detection:
  selection:
    event.action: something
  condition: selection
level: low
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.RulesCompiled != 0 {
		t.Errorf("expected 0 compiled rules for unmapped logsource, got %d", stats.RulesCompiled)
	}
	if stats.RulesSkipped != 1 {
		t.Errorf("expected 1 skipped rule, got %d", stats.RulesSkipped)
	}
}

func TestRuleEngine_InvalidRegexSkipped(t *testing.T) {
	registry := parseTestRules(t, `
title: Bad Regex Rule
id: bad-regex
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|re: "[invalid"
  condition: selection
level: high
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.RulesCompiled != 0 {
		t.Errorf("expected 0 compiled rules, got %d", stats.RulesCompiled)
	}
	if len(stats.CompileErrors) != 1 {
		t.Errorf("expected 1 compile error, got %d", len(stats.CompileErrors))
	}
}

func TestRuleEngine_EmptyRegistry(t *testing.T) {
	registry := NewRuleRegistry(nil)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.TotalRulesLoaded != 0 {
		t.Errorf("expected 0 total rules, got %d", stats.TotalRulesLoaded)
	}

	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "test"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts from empty engine, got %d", len(alerts))
	}
}

func TestRuleEngine_CorrelationRulesExcluded(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Behavioral Detection
id: edr-behavioral
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|contains: scanner_match
    event.kind: alert
  condition: selection
level: high
---
title: AV Malicious Scan Result
id: av-malicious
logsource:
  product: akeso_av
detection:
  selection:
    event.action: scan_result
    av.scan.result: malicious
  condition: selection
level: high
---
title: Correlation Rule
id: correlation-rule
type: correlation
rules:
  - edr-behavioral
  - av-malicious
group-by:
  - host.name
timespan: 5m
condition:
  gte: 2
level: high
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	// 3 total single-event rules (correlation excluded by SingleEventRules).
	// But first doc (metadata) + correlation doc are excluded differently.
	if stats.RulesCompiled != 2 {
		t.Errorf("expected 2 compiled rules (correlation excluded), got %d", stats.RulesCompiled)
	}
}

// --- Adversarial tests ---

func TestRuleEngine_NilEvent(t *testing.T) {
	registry := parseTestRules(t, `
title: Test Rule
id: test-nil
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
level: low
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	alerts := engine.Evaluate(nil)
	if alerts != nil {
		t.Errorf("expected nil for nil event, got %v", alerts)
	}
}

func TestRuleEngine_EmptyEvent(t *testing.T) {
	registry := parseTestRules(t, `
title: Test Rule
id: test-empty
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
level: low
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	event := &common.ECSEvent{}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for empty event, got %d", len(alerts))
	}
}

func TestRuleEngine_LogsourceMatchButDetectionMiss(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Specific Detection
id: edr-specific
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: very_specific_action
  condition: selection
level: medium
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// EDR event with different action — logsource matches but detection doesn't.
	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "different_action"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts (detection miss), got %d", len(alerts))
	}
}

func TestRuleEngine_WildcardLogsource(t *testing.T) {
	// Rule with no logsource fields should match all events.
	rules := []*SigmaRule{
		{
			ID:    "wildcard-rule",
			Title: "Wildcard Rule",
			Level: "low",
			Detection: &SigmaDetection{
				Selections: map[string]SigmaSelection{
					"selection": {{FieldMatchers: []SigmaFieldMatcher{
						{Field: "event.action", Values: []interface{}{"universal_action"}},
					}}},
				},
				Condition: "selection",
			},
		},
	}
	registry := NewRuleRegistry(rules)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.RulesCompiled != 1 {
		t.Fatalf("expected 1 compiled wildcard rule, got %d", stats.RulesCompiled)
	}

	// Any source type should match.
	for _, srcType := range []string{"akeso_edr", "akeso_av", "unknown"} {
		event := &common.ECSEvent{
			SourceType: srcType,
			Event:      &common.EventFields{Action: "universal_action"},
		}
		alerts := engine.Evaluate(event)
		if len(alerts) != 1 {
			t.Errorf("expected 1 alert for wildcard rule with source_type=%s, got %d", srcType, len(alerts))
		}
	}

	// Detection miss should still not fire.
	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "other_action"},
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for wildcard rule detection miss, got %d", len(alerts))
	}
}

// --- Stats test ---

func TestRuleEngine_Stats(t *testing.T) {
	registry := parseTestRules(t, `
title: Good Rule
id: good-rule
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: test
  condition: selection
level: medium
---
title: Bad Regex Rule
id: bad-regex
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|re: "[invalid"
  condition: selection
level: high
---
title: Unmapped Rule
id: unmapped
logsource:
  product: nonexistent_product
detection:
  selection:
    event.action: test
  condition: selection
level: low
---
title: Metadata Only
id: metadata-only
description: No detection block
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	stats := engine.Stats()
	if stats.TotalRulesLoaded != 4 {
		t.Errorf("expected 4 total loaded, got %d", stats.TotalRulesLoaded)
	}
	if stats.RulesCompiled != 1 {
		t.Errorf("expected 1 compiled, got %d", stats.RulesCompiled)
	}
	if stats.RulesSkipped != 3 {
		t.Errorf("expected 3 skipped, got %d", stats.RulesSkipped)
	}
	if len(stats.CompileErrors) != 1 {
		t.Errorf("expected 1 compile error, got %d", len(stats.CompileErrors))
	}
	if stats.BucketCount != 1 {
		t.Errorf("expected 1 bucket, got %d", stats.BucketCount)
	}
}

// --- Integration test with real project rules ---

func TestRuleEngine_ProjectRules(t *testing.T) {
	rules, parseErrors := LoadRulesFromDir("../../rules/akeso_portfolio")
	if len(parseErrors) > 0 {
		for _, pe := range parseErrors {
			t.Logf("parse error: %v", pe.Error())
		}
	}
	if len(rules) == 0 {
		t.Skip("no rules found in akeso_portfolio")
	}

	lsMap, err := LoadLogsourceMap("../../parsers/logsource_map.yaml")
	if err != nil {
		t.Fatalf("failed to load logsource map: %v", err)
	}

	registry := NewRuleRegistry(rules)
	engine := NewRuleEngine(registry, lsMap)

	stats := engine.Stats()
	t.Logf("Project rules: %d loaded, %d compiled, %d skipped, %d buckets, %d compile errors",
		stats.TotalRulesLoaded, stats.RulesCompiled, stats.RulesSkipped,
		stats.BucketCount, len(stats.CompileErrors))

	if stats.RulesCompiled == 0 {
		t.Error("expected at least some rules to compile successfully")
	}
	if len(stats.CompileErrors) > 0 {
		for _, err := range stats.CompileErrors {
			t.Errorf("compile error: %v", err)
		}
	}

	// Test: EDR behavioral event should trigger at least one EDR rule.
	edrEvent := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Action: "scanner_match_detected",
			Kind:   "alert",
		},
	}
	edrAlerts := engine.Evaluate(edrEvent)
	t.Logf("EDR behavioral event triggered %d alerts", len(edrAlerts))
	if len(edrAlerts) == 0 {
		t.Error("expected at least one alert for EDR behavioral event")
	}

	// Test: AV malicious scan should trigger at least one AV rule.
	avEvent := &common.ECSEvent{
		SourceType: "akeso_av",
		Event:      &common.EventFields{Action: "scan_result"},
		AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
	}
	avAlerts := engine.Evaluate(avEvent)
	t.Logf("AV malicious scan triggered %d alerts", len(avAlerts))
	if len(avAlerts) == 0 {
		t.Error("expected at least one alert for AV malicious scan")
	}

	// Test: DLP violation should trigger DLP rules.
	dlpEvent := &common.ECSEvent{
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Action: "policy_violation"},
		DLP:        &common.DLPFields{Classification: "confidential"},
	}
	dlpAlerts := engine.Evaluate(dlpEvent)
	t.Logf("DLP violation triggered %d alerts", len(dlpAlerts))
	if len(dlpAlerts) == 0 {
		t.Error("expected at least one alert for DLP violation")
	}

	// Test: Unrelated event should not trigger any rules.
	benignEvent := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "totally_normal_activity"},
	}
	benignAlerts := engine.Evaluate(benignEvent)
	if len(benignAlerts) != 0 {
		t.Errorf("expected 0 alerts for benign event, got %d", len(benignAlerts))
		for _, a := range benignAlerts {
			t.Logf("  unexpected alert: %s (%s)", a.Title, a.RuleID)
		}
	}
}

// --- Concurrency test ---

func TestRuleEngine_ConcurrentEvaluate(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Concurrent Test
id: concurrent-edr
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|contains: scanner
  condition: selection
level: high
---
title: AV Concurrent Test
id: concurrent-av
logsource:
  product: akeso_av
detection:
  selection:
    av.scan.result: malicious
  condition: selection
level: critical
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// Run 100 goroutines evaluating different events concurrently.
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	edrMatches := make([]int, numGoroutines)
	avMatches := make([]int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Half send EDR events, half send AV events.
			if idx%2 == 0 {
				event := &common.ECSEvent{
					SourceType: "akeso_edr",
					Event:      &common.EventFields{Action: "scanner_match"},
				}
				alerts := engine.Evaluate(event)
				edrMatches[idx] = len(alerts)
			} else {
				event := &common.ECSEvent{
					SourceType: "akeso_av",
					AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
				}
				alerts := engine.Evaluate(event)
				avMatches[idx] = len(alerts)
			}
		}(i)
	}
	wg.Wait()

	// Verify all EDR goroutines got exactly 1 match.
	for i := 0; i < numGoroutines; i += 2 {
		if edrMatches[i] != 1 {
			t.Errorf("goroutine %d: expected 1 EDR alert, got %d", i, edrMatches[i])
		}
	}
	// Verify all AV goroutines got exactly 1 match.
	for i := 1; i < numGoroutines; i += 2 {
		if avMatches[i] != 1 {
			t.Errorf("goroutine %d: expected 1 AV alert, got %d", i, avMatches[i])
		}
	}
}

// --- EvaluateConcurrent test ---

func TestRuleEngine_EvaluateConcurrent(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Batch Test
id: batch-edr
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	events := make([]*common.ECSEvent, 50)
	for i := range events {
		if i%2 == 0 {
			events[i] = &common.ECSEvent{
				SourceType: "akeso_edr",
				Event:      &common.EventFields{Action: "scanner_match"},
			}
		} else {
			events[i] = &common.ECSEvent{
				SourceType: "akeso_edr",
				Event:      &common.EventFields{Action: "other"},
			}
		}
	}

	alerts := engine.EvaluateConcurrent(events, 4)
	if len(alerts) != 25 {
		t.Errorf("expected 25 alerts from batch, got %d", len(alerts))
	}
}

func TestRuleEngine_EvaluateConcurrent_Empty(t *testing.T) {
	registry := NewRuleRegistry(nil)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	alerts := engine.EvaluateConcurrent(nil, 4)
	if alerts != nil {
		t.Errorf("expected nil for empty events, got %v", alerts)
	}

	alerts2 := engine.EvaluateConcurrent([]*common.ECSEvent{}, 0)
	if alerts2 != nil {
		t.Errorf("expected nil for zero workers, got %v", alerts2)
	}
}

// --- Sysmon logsource isolation test (acceptance criteria) ---

func TestRuleEngine_SysmonOnlyFiresForSysmonEvents(t *testing.T) {
	registry := parseTestRules(t, `
title: Sysmon Process Creation
id: sysmon-rule
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    process.name: powershell.exe
  condition: selection
level: medium
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// Sysmon rules should NOT fire for EDR events.
	edrEvent := &common.ECSEvent{
		SourceType: "akeso_edr",
		Process:    &common.ProcessFields{Name: "powershell.exe"},
	}
	if alerts := engine.Evaluate(edrEvent); len(alerts) != 0 {
		t.Errorf("sysmon rule should NOT fire for EDR events, got %d alerts", len(alerts))
	}

	// Note: winevt.channel matching is currently a placeholder (returns false).
	// When Phase 2 implements winevt parsing, this test can be extended.
}

func TestRuleEngine_EDROnlyFiresForEDR(t *testing.T) {
	registry := parseTestRules(t, `
title: EDR Alert
id: edr-only
logsource:
  product: akeso_edr
detection:
  selection:
    event.action: scanner_match
  condition: selection
level: high
`)
	engine := NewRuleEngine(registry, testEngineLogsourceMap(t))

	// Should not fire for AV events.
	avEvent := &common.ECSEvent{
		SourceType: "akeso_av",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	if alerts := engine.Evaluate(avEvent); len(alerts) != 0 {
		t.Errorf("EDR rule should NOT fire for AV events, got %d alerts", len(alerts))
	}

	// Should not fire for DLP events.
	dlpEvent := &common.ECSEvent{
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	if alerts := engine.Evaluate(dlpEvent); len(alerts) != 0 {
		t.Errorf("EDR rule should NOT fire for DLP events, got %d alerts", len(alerts))
	}

	// Should fire for EDR events.
	edrEvent := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "scanner_match"},
	}
	if alerts := engine.Evaluate(edrEvent); len(alerts) != 1 {
		t.Errorf("EDR rule should fire for EDR events, got %d alerts", len(alerts))
	}
}

// --- Benchmark ---

func BenchmarkRuleEngine_Evaluate_MultiBucket(b *testing.B) {
	// Build 20 rules across 4 logsource buckets.
	var yamlParts []string
	for i := 0; i < 5; i++ {
		yamlParts = append(yamlParts, buildBenchRule("akeso_edr", i))
	}
	for i := 0; i < 5; i++ {
		yamlParts = append(yamlParts, buildBenchRule("akeso_av", i))
	}
	for i := 0; i < 5; i++ {
		yamlParts = append(yamlParts, buildBenchRule("akeso_dlp", i))
	}
	for i := 0; i < 5; i++ {
		yamlParts = append(yamlParts, buildBenchRule("akeso_ndr", i))
	}

	yamlStr := strings.Join(yamlParts, "\n---\n")
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		b.Fatalf("parse error: %v", err)
	}

	lsMap, _ := ParseLogsourceMap([]byte(`
mappings:
  - logsource:
      product: akeso_edr
    conditions:
      source_type: akeso_edr
  - logsource:
      product: akeso_av
    conditions:
      source_type: akeso_av
  - logsource:
      product: akeso_dlp
    conditions:
      source_type: akeso_dlp
  - logsource:
      product: akeso_ndr
    conditions:
      source_type: akeso_ndr
`))

	registry := NewRuleRegistry(rules)
	engine := NewRuleEngine(registry, lsMap)

	event := &common.ECSEvent{
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Action: "action_2"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(event)
	}
}

func buildBenchRule(product string, idx int) string {
	idxStr := fmt.Sprintf("%d", idx)
	return strings.ReplaceAll(strings.ReplaceAll(`
title: Bench Rule PRODUCT IDX
id: bench-PRODUCT-IDX
logsource:
  product: PRODUCT
detection:
  selection:
    event.action: action_IDX
  condition: selection
level: medium
`, "PRODUCT", product), "IDX", idxStr)
}
