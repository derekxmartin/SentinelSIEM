package integration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// TestCrossSourceTemporalCorrelation validates the three-stage attack chain:
//
//	EDR credential theft → NDR lateral movement → EDR outbound transfer
//
// All correlated by source.ip within 30 minutes. This is the core P10-T3
// acceptance test: temporal rules must fire across AkesoEDR + AkesoNDR
// sources, correlating events from the same host correctly.
func TestCrossSourceTemporalCorrelation(t *testing.T) {
	// ── Load rules ──────────────────────────────────────────────────────
	rulesRoot := filepath.Join("..", "..", "rules")
	rules, errs := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))
	for _, e := range errs {
		t.Logf("parse warning: %v", e)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}

	lsMap, err := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))
	if err != nil {
		t.Fatalf("loading logsource map: %v", err)
	}

	// ── Build engines ───────────────────────────────────────────────────
	registry := correlate.NewRuleRegistry(rules)
	singleEngine := correlate.NewRuleEngine(registry, lsMap)

	// Parse correlation rules and build temporal evaluator.
	corrRules, corrErrs := correlate.ParseCorrelationRules(registry)
	for _, e := range corrErrs {
		t.Logf("correlation parse warning: %v", e)
	}
	t.Logf("Parsed %d correlation rules", len(corrRules))

	temporalEval := correlate.NewTemporalEvaluator(corrRules)

	// ── Define attack timeline ──────────────────────────────────────────
	base := time.Date(2026, 3, 16, 14, 0, 0, 0, time.UTC)
	attackerIP := "192.168.1.100"

	// Stage 1: EDR credential theft (LSASS access) at T+0
	edrCredTheft := &common.ECSEvent{
		Timestamp:  base,
		SourceType: "akeso_edr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "lsass_access"},
		Source:     &common.EndpointFields{IP: attackerIP},
		Process:    &common.ProcessFields{Name: "mimikatz.exe", CommandLine: "mimikatz.exe sekurlsa::logonpasswords"},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	}

	// Stage 2: NDR lateral movement (SMB write) at T+8min
	ndrLateral := &common.ECSEvent{
		Timestamp:   base.Add(8 * time.Minute),
		SourceType:  "akeso_ndr",
		Event:       &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "smb_write"},
		Source:      &common.EndpointFields{IP: attackerIP, Port: 49152},
		Destination: &common.EndpointFields{IP: "10.0.0.50", Port: 445},
		Host:        &common.HostFields{Name: "WORKSTATION-01"},
	}

	// Stage 3: EDR outbound data transfer at T+20min
	edrExfil := &common.ECSEvent{
		Timestamp:   base.Add(20 * time.Minute),
		SourceType:  "akeso_edr",
		Event:       &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "outbound_transfer"},
		Source:      &common.EndpointFields{IP: attackerIP, Port: 55000},
		Destination: &common.EndpointFields{IP: "185.220.101.45", Port: 443},
		Host:        &common.HostFields{Name: "WORKSTATION-01"},
	}

	// ── Evaluate events in sequence ─────────────────────────────────────
	attackEvents := []*common.ECSEvent{edrCredTheft, ndrLateral, edrExfil}

	var correlationAlerts []correlate.Alert
	for i, ev := range attackEvents {
		// First: evaluate against single-event rules.
		singleAlerts := singleEngine.Evaluate(ev)
		t.Logf("Step %d (%s): %d single-event alerts", i+1, ev.Event.Action, len(singleAlerts))
		for _, a := range singleAlerts {
			t.Logf("  single: %s (%s)", a.Title, a.RuleID)
		}

		// Second: feed single-event alerts into the temporal evaluator.
		for _, alert := range singleAlerts {
			corrAlerts := temporalEval.Process(alert, ev)
			correlationAlerts = append(correlationAlerts, corrAlerts...)
		}
	}

	// ── Assert ──────────────────────────────────────────────────────────
	t.Logf("Total correlation alerts: %d", len(correlationAlerts))
	for _, a := range correlationAlerts {
		t.Logf("  correlation: %s (%s) level=%s", a.Title, a.RuleID, a.Level)
	}

	if len(correlationAlerts) == 0 {
		t.Fatal("FAIL: expected at least 1 temporal correlation alert, got 0")
	}

	// Verify the correct rule fired.
	found := false
	for _, a := range correlationAlerts {
		if a.RuleID == "d4e5f6a7-b8c9-4d0e-1f2a-a00000000004" {
			found = true
			if a.Level != "critical" {
				t.Errorf("expected level critical, got %s", a.Level)
			}
			if a.Ruleset != "sigma_correlation" {
				t.Errorf("expected ruleset sigma_correlation, got %s", a.Ruleset)
			}
		}
	}
	if !found {
		t.Error("expected cross-source credential-lateral-exfil correlation rule to fire")
	}

	t.Log("PASS: cross-source temporal correlation fires correctly")
}

// TestTemporalWindowExpiry verifies the temporal chain does NOT fire when
// events fall outside the 30-minute window.
func TestTemporalWindowExpiry(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	rules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))
	lsMap, _ := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))

	registry := correlate.NewRuleRegistry(rules)
	singleEngine := correlate.NewRuleEngine(registry, lsMap)
	corrRules, _ := correlate.ParseCorrelationRules(registry)
	temporalEval := correlate.NewTemporalEvaluator(corrRules)

	base := time.Date(2026, 3, 16, 14, 0, 0, 0, time.UTC)
	attackerIP := "192.168.1.200"

	events := []*common.ECSEvent{
		// Stage 1: T+0
		{
			Timestamp:  base,
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Action: "credential_theft"},
			Source:     &common.EndpointFields{IP: attackerIP},
			Host:       &common.HostFields{Name: "WORKSTATION-02"},
		},
		// Stage 2: T+10min (within window)
		{
			Timestamp:   base.Add(10 * time.Minute),
			SourceType:  "akeso_ndr",
			Event:       &common.EventFields{Kind: "event", Action: "smb_session"},
			Source:      &common.EndpointFields{IP: attackerIP},
			Destination: &common.EndpointFields{IP: "10.0.0.60", Port: 445},
			Host:        &common.HostFields{Name: "WORKSTATION-02"},
		},
		// Stage 3: T+45min (OUTSIDE 30-minute window)
		{
			Timestamp:   base.Add(45 * time.Minute),
			SourceType:  "akeso_edr",
			Event:       &common.EventFields{Kind: "event", Action: "outbound_transfer"},
			Source:      &common.EndpointFields{IP: attackerIP},
			Destination: &common.EndpointFields{IP: "91.234.99.42", Port: 443},
			Host:        &common.HostFields{Name: "WORKSTATION-02"},
		},
	}

	var correlationAlerts []correlate.Alert
	for _, ev := range events {
		singleAlerts := singleEngine.Evaluate(ev)
		for _, alert := range singleAlerts {
			corrAlerts := temporalEval.Process(alert, ev)
			correlationAlerts = append(correlationAlerts, corrAlerts...)
		}
	}

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (expired window), got %d", len(correlationAlerts))
	}

	t.Log("PASS: temporal window expiry correctly prevents firing")
}

// TestTemporalDifferentSourceIPs verifies the temporal chain does NOT fire
// when events come from different source IPs (group-by isolation).
func TestTemporalDifferentSourceIPs(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	rules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))
	lsMap, _ := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))

	registry := correlate.NewRuleRegistry(rules)
	singleEngine := correlate.NewRuleEngine(registry, lsMap)
	corrRules, _ := correlate.ParseCorrelationRules(registry)
	temporalEval := correlate.NewTemporalEvaluator(corrRules)

	base := time.Date(2026, 3, 16, 14, 0, 0, 0, time.UTC)

	events := []*common.ECSEvent{
		// Stage 1: IP-A credential theft
		{
			Timestamp:  base,
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Action: "lsass_access"},
			Source:     &common.EndpointFields{IP: "192.168.1.50"},
			Host:       &common.HostFields{Name: "WORKSTATION-03"},
		},
		// Stage 2: IP-B (different!) lateral movement
		{
			Timestamp:   base.Add(5 * time.Minute),
			SourceType:  "akeso_ndr",
			Event:       &common.EventFields{Kind: "event", Action: "smb_write"},
			Source:      &common.EndpointFields{IP: "192.168.1.99"},
			Destination: &common.EndpointFields{IP: "10.0.0.70", Port: 445},
			Host:        &common.HostFields{Name: "WORKSTATION-05"},
		},
		// Stage 3: IP-A exfil (back to original IP, but stage 2 was different)
		{
			Timestamp:   base.Add(15 * time.Minute),
			SourceType:  "akeso_edr",
			Event:       &common.EventFields{Kind: "event", Action: "outbound_transfer"},
			Source:      &common.EndpointFields{IP: "192.168.1.50"},
			Destination: &common.EndpointFields{IP: "203.0.113.42", Port: 443},
			Host:        &common.HostFields{Name: "WORKSTATION-03"},
		},
	}

	var correlationAlerts []correlate.Alert
	for _, ev := range events {
		singleAlerts := singleEngine.Evaluate(ev)
		for _, alert := range singleAlerts {
			corrAlerts := temporalEval.Process(alert, ev)
			correlationAlerts = append(correlationAlerts, corrAlerts...)
		}
	}

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (different source IPs), got %d", len(correlationAlerts))
	}

	t.Log("PASS: group-by isolation prevents cross-IP correlation")
}

// TestTemporalOutOfOrderIgnored verifies that events arriving out of sequence
// do not advance the temporal chain.
func TestTemporalOutOfOrderIgnored(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	rules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))
	lsMap, _ := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))

	registry := correlate.NewRuleRegistry(rules)
	singleEngine := correlate.NewRuleEngine(registry, lsMap)
	corrRules, _ := correlate.ParseCorrelationRules(registry)
	temporalEval := correlate.NewTemporalEvaluator(corrRules)

	base := time.Date(2026, 3, 16, 14, 0, 0, 0, time.UTC)
	ip := "192.168.1.77"

	events := []*common.ECSEvent{
		// Stage 2 first (out of order!) — should not start a chain
		{
			Timestamp:   base,
			SourceType:  "akeso_ndr",
			Event:       &common.EventFields{Kind: "event", Action: "smb_write"},
			Source:      &common.EndpointFields{IP: ip},
			Destination: &common.EndpointFields{IP: "10.0.0.80", Port: 445},
			Host:        &common.HostFields{Name: "WORKSTATION-06"},
		},
		// Stage 3 next (still out of order)
		{
			Timestamp:   base.Add(5 * time.Minute),
			SourceType:  "akeso_edr",
			Event:       &common.EventFields{Kind: "event", Action: "outbound_transfer"},
			Source:      &common.EndpointFields{IP: ip},
			Destination: &common.EndpointFields{IP: "185.220.101.45", Port: 443},
			Host:        &common.HostFields{Name: "WORKSTATION-06"},
		},
		// Stage 1 last (chain can't complete — wrong order)
		{
			Timestamp:  base.Add(10 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Action: "mimikatz_execution"},
			Source:     &common.EndpointFields{IP: ip},
			Host:       &common.HostFields{Name: "WORKSTATION-06"},
		},
	}

	var correlationAlerts []correlate.Alert
	for _, ev := range events {
		singleAlerts := singleEngine.Evaluate(ev)
		for _, alert := range singleAlerts {
			corrAlerts := temporalEval.Process(alert, ev)
			correlationAlerts = append(correlationAlerts, corrAlerts...)
		}
	}

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (out-of-order events), got %d", len(correlationAlerts))
	}

	t.Log("PASS: out-of-order events do not fire temporal correlation")
}

// Ensure fmt is imported.
var _ = fmt.Sprintf
