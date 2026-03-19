package integration

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// buildFourSourceEngines loads rules from akeso_portfolio, builds the single-event
// engine and temporal evaluator. Shared across all four-source tests.
func buildFourSourceEngines(t *testing.T) (*correlate.RuleEngine, *correlate.TemporalEvaluator) {
	t.Helper()

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

	registry := correlate.NewRuleRegistry(rules)
	singleEngine := correlate.NewRuleEngine(registry, lsMap)

	corrRules, corrErrs := correlate.ParseCorrelationRules(registry)
	for _, e := range corrErrs {
		t.Logf("correlation parse warning: %v", e)
	}
	t.Logf("Parsed %d correlation rules", len(corrRules))

	temporalEval := correlate.NewTemporalEvaluator(corrRules)
	return singleEngine, temporalEval
}

// evaluateSequence feeds events through single-event engine then temporal evaluator,
// logging intermediate results. Returns all correlation alerts.
func evaluateSequence(t *testing.T, engine *correlate.RuleEngine, temporal *correlate.TemporalEvaluator, events []*common.ECSEvent) []correlate.Alert {
	t.Helper()

	var correlationAlerts []correlate.Alert
	for i, ev := range events {
		singleAlerts := engine.Evaluate(ev)
		t.Logf("Step %d (%s / %s): %d single-event alerts",
			i+1, ev.SourceType, ev.Event.Action, len(singleAlerts))
		for _, a := range singleAlerts {
			t.Logf("  single: %s (%s)", a.Title, a.RuleID)
		}

		for _, alert := range singleAlerts {
			corrAlerts := temporal.Process(alert, ev)
			correlationAlerts = append(correlationAlerts, corrAlerts...)
		}
	}
	return correlationAlerts
}

// TestFourSourceCrossProductCorrelation validates the complete 4-source attack chain:
//
//	NDR SMB transfer → AV malware detection → EDR process execution → WinEvt user audit
//
// All correlated by host.name within 45 minutes. This is the core P10-T4 acceptance
// test: four independent security products must converge on a single incident.
func TestFourSourceCrossProductCorrelation(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)
	targetHost := "SRV-FINANCE-01"

	events := []*common.ECSEvent{
		// Stage 1: NDR detects SMB file transfer to SRV-FINANCE-01 at T+0
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"network"},
				Action:   "smb_write",
			},
			Source:      &common.EndpointFields{IP: "10.1.2.45", Port: 49200},
			Destination: &common.EndpointFields{IP: "10.1.3.20", Port: 445},
			Host:        &common.HostFields{Name: targetHost},
			SMB:         &common.SMBFields{Action: "write", Filename: "payload.exe"},
		},
		// Stage 2: AV detects malicious file on SRV-FINANCE-01 at T+3min
		{
			Timestamp:  base.Add(3 * time.Minute),
			SourceType: "akeso_av",
			Event: &common.EventFields{
				Kind:     "alert",
				Category: []string{"malware"},
				Action:   "realtime_block",
			},
			Host: &common.HostFields{Name: targetHost},
			AV: &common.AVFields{
				Signature: &common.AVSignature{Name: "Trojan.GenericKD.48291"},
				Action:    "quarantine",
				Scan:      &common.AVScan{Result: "malicious"},
			},
			File: &common.FileFields{
				Name: "payload.exe",
				Path: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\payload.exe",
				Hash: &common.HashFields{SHA256: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
			},
		},
		// Stage 3: EDR detects the dropped file execution on SRV-FINANCE-01 at T+8min
		{
			Timestamp:  base.Add(8 * time.Minute),
			SourceType: "akeso_edr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"process"},
				Action:   "process_create",
			},
			Host:    &common.HostFields{Name: targetHost},
			Process: &common.ProcessFields{Name: "payload.exe", CommandLine: "payload.exe -connect 185.220.101.45"},
			User:    &common.UserFields{Name: "jsmith", Domain: "CORP"},
		},
		// Stage 4: Windows Security Event shows user audit on SRV-FINANCE-01 at T+10min
		{
			Timestamp:  base.Add(10 * time.Minute),
			SourceType: "winevt",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"authentication"},
				Action:   "logon_success",
			},
			Host:   &common.HostFields{Name: targetHost},
			User:   &common.UserFields{Name: "jsmith", Domain: "CORP"},
			WinEvt: &common.WinEvtFields{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4624},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	// Assert
	t.Logf("Total correlation alerts: %d", len(correlationAlerts))
	for _, a := range correlationAlerts {
		t.Logf("  correlation: %s (%s) level=%s", a.Title, a.RuleID, a.Level)
	}

	if len(correlationAlerts) == 0 {
		t.Fatal("FAIL: expected at least 1 temporal correlation alert from 4-source chain, got 0")
	}

	// Verify the correct rule fired.
	found := false
	for _, a := range correlationAlerts {
		if a.RuleID == "f6a7b8c9-d0e1-4f2a-3b4c-b00000000005" {
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
		t.Error("expected four-source attack chain correlation rule to fire (f6a7b8c9-d0e1-4f2a-3b4c-b00000000005)")
	}

	t.Log("PASS: four-source cross-product correlation fires correctly")
}

// TestFourSourceMissingOneStage verifies the chain does NOT fire when one of the
// four sources is missing. Tests with NDR, AV, and EDR present but WinEvt absent.
func TestFourSourceMissingOneStage(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)
	targetHost := "SRV-MISSING-01"

	events := []*common.ECSEvent{
		// Stage 1: NDR
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "smb_write"},
			Source:     &common.EndpointFields{IP: "10.1.2.45"},
			Host:       &common.HostFields{Name: targetHost},
		},
		// Stage 2: AV
		{
			Timestamp:  base.Add(3 * time.Minute),
			SourceType: "akeso_av",
			Event:      &common.EventFields{Kind: "alert", Action: "scan_result"},
			Host:       &common.HostFields{Name: targetHost},
			AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
		},
		// Stage 3: EDR
		{
			Timestamp:  base.Add(8 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "process_create"},
			Host:       &common.HostFields{Name: targetHost},
			Process:    &common.ProcessFields{Name: "dropper.exe"},
		},
		// Stage 4: MISSING — no WinEvt event
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (missing stage 4), got %d", len(correlationAlerts))
	}

	t.Log("PASS: missing stage correctly prevents four-source chain from firing")
}

// TestFourSourceDifferentHosts verifies the chain does NOT fire when events come
// from different hosts (group-by host.name isolation).
func TestFourSourceDifferentHosts(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)

	events := []*common.ECSEvent{
		// Stage 1: NDR on Host-A
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "smb_write"},
			Source:     &common.EndpointFields{IP: "10.1.2.45"},
			Host:       &common.HostFields{Name: "HOST-A"},
		},
		// Stage 2: AV on Host-B (DIFFERENT!)
		{
			Timestamp:  base.Add(3 * time.Minute),
			SourceType: "akeso_av",
			Event:      &common.EventFields{Kind: "alert", Action: "scan_result"},
			Host:       &common.HostFields{Name: "HOST-B"},
			AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
		},
		// Stage 3: EDR on Host-A (back to original)
		{
			Timestamp:  base.Add(8 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "process_create"},
			Host:       &common.HostFields{Name: "HOST-A"},
			Process:    &common.ProcessFields{Name: "dropper.exe"},
		},
		// Stage 4: WinEvt on Host-A
		{
			Timestamp:  base.Add(10 * time.Minute),
			SourceType: "winevt",
			Event:      &common.EventFields{Kind: "event", Action: "logon_success"},
			Host:       &common.HostFields{Name: "HOST-A"},
			WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4624},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (different hosts), got %d", len(correlationAlerts))
	}

	t.Log("PASS: host.name group-by isolation prevents cross-host correlation")
}

// TestFourSourceWindowExpiry verifies the chain does NOT fire when stage 4
// arrives outside the 45-minute timespan.
func TestFourSourceWindowExpiry(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)
	targetHost := "SRV-EXPIRED-01"

	events := []*common.ECSEvent{
		// Stage 1: NDR at T+0
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "smb_transfer"},
			Source:     &common.EndpointFields{IP: "10.1.2.45"},
			Host:       &common.HostFields{Name: targetHost},
		},
		// Stage 2: AV at T+5min
		{
			Timestamp:  base.Add(5 * time.Minute),
			SourceType: "akeso_av",
			Event:      &common.EventFields{Kind: "alert", Action: "realtime_block"},
			Host:       &common.HostFields{Name: targetHost},
			AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
		},
		// Stage 3: EDR at T+15min
		{
			Timestamp:  base.Add(15 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "file_execute"},
			Host:       &common.HostFields{Name: targetHost},
			Process:    &common.ProcessFields{Name: "malware.exe"},
		},
		// Stage 4: WinEvt at T+60min (OUTSIDE 45-minute window)
		{
			Timestamp:  base.Add(60 * time.Minute),
			SourceType: "winevt",
			Event:      &common.EventFields{Kind: "event", Action: "process_created"},
			Host:       &common.HostFields{Name: targetHost},
			WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4688},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	if len(correlationAlerts) != 0 {
		for _, a := range correlationAlerts {
			t.Errorf("unexpected correlation alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 alerts (expired window), got %d", len(correlationAlerts))
	}

	t.Log("PASS: 45-minute window expiry correctly prevents firing")
}

// TestFourSourceOutOfOrder verifies the chain does NOT fire when events arrive
// in the wrong sequence (e.g., AV before NDR).
func TestFourSourceOutOfOrder(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)
	targetHost := "SRV-ORDER-01"

	events := []*common.ECSEvent{
		// Stage 2 first (AV — out of order!)
		{
			Timestamp:  base,
			SourceType: "akeso_av",
			Event:      &common.EventFields{Kind: "alert", Action: "scan_result"},
			Host:       &common.HostFields{Name: targetHost},
			AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
		},
		// Stage 1 (NDR — should have been first)
		{
			Timestamp:  base.Add(3 * time.Minute),
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "smb_write"},
			Source:     &common.EndpointFields{IP: "10.1.2.45"},
			Host:       &common.HostFields{Name: targetHost},
		},
		// Stage 3 (EDR)
		{
			Timestamp:  base.Add(8 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "process_create"},
			Host:       &common.HostFields{Name: targetHost},
			Process:    &common.ProcessFields{Name: "dropper.exe"},
		},
		// Stage 4 (WinEvt)
		{
			Timestamp:  base.Add(10 * time.Minute),
			SourceType: "winevt",
			Event:      &common.EventFields{Kind: "event", Action: "logon_success"},
			Host:       &common.HostFields{Name: targetHost},
			WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4624},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	// The chain should NOT complete because:
	// - AV fires first but is step 2 (not step 0), so no chain starts
	// - NDR fires second and starts a new chain at step 0
	// - EDR fires as step 2 but chain expects step 1 (AV), so it doesn't advance
	// Result: chain never completes
	//
	// However, NDR starting a chain at step 1, then EDR at step 2 would advance
	// if step mapping allows. The key validation is that the FULL 4-step sequence
	// cannot complete out of order.

	// Filter to only our rule ID to avoid false positives from other portfolio rules
	var fourSourceAlerts []correlate.Alert
	for _, a := range correlationAlerts {
		if a.RuleID == "f6a7b8c9-d0e1-4f2a-3b4c-b00000000005" {
			fourSourceAlerts = append(fourSourceAlerts, a)
		}
	}

	if len(fourSourceAlerts) != 0 {
		for _, a := range fourSourceAlerts {
			t.Errorf("unexpected four-source alert: %s (%s)", a.Title, a.RuleID)
		}
		t.Fatalf("FAIL: expected 0 four-source alerts (out-of-order), got %d", len(fourSourceAlerts))
	}

	t.Log("PASS: out-of-order events do not complete four-source chain")
}
