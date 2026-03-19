package integration

import (
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// TestNDRFullChainCorrelation validates the 4-event NDR+EDR attack scenario:
//
//	NDR port scan → EDR LSASS access → NDR SMB lateral movement → NDR data exfiltration
//
// This tests the existing ndr_cross_full_attack_chain.yml rule, which correlates
// by user.name within 2 hours with ordered=true.
func TestNDRFullChainCorrelation(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 9, 0, 0, 0, time.UTC)
	attackerUser := "compromised_admin"

	events := []*common.ECSEvent{
		// Stage 1: NDR port scan reconnaissance at T+0
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"network"},
				Action:   "port_scan",
			},
			Source:      &common.EndpointFields{IP: "10.1.2.45", Port: 0},
			Destination: &common.EndpointFields{IP: "10.1.3.0"},
			Host:        &common.HostFields{Name: "ATTACKER-WS"},
			User:        &common.UserFields{Name: attackerUser},
			NDR: &common.NDRFields{
				Detection: &common.NDRDetection{
					Name:     "Internal Port Scan",
					Category: "reconnaissance",
				},
			},
		},
		// Stage 2: EDR LSASS credential dumping at T+15min
		{
			Timestamp:  base.Add(15 * time.Minute),
			SourceType: "akeso_edr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"process"},
				Action:   "lsass_access",
			},
			Source:  &common.EndpointFields{IP: "10.1.2.45"},
			Host:    &common.HostFields{Name: "TARGET-SRV"},
			User:    &common.UserFields{Name: attackerUser},
			Process: &common.ProcessFields{Name: "mimikatz.exe", CommandLine: "mimikatz.exe sekurlsa::logonpasswords"},
		},
		// Stage 3: NDR SMB lateral movement at T+30min
		{
			Timestamp:  base.Add(30 * time.Minute),
			SourceType: "akeso_ndr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"network"},
				Action:   "smb_write",
			},
			Source:      &common.EndpointFields{IP: "10.1.2.45", Port: 49300},
			Destination: &common.EndpointFields{IP: "10.1.4.20", Port: 445},
			Host:        &common.HostFields{Name: "ATTACKER-WS"},
			User:        &common.UserFields{Name: attackerUser},
			Network: &common.NetworkFields{
				Direction: "outbound",
				Protocol:  "tcp",
			},
		},
		// Stage 4: NDR data exfiltration at T+90min
		{
			Timestamp:  base.Add(90 * time.Minute),
			SourceType: "akeso_ndr",
			Event: &common.EventFields{
				Kind:     "event",
				Category: []string{"network"},
				Action:   "session",
			},
			Source:      &common.EndpointFields{IP: "10.1.2.45", Port: 55000},
			Destination: &common.EndpointFields{IP: "185.220.101.45", Port: 443},
			Host:        &common.HostFields{Name: "ATTACKER-WS"},
			User:        &common.UserFields{Name: attackerUser},
			Network: &common.NetworkFields{
				Direction: "outbound",
				Protocol:  "tcp",
			},
			NDR: &common.NDRFields{
				Session: &common.NDRSession{
					Duration:  300,
					BytesOrig: 50000000, // 50MB outbound
				},
			},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	t.Logf("Total correlation alerts: %d", len(correlationAlerts))
	for _, a := range correlationAlerts {
		t.Logf("  correlation: %s (%s) level=%s", a.Title, a.RuleID, a.Level)
	}

	// The full attack chain correlation rule should fire.
	found := false
	for _, a := range correlationAlerts {
		if a.RuleID == "c1a2b3c4-d5e6-4f78-9a0b-500000000005" {
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
		t.Error("FAIL: NDR full attack chain correlation rule did not fire")
	}

	t.Log("PASS: NDR full-chain correlation (port scan → LSASS → SMB → exfil) fires correctly")
}

// TestNDRFullChainDifferentUsers verifies the chain does NOT fire when events
// come from different users (group-by user.name isolation).
func TestNDRFullChainDifferentUsers(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 9, 0, 0, 0, time.UTC)

	events := []*common.ECSEvent{
		// Stage 1: user_a does port scan
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "port_scan"},
			User:       &common.UserFields{Name: "user_a"},
			NDR:        &common.NDRFields{Detection: &common.NDRDetection{Category: "reconnaissance"}},
		},
		// Stage 2: user_b does credential dump (DIFFERENT user!)
		{
			Timestamp:  base.Add(15 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "lsass_access"},
			User:       &common.UserFields{Name: "user_b"},
		},
		// Stage 3: user_a does SMB
		{
			Timestamp:  base.Add(30 * time.Minute),
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "smb_write"},
			User:       &common.UserFields{Name: "user_a"},
			Network:    &common.NetworkFields{Direction: "outbound"},
		},
		// Stage 4: user_a does exfil
		{
			Timestamp:  base.Add(90 * time.Minute),
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "session"},
			User:       &common.UserFields{Name: "user_a"},
			Network:    &common.NetworkFields{Direction: "outbound"},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	// Filter to just the full chain rule.
	for _, a := range correlationAlerts {
		if a.RuleID == "c1a2b3c4-d5e6-4f78-9a0b-500000000005" {
			t.Errorf("FAIL: full chain correlation fired despite different users: %s", a.Title)
		}
	}

	t.Log("PASS: user.name group-by isolation prevents cross-user full chain correlation")
}

// TestNDRFullChainWindowExpiry verifies the chain does NOT fire when events
// fall outside the 2-hour (120-minute) window.
func TestNDRFullChainWindowExpiry(t *testing.T) {
	engine, temporal := buildFourSourceEngines(t)

	base := time.Date(2026, 3, 16, 9, 0, 0, 0, time.UTC)
	user := "expiry_user"

	events := []*common.ECSEvent{
		// Stage 1: T+0
		{
			Timestamp:  base,
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "port_scan"},
			User:       &common.UserFields{Name: user},
			NDR:        &common.NDRFields{Detection: &common.NDRDetection{Category: "reconnaissance"}},
		},
		// Stage 2: T+30min
		{
			Timestamp:  base.Add(30 * time.Minute),
			SourceType: "akeso_edr",
			Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "lsass_access"},
			User:       &common.UserFields{Name: user},
		},
		// Stage 3: T+60min
		{
			Timestamp:  base.Add(60 * time.Minute),
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "smb_write"},
			User:       &common.UserFields{Name: user},
			Network:    &common.NetworkFields{Direction: "outbound"},
		},
		// Stage 4: T+150min (OUTSIDE 120-minute window from stage 1)
		{
			Timestamp:  base.Add(150 * time.Minute),
			SourceType: "akeso_ndr",
			Event:      &common.EventFields{Kind: "event", Action: "session"},
			User:       &common.UserFields{Name: user},
			Network:    &common.NetworkFields{Direction: "outbound"},
		},
	}

	correlationAlerts := evaluateSequence(t, engine, temporal, events)

	for _, a := range correlationAlerts {
		if a.RuleID == "c1a2b3c4-d5e6-4f78-9a0b-500000000005" {
			t.Errorf("FAIL: full chain correlation fired despite expired 2-hour window: %s", a.Title)
		}
	}

	t.Log("PASS: 2-hour window expiry prevents NDR full chain from firing")
}
