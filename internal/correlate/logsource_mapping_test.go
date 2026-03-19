package correlate

import (
	"os"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

const testLogsourceMap = `
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
      category: file_event
    conditions:
      event.category: file

  - logsource:
      product: windows
      service: security
    conditions:
      source_type: winevt
      winevt.channel: Security

  - logsource:
      product: windows
      service: sysmon
    conditions:
      source_type: winevt
      winevt.channel: Microsoft-Windows-Sysmon/Operational

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
      category: ids
    conditions:
      event.category: intrusion_detection

  - logsource:
      category: authentication
    conditions:
      event.category: authentication
`

func loadTestMap(t *testing.T) *LogsourceMap {
	t.Helper()
	lm, err := ParseLogsourceMap([]byte(testLogsourceMap))
	if err != nil {
		t.Fatalf("ParseLogsourceMap failed: %v", err)
	}
	return lm
}

func TestParseLogsourceMap(t *testing.T) {
	lm := loadTestMap(t)
	if lm.MappingCount() != 13 {
		t.Errorf("MappingCount() = %d, want 13", lm.MappingCount())
	}
}

func TestParseEmptyMappings(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`mappings: []`))
	if err == nil {
		t.Error("expected error for empty mappings")
	}
}

func TestParseNoLogsourceFields(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`
mappings:
  - logsource: {}
    conditions:
      source_type: test
`))
	if err == nil {
		t.Error("expected error for mapping with no logsource fields")
	}
}

func TestParseNoConditions(t *testing.T) {
	_, err := ParseLogsourceMap([]byte(`
mappings:
  - logsource:
      product: test
    conditions: {}
`))
	if err == nil {
		t.Error("expected error for mapping with no conditions")
	}
}

func TestResolveProductAkesoAV(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "akeso_av", "")
	if conds == nil {
		t.Fatal("expected conditions for product: akeso_av")
	}
	if conds["source_type"] != "akeso_av" {
		t.Errorf("source_type = %q, want akeso_av", conds["source_type"])
	}
}

func TestResolveProductAkesoDLP(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "akeso_dlp", "")
	if conds == nil {
		t.Fatal("expected conditions for product: akeso_dlp")
	}
	if conds["source_type"] != "akeso_dlp" {
		t.Errorf("source_type = %q, want akeso_dlp", conds["source_type"])
	}
}

func TestResolveProductakeso_edr(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "akeso_edr", "")
	if conds == nil {
		t.Fatal("expected conditions for product: akeso_edr")
	}
	if conds["source_type"] != "akeso_edr" {
		t.Errorf("source_type = %q, want akeso_edr", conds["source_type"])
	}
}

func TestResolveCategoryMalware(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("malware", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: malware")
	}
	if conds["event.category"] != "malware" {
		t.Errorf("event.category = %q, want malware", conds["event.category"])
	}
}

func TestResolveCategoryProcessCreation(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("process_creation", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: process_creation")
	}
	if conds["event.category"] != "process" {
		t.Errorf("event.category = %q, want process", conds["event.category"])
	}
	if conds["event.type"] != "start" {
		t.Errorf("event.type = %q, want start", conds["event.type"])
	}
}

func TestResolveProductServiceWindowsSecurity(t *testing.T) {
	lm := loadTestMap(t)
	// product+service is more specific than product alone.
	conds := lm.Resolve("", "windows", "security")
	if conds == nil {
		t.Fatal("expected conditions for product: windows, service: security")
	}
	if conds["source_type"] != "winevt" {
		t.Errorf("source_type = %q, want winevt", conds["source_type"])
	}
	if conds["winevt.channel"] != "Security" {
		t.Errorf("winevt.channel = %q, want Security", conds["winevt.channel"])
	}
}

func TestResolveProductServiceWindowsSysmon(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "windows", "sysmon")
	if conds == nil {
		t.Fatal("expected conditions for product: windows, service: sysmon")
	}
	if conds["winevt.channel"] != "Microsoft-Windows-Sysmon/Operational" {
		t.Errorf("winevt.channel = %q", conds["winevt.channel"])
	}
}

func TestResolveNoMatch(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "unknown_product", "")
	if conds != nil {
		t.Errorf("expected nil for unknown product, got %v", conds)
	}
}

func TestResolveSpecificityPriority(t *testing.T) {
	// product+service (score 2) should beat product alone (score 1).
	lm := loadTestMap(t)
	conds := lm.Resolve("", "windows", "security")
	if conds == nil {
		t.Fatal("expected match")
	}
	// Should pick the product+service mapping, not just product.
	if conds["winevt.channel"] != "Security" {
		t.Errorf("expected specific mapping, got %v", conds)
	}
}

func TestResolveAllCategoryMalware(t *testing.T) {
	lm := loadTestMap(t)
	// category: malware should return only the malware mapping.
	results := lm.ResolveAll("malware", "", "")
	if len(results) != 1 {
		t.Fatalf("expected 1 result for category: malware, got %d", len(results))
	}
	if results[0]["event.category"] != "malware" {
		t.Errorf("expected event.category: malware, got %v", results[0])
	}
}

// --- Event matching tests ---

func TestMatchesEventAVScanResult(t *testing.T) {
	// An AV malicious scan result should match both product:akeso_av AND category:malware.
	lm := loadTestMap(t)

	avEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_av",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"malware"},
			Type:     []string{"info"},
			Action:   "scan_result",
		},
	}

	// Should match product: akeso_av conditions.
	productConds := lm.Resolve("", "akeso_av", "")
	if !MatchesEvent(productConds, avEvent) {
		t.Error("AV event should match product: akeso_av conditions")
	}

	// Should also match category: malware conditions.
	categoryConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(categoryConds, avEvent) {
		t.Error("AV malware event should match category: malware conditions")
	}
}

func TestMatchesEventEDRMalwareDetection(t *testing.T) {
	// An EDR scanner detection (event.category: malware) should match category:malware.
	lm := loadTestMap(t)

	edrEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Kind:     "alert",
			Category: []string{"malware"},
			Type:     []string{"info"},
			Action:   "scanner_match",
		},
	}

	// Should match category: malware.
	categoryConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(categoryConds, edrEvent) {
		t.Error("EDR malware detection should match category: malware conditions")
	}

	// Should NOT match product: akeso_av.
	avConds := lm.Resolve("", "akeso_av", "")
	if MatchesEvent(avConds, edrEvent) {
		t.Error("EDR event should NOT match product: akeso_av conditions")
	}
}

func TestMatchesEventDLPPolicyViolation(t *testing.T) {
	lm := loadTestMap(t)

	dlpEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_dlp",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"file"},
			Type:     []string{"access"},
			Action:   "violation",
		},
	}

	// Should match product: akeso_dlp.
	dlpConds := lm.Resolve("", "akeso_dlp", "")
	if !MatchesEvent(dlpConds, dlpEvent) {
		t.Error("DLP event should match product: akeso_dlp conditions")
	}

	// Should match category: file_event.
	fileConds := lm.Resolve("file_event", "", "")
	if !MatchesEvent(fileConds, dlpEvent) {
		t.Error("DLP file event should match category: file_event conditions")
	}

	// Should NOT match product: akeso_av.
	avConds := lm.Resolve("", "akeso_av", "")
	if MatchesEvent(avConds, dlpEvent) {
		t.Error("DLP event should NOT match product: akeso_av conditions")
	}
}

func TestMatchesEventProcessCreation(t *testing.T) {
	lm := loadTestMap(t)

	procEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
	}

	// Should match category: process_creation.
	procConds := lm.Resolve("process_creation", "", "")
	if !MatchesEvent(procConds, procEvent) {
		t.Error("process start event should match category: process_creation")
	}

	// Should NOT match category: malware.
	malwareConds := lm.Resolve("malware", "", "")
	if MatchesEvent(malwareConds, procEvent) {
		t.Error("process event should NOT match category: malware")
	}
}

func TestMatchesEventCrossProductMalware(t *testing.T) {
	// The key acceptance criteria: category:malware matches BOTH AV and EDR malware events.
	lm := loadTestMap(t)
	categoryConds := lm.Resolve("malware", "", "")

	avMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_av",
		Event: &common.EventFields{
			Category: []string{"malware"},
			Type:     []string{"info"},
		},
	}

	edrMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Category: []string{"malware"},
			Type:     []string{"info"},
		},
	}

	nonMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_dlp",
		Event: &common.EventFields{
			Category: []string{"file"},
			Type:     []string{"access"},
		},
	}

	if !MatchesEvent(categoryConds, avMalware) {
		t.Error("AV malware event should match category: malware")
	}
	if !MatchesEvent(categoryConds, edrMalware) {
		t.Error("EDR malware event should match category: malware")
	}
	if MatchesEvent(categoryConds, nonMalware) {
		t.Error("DLP file event should NOT match category: malware")
	}
}

func TestMatchesEventNilEvent(t *testing.T) {
	conditions := map[string]string{"event.category": "malware"}
	event := &common.ECSEvent{
		Timestamp: time.Now().UTC(),
	}
	if MatchesEvent(conditions, event) {
		t.Error("event with nil Event field should not match event.category condition")
	}
}

func TestMatchesEventMultiCategoryEvent(t *testing.T) {
	// An event with multiple categories (e.g., ["process", "malware"]) should
	// match BOTH category:process_creation and category:malware logsources.
	lm := loadTestMap(t)

	multiCatEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process", "malware"},
			Type:     []string{"start"},
		},
	}

	// Should match category: process_creation (has "process" in category + "start" in type).
	procConds := lm.Resolve("process_creation", "", "")
	if !MatchesEvent(procConds, multiCatEvent) {
		t.Error("multi-category event with [process, malware] should match process_creation")
	}

	// Should also match category: malware (has "malware" in category).
	malwareConds := lm.Resolve("malware", "", "")
	if !MatchesEvent(malwareConds, multiCatEvent) {
		t.Error("multi-category event with [process, malware] should match malware")
	}
}

func TestResolveCategoryAndProduct(t *testing.T) {
	// A Sigma rule specifying both category AND product should require both to match.
	// Add a mapping that has category+product for this test.
	yaml := `
mappings:
  - logsource:
      product: akeso_av
    conditions:
      source_type: akeso_av

  - logsource:
      category: malware
    conditions:
      event.category: malware

  - logsource:
      category: malware
      product: akeso_av
    conditions:
      source_type: akeso_av
      event.category: malware
`
	lm, err := ParseLogsourceMap([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseLogsourceMap failed: %v", err)
	}

	// category:malware + product:akeso_av should pick the most specific (score 2) mapping.
	conds := lm.Resolve("malware", "akeso_av", "")
	if conds == nil {
		t.Fatal("expected match for category:malware + product:akeso_av")
	}
	// Should have both conditions from the specific mapping.
	if conds["source_type"] != "akeso_av" {
		t.Errorf("source_type = %q, want akeso_av", conds["source_type"])
	}
	if conds["event.category"] != "malware" {
		t.Errorf("event.category = %q, want malware", conds["event.category"])
	}

	// AV malware event should match this combined condition.
	avMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_av",
		Event: &common.EventFields{
			Category: []string{"malware"},
		},
	}
	if !MatchesEvent(conds, avMalware) {
		t.Error("AV malware event should match combined category+product conditions")
	}

	// EDR malware event should NOT match (wrong source_type).
	edrMalware := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_edr",
		Event: &common.EventFields{
			Category: []string{"malware"},
		},
	}
	if MatchesEvent(conds, edrMalware) {
		t.Error("EDR malware event should NOT match akeso_av+malware conditions")
	}
}

func TestResolveReturnsCopy(t *testing.T) {
	// Mutating the returned map should not affect internal state.
	lm := loadTestMap(t)

	conds1 := lm.Resolve("", "akeso_av", "")
	if conds1 == nil {
		t.Fatal("expected conditions")
	}

	// Mutate the returned map.
	conds1["source_type"] = "MUTATED"

	// Resolve again — should get the original value.
	conds2 := lm.Resolve("", "akeso_av", "")
	if conds2["source_type"] != "akeso_av" {
		t.Errorf("mutation leaked: source_type = %q, want akeso_av", conds2["source_type"])
	}
}

func TestLoadLogsourceMapFromFile(t *testing.T) {
	// Write a temp file and load it.
	tmpFile := t.TempDir() + "/logsource_map.yaml"
	if err := os.WriteFile(tmpFile, []byte(testLogsourceMap), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	lm, err := LoadLogsourceMap(tmpFile)
	if err != nil {
		t.Fatalf("LoadLogsourceMap failed: %v", err)
	}

	if lm.MappingCount() != 13 {
		t.Errorf("MappingCount() = %d, want 13", lm.MappingCount())
	}
}

func TestLoadLogsourceMapFileNotFound(t *testing.T) {
	_, err := LoadLogsourceMap("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// --- NDR logsource mapping tests ---

func TestResolveProductAkesoNDR(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("", "akeso_ndr", "")
	if conds == nil {
		t.Fatal("expected conditions for product: akeso_ndr")
	}
	if conds["source_type"] != "akeso_ndr" {
		t.Errorf("source_type = %q, want akeso_ndr", conds["source_type"])
	}
}

func TestResolveCategoryDNS(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("dns", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: dns")
	}
	if conds["event.category"] != "network" {
		t.Errorf("event.category = %q, want network", conds["event.category"])
	}
	if conds["event.action"] != "dns_query" {
		t.Errorf("event.action = %q, want dns_query", conds["event.action"])
	}
}

func TestResolveCategoryIDS(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("ids", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: ids")
	}
	if conds["event.category"] != "intrusion_detection" {
		t.Errorf("event.category = %q, want intrusion_detection", conds["event.category"])
	}
}

func TestResolveCategoryAuthentication(t *testing.T) {
	lm := loadTestMap(t)
	conds := lm.Resolve("authentication", "", "")
	if conds == nil {
		t.Fatal("expected conditions for category: authentication")
	}
	if conds["event.category"] != "authentication" {
		t.Errorf("event.category = %q, want authentication", conds["event.category"])
	}
}

func TestMatchesNDRSessionEvent(t *testing.T) {
	lm := loadTestMap(t)

	ndrSession := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_ndr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"network_connection"},
			Type:     []string{"connection"},
			Action:   "session",
		},
	}

	// Should match product: akeso_ndr.
	ndrConds := lm.Resolve("", "akeso_ndr", "")
	if !MatchesEvent(ndrConds, ndrSession) {
		t.Error("NDR session should match product: akeso_ndr")
	}

	// Should NOT match product: akeso_edr.
	edrConds := lm.Resolve("", "akeso_edr", "")
	if MatchesEvent(edrConds, ndrSession) {
		t.Error("NDR session should NOT match product: akeso_edr")
	}
}

func TestMatchesNDRDNSEventDualLogsource(t *testing.T) {
	// The key acceptance criteria: ndr:dns events match BOTH
	// product:akeso_ndr AND category:dns.
	lm := loadTestMap(t)

	ndrDNS := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_ndr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"network"},
			Type:     []string{"protocol"},
			Action:   "dns_query",
		},
		DNS: &common.DNSFields{
			Question: &common.DNSQuestion{
				Name: "malicious.example.com",
				Type: "A",
			},
		},
	}

	// Should match product: akeso_ndr (by source_type).
	ndrConds := lm.Resolve("", "akeso_ndr", "")
	if !MatchesEvent(ndrConds, ndrDNS) {
		t.Error("NDR DNS event should match product: akeso_ndr")
	}

	// Should ALSO match category: dns (by event.category + event.action).
	dnsConds := lm.Resolve("dns", "", "")
	if !MatchesEvent(dnsConds, ndrDNS) {
		t.Error("NDR DNS event should match category: dns (dual logsource)")
	}
}

func TestMatchesNDRDetectionEvent(t *testing.T) {
	lm := loadTestMap(t)

	ndrDetection := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_ndr",
		Event: &common.EventFields{
			Kind:     "alert",
			Category: []string{"intrusion_detection"},
			Type:     []string{"info"},
			Action:   "detection",
		},
		NDR: &common.NDRFields{
			Detection: &common.NDRDetection{
				Name:     "C2 Beacon",
				Severity: 8,
			},
		},
	}

	// Should match product: akeso_ndr.
	ndrConds := lm.Resolve("", "akeso_ndr", "")
	if !MatchesEvent(ndrConds, ndrDetection) {
		t.Error("NDR detection should match product: akeso_ndr")
	}

	// Should match category: ids.
	idsConds := lm.Resolve("ids", "", "")
	if !MatchesEvent(idsConds, ndrDetection) {
		t.Error("NDR detection should match category: ids")
	}
}

func TestMatchesNDRKerberosAuthCategory(t *testing.T) {
	lm := loadTestMap(t)

	ndrKerb := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_ndr",
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"network", "authentication"},
			Type:     []string{"protocol"},
			Action:   "kerberos",
		},
	}

	// Should match category: authentication.
	authConds := lm.Resolve("authentication", "", "")
	if !MatchesEvent(authConds, ndrKerb) {
		t.Error("NDR Kerberos event should match category: authentication")
	}
}

func TestMatchesNDRFieldEquals(t *testing.T) {
	// Test the new NDR-specific field matchers.
	ndrEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "akeso_ndr",
		Network: &common.NetworkFields{
			CommunityID: "1:abc123",
			Transport:   "tcp",
		},
		NDR: &common.NDRFields{
			Detection: &common.NDRDetection{
				Name:     "C2 Beacon",
				Category: "command_and_control",
			},
			HostScore: &common.NDRHostScore{
				Quadrant: "critical",
			},
		},
		DNS: &common.DNSFields{
			Question: &common.DNSQuestion{
				Name: "evil.example.com",
			},
			ResponseCode: "NOERROR",
		},
		TLS: &common.TLSFields{
			Version: "1.3",
			Client: &common.TLSClientFields{
				ServerName: "example.com",
				JA3:        "abc123def",
			},
		},
		SMB: &common.SMBFields{
			Action:   "read",
			Filename: "secrets.docx",
		},
		SSH: &common.SSHFields{
			HASSH: "hassh123",
		},
		Process: &common.ProcessFields{
			Name: "sshd",
		},
	}

	tests := []struct {
		field    string
		value    string
		expected bool
	}{
		{"network.community_id", "1:abc123", true},
		{"network.community_id", "1:wrong", false},
		{"network.transport", "tcp", true},
		{"network.transport", "udp", false},
		{"ndr.detection.name", "C2 Beacon", true},
		{"ndr.detection.name", "Wrong Name", false},
		{"ndr.detection.category", "command_and_control", true},
		{"ndr.host_score.quadrant", "critical", true},
		{"ndr.host_score.quadrant", "low", false},
		{"dns.question.name", "evil.example.com", true},
		{"dns.question.name", "safe.example.com", false},
		{"dns.response_code", "NOERROR", true},
		{"tls.client.server_name", "example.com", true},
		{"tls.client.ja3", "abc123def", true},
		{"tls.version", "1.3", true},
		{"tls.version", "1.2", false},
		{"smb.action", "read", true},
		{"smb.filename", "secrets.docx", true},
		{"ssh.hassh", "hassh123", true},
		{"ssh.hassh", "wrong", false},
		{"process.name", "sshd", true},
		{"process.name", "nginx", false},
	}

	for _, tc := range tests {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			conds := map[string]string{tc.field: tc.value}
			got := MatchesEvent(conds, ndrEvent)
			if got != tc.expected {
				t.Errorf("MatchesEvent(%q=%q) = %v, want %v", tc.field, tc.value, got, tc.expected)
			}
		})
	}
}

func TestMatchesNDRFieldEqualsNilStructs(t *testing.T) {
	// Ensure nil NDR structs don't panic.
	emptyEvent := &common.ECSEvent{
		Timestamp: time.Now().UTC(),
	}

	nilTests := []string{
		"network.community_id",
		"ndr.detection.name",
		"ndr.host_score.quadrant",
		"dns.question.name",
		"tls.client.server_name",
		"smb.action",
		"ssh.hassh",
		"process.name",
	}

	for _, field := range nilTests {
		t.Run("nil_"+field, func(t *testing.T) {
			conds := map[string]string{field: "anything"}
			if MatchesEvent(conds, emptyEvent) {
				t.Errorf("MatchesEvent with nil struct should return false for %q", field)
			}
		})
	}
}

func TestNDRDNSDoesNotMatchSyslog(t *testing.T) {
	// Ensure category:dns does NOT match a syslog event that happens to be network-related
	// but doesn't have event.action: dns_query.
	lm := loadTestMap(t)

	syslogNetworkEvent := &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: "syslog",
		Event: &common.EventFields{
			Category: []string{"network"},
			Type:     []string{"connection"},
			Action:   "firewall_drop",
		},
	}

	dnsConds := lm.Resolve("dns", "", "")
	if MatchesEvent(dnsConds, syslogNetworkEvent) {
		t.Error("syslog firewall event should NOT match category: dns")
	}
}
