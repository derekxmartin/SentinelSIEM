package parsers

import (
	"encoding/json"
	"strings"
	"testing"
)

// ============================================================================
// Happy path tests
// ============================================================================

func TestJSONParse4688(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T13:00:00.000Z",
		"source_type": "winevt_json",
		"winlog": {
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
			"event_id": 4688,
			"version": 1,
			"level": "Information",
			"task": "Process Creation",
			"opcode": "Info",
			"keywords": ["Audit Success"],
			"record_id": 55555,
			"channel": "Security",
			"computer_name": "WORKSTATION-01",
			"user": {"identifier": "S-1-5-18"},
			"event_data": {
				"NewProcessId": "0x1a2b",
				"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c whoami",
				"ParentProcessName": "C:\\Windows\\explorer.exe",
				"SubjectUserName": "jsmith",
				"SubjectDomainName": "CORP",
				"TokenElevationType": "%%1936"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 4688 {
		t.Errorf("EventID = %d, want 4688", event.EventID)
	}
	if event.Channel != "Security" {
		t.Errorf("Channel = %q, want %q", event.Channel, "Security")
	}
	if event.Computer != "WORKSTATION-01" {
		t.Errorf("Computer = %q, want %q", event.Computer, "WORKSTATION-01")
	}
	if event.Provider != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider = %q", event.Provider)
	}
	if event.ProviderGUID != "{54849625-5478-4994-a5ba-3e3b0328c30d}" {
		t.Errorf("ProviderGUID = %q", event.ProviderGUID)
	}
	if event.Version != 1 {
		t.Errorf("Version = %d, want 1", event.Version)
	}
	if event.Level != 4 { // "Information" → 4
		t.Errorf("Level = %d, want 4", event.Level)
	}
	if event.RecordID != 55555 {
		t.Errorf("RecordID = %d, want 55555", event.RecordID)
	}
	if event.UserID != "S-1-5-18" {
		t.Errorf("UserID = %q, want %q", event.UserID, "S-1-5-18")
	}
	if !strings.Contains(event.Keywords, "Audit Success") {
		t.Errorf("Keywords = %q, want to contain 'Audit Success'", event.Keywords)
	}

	// EventData.
	assertEventData(t, event, "NewProcessName", `C:\Windows\System32\cmd.exe`)
	assertEventData(t, event, "CommandLine", "cmd.exe /c whoami")
	assertEventData(t, event, "ParentProcessName", `C:\Windows\explorer.exe`)
	assertEventData(t, event, "SubjectUserName", "jsmith")

	// Hex PID via helper.
	pid := event.EventDataGetInt("NewProcessId")
	if pid != 0x1a2b {
		t.Errorf("NewProcessId = %d, want %d", pid, 0x1a2b)
	}
}

func TestJSONParse4624(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:30:45.123Z",
		"winlog": {
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"event_id": 4624,
			"level": "Information",
			"record_id": 98765,
			"channel": "Security",
			"computer_name": "DC01.corp.local",
			"user": {"identifier": "S-1-5-18"},
			"event_data": {
				"SubjectUserSid": "S-1-5-18",
				"TargetUserName": "jsmith",
				"TargetDomainName": "CORP",
				"LogonType": "10",
				"IpAddress": "192.168.1.50",
				"IpPort": "54321",
				"WorkstationName": "WORKSTATION-01"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", event.EventID)
	}
	assertEventData(t, event, "TargetUserName", "jsmith")
	assertEventData(t, event, "LogonType", "10")
	assertEventData(t, event, "IpAddress", "192.168.1.50")
}

func TestJSONParseSysmon1(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T14:00:00.000Z",
		"winlog": {
			"provider_name": "Microsoft-Windows-Sysmon",
			"provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
			"event_id": 1,
			"channel": "Microsoft-Windows-Sysmon/Operational",
			"computer_name": "WORKSTATION-02",
			"event_data": {
				"RuleName": "technique_id=T1059.001",
				"UtcTime": "2026-03-14 14:00:00.000",
				"ProcessGuid": "{12345678-aaaa-bbbb-cccc-ddddeeeeeeee}",
				"ProcessId": "5678",
				"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
				"ParentImage": "C:\\Windows\\System32\\cmd.exe",
				"Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb924,MD5=d41d8cd98f00b204e9800998ecf8427e",
				"User": "CORP\\jsmith",
				"IntegrityLevel": "High"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 1 {
		t.Errorf("EventID = %d, want 1", event.EventID)
	}
	if event.Channel != "Microsoft-Windows-Sysmon/Operational" {
		t.Errorf("Channel = %q", event.Channel)
	}
	assertEventData(t, event, "Image", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
	assertEventData(t, event, "CommandLine", "powershell.exe -nop -w hidden -enc SQBFAFgA")
	assertEventData(t, event, "Hashes", "SHA256=e3b0c44298fc1c149afbf4c8996fb924,MD5=d41d8cd98f00b204e9800998ecf8427e")
}

func TestJSONParseMinimal(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1000,
			"channel": "Application",
			"computer_name": "MYPC"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 1000 {
		t.Errorf("EventID = %d, want 1000", event.EventID)
	}
	if event.Channel != "Application" {
		t.Errorf("Channel = %q", event.Channel)
	}
	if len(event.EventData) != 0 {
		t.Errorf("EventData should be empty, got %d entries", len(event.EventData))
	}
	if event.UserID != "" {
		t.Errorf("UserID should be empty, got %q", event.UserID)
	}
	if !event.TimeCreated.IsZero() {
		t.Errorf("TimeCreated should be zero, got %v", event.TimeCreated)
	}
}

func TestJSONParseUserData(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T15:00:00Z",
		"winlog": {
			"event_id": 541,
			"channel": "DNS Server",
			"computer_name": "DNS01",
			"user_data": {
				"Zone": "corp.local",
				"QNAME": "evil.example.com",
				"QTYPE": "A"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertEventData(t, event, "Zone", "corp.local")
	assertEventData(t, event, "QNAME", "evil.example.com")
}

func TestJSONParseBatch(t *testing.T) {
	docs := []json.RawMessage{
		json.RawMessage(`{"winlog":{"event_id":4624,"channel":"Security","computer_name":"DC01"}}`),
		json.RawMessage(`{"winlog":{"event_id":4688,"channel":"Security","computer_name":"WS01"}}`),
	}

	events, errs := ParseWinEventJSONBatch(docs)
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].EventID != 4624 || events[1].EventID != 4688 {
		t.Errorf("EventIDs = [%d, %d], want [4624, 4688]", events[0].EventID, events[1].EventID)
	}
}

// ============================================================================
// Level mapping tests
// ============================================================================

func TestJSONLevelMapping(t *testing.T) {
	cases := []struct {
		level string
		want  int
	}{
		{"Critical", 1},
		{"Error", 2},
		{"Warning", 3},
		{"Information", 4},
		{"Info", 4},
		{"Verbose", 5},
		{"Audit Success", 0},
		{"Audit Failure", 0},
		{"audit_success", 0},
		{"audit_failure", 0},
		{"INFORMATION", 4},    // case insensitive
		{"  Warning  ", 3},    // whitespace trimmed
		{"", 0},               // empty
		{"UnknownLevel", 0},   // unknown
	}

	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			got := winlogLevelToInt(tc.level)
			if got != tc.want {
				t.Errorf("winlogLevelToInt(%q) = %d, want %d", tc.level, got, tc.want)
			}
		})
	}
}

// ============================================================================
// EventID format variants
// ============================================================================

func TestJSONEventIDAsObject(t *testing.T) {
	// Some forwarders send event_id as {"value": 4624, "qualifiers": 0}.
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": {"value": 4624, "qualifiers": 0},
			"channel": "Security",
			"computer_name": "DC01"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", event.EventID)
	}
}

func TestJSONEventIDAsString(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": "7045",
			"channel": "System",
			"computer_name": "SRV01"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 7045 {
		t.Errorf("EventID = %d, want 7045", event.EventID)
	}
}

// ============================================================================
// Timestamp tests
// ============================================================================

func TestJSONTimestampFormats(t *testing.T) {
	cases := []struct {
		name string
		ts   string
	}{
		{"RFC3339", "2026-03-14T12:00:00Z"},
		{"RFC3339_millis", "2026-03-14T12:00:00.123Z"},
		{"RFC3339_micros", "2026-03-14T12:00:00.123456Z"},
		{"RFC3339_nanos", "2026-03-14T12:00:00.123456789Z"},
		{"RFC3339_7frac", "2026-03-14T12:00:00.1234567Z"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(`{"@timestamp":"` + tc.ts + `","winlog":{"event_id":1,"channel":"Test","computer_name":"TEST"}}`)
			event, err := ParseWinEventJSON(raw)
			if err != nil {
				t.Fatalf("failed for timestamp %q: %v", tc.ts, err)
			}
			if event.TimeCreated.IsZero() {
				t.Errorf("TimeCreated is zero for %q", tc.ts)
			}
			if event.TimeCreated.Year() != 2026 {
				t.Errorf("year = %d, want 2026", event.TimeCreated.Year())
			}
		})
	}
}

func TestJSONTimestampTimezone(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:00:00+05:00",
		"winlog": {"event_id": 1, "channel": "Test", "computer_name": "TEST"}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.TimeCreated.Hour() != 7 {
		t.Errorf("hour = %d, want 7 (UTC)", event.TimeCreated.Hour())
	}
}

// ============================================================================
// XML ↔ JSON equivalence
// ============================================================================

func TestXMLAndJSONProduceSameWinEvent(t *testing.T) {
	// Same 4624 event in both formats → identical WinEvent fields.
	xmlData := []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <TimeCreated SystemTime="2026-03-14T12:30:45.000Z" />
    <EventRecordID>98765</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
  </EventData>
</Event>`)

	jsonData := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:30:45.000Z",
		"winlog": {
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
			"event_id": 4624,
			"version": 2,
			"level": "Audit Success",
			"record_id": 98765,
			"channel": "Security",
			"computer_name": "DC01.corp.local",
			"user": {"identifier": "S-1-5-18"},
			"event_data": {
				"TargetUserName": "jsmith",
				"LogonType": "10",
				"IpAddress": "192.168.1.50"
			}
		}
	}`)

	xmlEvent, err := ParseWinEventXML(xmlData)
	if err != nil {
		t.Fatalf("XML parse error: %v", err)
	}

	jsonEvent, err := ParseWinEventJSON(jsonData)
	if err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Core fields must match.
	if xmlEvent.EventID != jsonEvent.EventID {
		t.Errorf("EventID: XML=%d, JSON=%d", xmlEvent.EventID, jsonEvent.EventID)
	}
	if xmlEvent.Channel != jsonEvent.Channel {
		t.Errorf("Channel: XML=%q, JSON=%q", xmlEvent.Channel, jsonEvent.Channel)
	}
	if xmlEvent.Computer != jsonEvent.Computer {
		t.Errorf("Computer: XML=%q, JSON=%q", xmlEvent.Computer, jsonEvent.Computer)
	}
	if xmlEvent.Provider != jsonEvent.Provider {
		t.Errorf("Provider: XML=%q, JSON=%q", xmlEvent.Provider, jsonEvent.Provider)
	}
	if xmlEvent.ProviderGUID != jsonEvent.ProviderGUID {
		t.Errorf("ProviderGUID: XML=%q, JSON=%q", xmlEvent.ProviderGUID, jsonEvent.ProviderGUID)
	}
	if xmlEvent.RecordID != jsonEvent.RecordID {
		t.Errorf("RecordID: XML=%d, JSON=%d", xmlEvent.RecordID, jsonEvent.RecordID)
	}
	if xmlEvent.UserID != jsonEvent.UserID {
		t.Errorf("UserID: XML=%q, JSON=%q", xmlEvent.UserID, jsonEvent.UserID)
	}
	if !xmlEvent.TimeCreated.Equal(jsonEvent.TimeCreated) {
		t.Errorf("TimeCreated: XML=%v, JSON=%v", xmlEvent.TimeCreated, jsonEvent.TimeCreated)
	}

	// EventData fields must match.
	for key, xmlVal := range xmlEvent.EventData {
		jsonVal, ok := jsonEvent.EventData[key]
		if !ok {
			t.Errorf("EventData[%q]: present in XML but not JSON", key)
			continue
		}
		if xmlVal != jsonVal {
			t.Errorf("EventData[%q]: XML=%q, JSON=%q", key, xmlVal, jsonVal)
		}
	}
	for key := range jsonEvent.EventData {
		if _, ok := xmlEvent.EventData[key]; !ok {
			t.Errorf("EventData[%q]: present in JSON but not XML", key)
		}
	}
}

// ============================================================================
// Adversarial / breaking tests
// ============================================================================

func TestJSONParseEmptyInput(t *testing.T) {
	_, err := ParseWinEventJSON(json.RawMessage{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestJSONParseNilInput(t *testing.T) {
	_, err := ParseWinEventJSON(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestJSONParseMalformedJSON(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"not_json", "this is not json"},
		{"xml_instead", "<Event><System><EventID>1</EventID></System></Event>"},
		{"partial_json", `{"winlog": {`},
		{"binary_garbage", "\x00\x01\x02"},
		{"array_instead", `[1,2,3]`},
		{"number_instead", `42`},
		{"string_instead", `"hello"`},
		{"null", `null`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWinEventJSON(json.RawMessage(tc.raw))
			if err == nil {
				t.Error("expected error for malformed input")
			}
			// Key: no panic.
		})
	}
}

func TestJSONParseMissingWinlog(t *testing.T) {
	raw := json.RawMessage(`{"@timestamp": "2026-03-14T12:00:00Z", "source_type": "winevt_json"}`)
	_, err := ParseWinEventJSON(raw)
	if err == nil {
		t.Fatal("expected error for missing winlog field")
	}
	if !strings.Contains(err.Error(), "missing 'winlog'") {
		t.Errorf("error = %q, want to contain 'missing winlog'", err.Error())
	}
}

func TestJSONParseNullWinlog(t *testing.T) {
	raw := json.RawMessage(`{"winlog": null}`)
	_, err := ParseWinEventJSON(raw)
	if err == nil {
		t.Fatal("expected error for null winlog")
	}
}

func TestJSONParseMissingEventData(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1000,
			"channel": "Application",
			"computer_name": "MYPC"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData) != 0 {
		t.Errorf("EventData should be empty, got %d entries", len(event.EventData))
	}
}

func TestJSONParseInvalidTimestamp(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "not-a-timestamp",
		"winlog": {"event_id": 1, "channel": "Test", "computer_name": "TEST"}
	}`)

	_, err := ParseWinEventJSON(raw)
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

func TestJSONParseExtraFields(t *testing.T) {
	// Extra top-level fields should be silently ignored.
	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:00:00Z",
		"agent": {"name": "winlogbeat", "version": "8.12.0"},
		"ecs": {"version": "8.11.0"},
		"host": {"name": "WORKSTATION-01"},
		"tags": ["beats_input_codec_plain_applied"],
		"totally_unknown_field": {"nested": true},
		"winlog": {
			"event_id": 4688,
			"channel": "Security",
			"computer_name": "WORKSTATION-01",
			"event_data": {
				"NewProcessName": "C:\\test.exe"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 4688 {
		t.Errorf("EventID = %d, want 4688", event.EventID)
	}
	assertEventData(t, event, "NewProcessName", `C:\test.exe`)
}

func TestJSONParseLargeEventData(t *testing.T) {
	// 100 fields in event_data.
	eventData := make(map[string]string, 100)
	for i := 0; i < 100; i++ {
		eventData[string(rune('A'+i%26))+strings.Repeat("x", i)] = strings.Repeat("v", i+1)
	}
	dataBytes, _ := json.Marshal(eventData)

	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 9999,
			"channel": "Test",
			"computer_name": "TEST",
			"event_data": ` + string(dataBytes) + `
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData) != 100 {
		t.Errorf("EventData count = %d, want 100", len(event.EventData))
	}
}

func TestJSONParseLargeFieldValue(t *testing.T) {
	// 50KB ScriptBlockText.
	largeValue := strings.Repeat("A", 50000)
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 4104,
			"channel": "Microsoft-Windows-PowerShell/Operational",
			"computer_name": "TEST",
			"event_data": {
				"ScriptBlockText": "` + largeValue + `"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData["ScriptBlockText"]) != 50000 {
		t.Errorf("ScriptBlockText length = %d, want 50000", len(event.EventData["ScriptBlockText"]))
	}
}

func TestJSONParseSpecialCharsInEventData(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST",
			"event_data": {
				"CommandLine": "cmd.exe /c \"echo <hello> & whoami\"",
				"Unicode": "日本語テスト",
				"Newlines": "line1\nline2\nline3",
				"Tabs": "col1\tcol2\tcol3",
				"Backslash": "C:\\Users\\john\\test.exe",
				"Empty": "",
				"NullLike": "null"
			}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertEventData(t, event, "CommandLine", `cmd.exe /c "echo <hello> & whoami"`)
	assertEventData(t, event, "Unicode", "日本語テスト")
	assertEventData(t, event, "Backslash", `C:\Users\john\test.exe`)
	assertEventData(t, event, "Empty", "")
	assertEventData(t, event, "NullLike", "null")
	if !strings.Contains(event.EventData["Newlines"], "line2") {
		t.Errorf("Newlines should contain 'line2', got %q", event.EventData["Newlines"])
	}
}

func TestJSONParseEmptyWinlogObject(t *testing.T) {
	raw := json.RawMessage(`{"winlog": {}}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 0 {
		t.Errorf("EventID = %d, want 0", event.EventID)
	}
	if event.Channel != "" {
		t.Errorf("Channel = %q, want empty", event.Channel)
	}
}

func TestJSONParseBothEventDataAndUserData(t *testing.T) {
	// EventData should take precedence.
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST",
			"event_data": {"FromEventData": "edvalue"},
			"user_data": {"FromUserData": "udvalue"}
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertEventData(t, event, "FromEventData", "edvalue")
	if _, found := event.EventData["FromUserData"]; found {
		t.Error("UserData should not be used when EventData is present")
	}
}

func TestJSONParseBatchMixedValidInvalid(t *testing.T) {
	docs := []json.RawMessage{
		json.RawMessage(`{"winlog":{"event_id":1,"channel":"Test","computer_name":"TEST"}}`),
		json.RawMessage(`{broken json`),
		json.RawMessage(`{}`),
		json.RawMessage(`{"winlog":{"event_id":2,"channel":"Test","computer_name":"TEST"}}`),
	}

	events, errs := ParseWinEventJSONBatch(docs)
	if len(events) != 2 {
		t.Errorf("events = %d, want 2", len(events))
	}
	if len(errs) != 2 {
		t.Errorf("errors = %d, want 2 (broken json + missing winlog)", len(errs))
	}
}

func TestJSONParseMultipleKeywords(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST",
			"keywords": ["Audit Success", "Correlation"]
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(event.Keywords, "Audit Success") {
		t.Errorf("Keywords = %q, want to contain 'Audit Success'", event.Keywords)
	}
	if !strings.Contains(event.Keywords, "Correlation") {
		t.Errorf("Keywords = %q, want to contain 'Correlation'", event.Keywords)
	}
}

func TestJSONParseNoKeywords(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Keywords != "" {
		t.Errorf("Keywords = %q, want empty", event.Keywords)
	}
}

func TestJSONParseNoUser(t *testing.T) {
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST"
		}
	}`)

	event, err := ParseWinEventJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.UserID != "" {
		t.Errorf("UserID = %q, want empty", event.UserID)
	}
}

// ============================================================================
// Format detection
// ============================================================================

func TestDetectWinEventFormat(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"winlogbeat", `{"winlog":{"event_id":1}}`, "winlogbeat"},
		{"xml_wrapper", `{"xml":"<Event>...</Event>"}`, "xml"},
		{"event_wrapper", `{"Event":{"System":{}}}`, "xml"},
		{"unknown", `{"data":"test"}`, "unknown"},
		{"invalid_json", `not json`, "unknown"},
		{"empty", `{}`, "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectWinEventFormat(json.RawMessage(tc.raw))
			if got != tc.want {
				t.Errorf("DetectWinEventFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

// ============================================================================
// Timestamp fallback
// ============================================================================

func TestWinlogTimestampFallback(t *testing.T) {
	cases := []struct {
		name      string
		eventData map[string]string
		wantZero  bool
	}{
		{"UtcTime", map[string]string{"UtcTime": "2026-03-14 14:00:00"}, false},
		{"TimeGenerated", map[string]string{"TimeGenerated": "2026-03-14T14:00:00Z"}, false},
		{"SystemTime", map[string]string{"SystemTime": "2026-03-14T14:00:00.000Z"}, false},
		{"no_ts", map[string]string{"SomeField": "value"}, true},
		{"empty", map[string]string{}, true},
		{"invalid_ts", map[string]string{"UtcTime": "not-a-time"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := winlogTimestampFallback(tc.eventData)
			if tc.wantZero && !ts.IsZero() {
				t.Errorf("expected zero time, got %v", ts)
			}
			if !tc.wantZero && ts.IsZero() {
				t.Error("expected non-zero time, got zero")
			}
		})
	}
}

func TestJSONEventDataMutation(t *testing.T) {
	// Verify mutating the returned EventData doesn't affect re-parsing.
	raw := json.RawMessage(`{
		"winlog": {
			"event_id": 1,
			"channel": "Test",
			"computer_name": "TEST",
			"event_data": {"Key": "original"}
		}
	}`)

	event1, _ := ParseWinEventJSON(raw)
	event1.EventData["Key"] = "mutated"
	event1.EventData["NewKey"] = "injected"

	event2, _ := ParseWinEventJSON(raw)
	if event2.EventData["Key"] != "original" {
		t.Errorf("mutation leaked: Key = %q, want 'original'", event2.EventData["Key"])
	}
	if _, found := event2.EventData["NewKey"]; found {
		t.Error("mutation leaked: NewKey should not exist in re-parsed event")
	}
}
