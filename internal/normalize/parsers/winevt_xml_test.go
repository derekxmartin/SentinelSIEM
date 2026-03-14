package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Happy path tests
// ============================================================================

func TestParse4624XML(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-03-14T12:30:45.1234567Z" />
    <EventRecordID>98765</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="TargetUserSid">S-1-5-21-1234-5678-9012-1001</Data>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="WorkstationName">WORKSTATION-01</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="IpPort">54321</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// System fields.
	if event.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", event.EventID)
	}
	if event.Channel != "Security" {
		t.Errorf("Channel = %q, want %q", event.Channel, "Security")
	}
	if event.Computer != "DC01.corp.local" {
		t.Errorf("Computer = %q, want %q", event.Computer, "DC01.corp.local")
	}
	if event.Provider != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider = %q", event.Provider)
	}
	if event.ProviderGUID != "{54849625-5478-4994-a5ba-3e3b0328c30d}" {
		t.Errorf("ProviderGUID = %q", event.ProviderGUID)
	}
	if event.Version != 2 {
		t.Errorf("Version = %d, want 2", event.Version)
	}
	if event.Level != 0 {
		t.Errorf("Level = %d, want 0", event.Level)
	}
	if event.Task != 12544 {
		t.Errorf("Task = %d, want 12544", event.Task)
	}
	if event.Keywords != "0x8020000000000000" {
		t.Errorf("Keywords = %q", event.Keywords)
	}
	if event.RecordID != 98765 {
		t.Errorf("RecordID = %d, want 98765", event.RecordID)
	}
	if event.UserID != "S-1-5-18" {
		t.Errorf("UserID = %q, want %q", event.UserID, "S-1-5-18")
	}

	// Timestamp with 7-digit fractional seconds.
	expectedTime := time.Date(2026, 3, 14, 12, 30, 45, 123456700, time.UTC)
	if !event.TimeCreated.Equal(expectedTime) {
		t.Errorf("TimeCreated = %v, want %v", event.TimeCreated, expectedTime)
	}

	// EventData fields.
	assertEventData(t, event, "TargetUserName", "jsmith")
	assertEventData(t, event, "TargetDomainName", "CORP")
	assertEventData(t, event, "LogonType", "10")
	assertEventData(t, event, "IpAddress", "192.168.1.50")
	assertEventData(t, event, "IpPort", "54321")
	assertEventData(t, event, "WorkstationName", "WORKSTATION-01")
	assertEventData(t, event, "SubjectUserSid", "S-1-5-18")
}

func TestParse4688XML(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-03-14T13:00:00.000Z" />
    <Channel>Security</Channel>
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x1a2b</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="TokenElevationType">%%1936</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 4688 {
		t.Errorf("EventID = %d, want 4688", event.EventID)
	}
	assertEventData(t, event, "NewProcessName", `C:\Windows\System32\cmd.exe`)
	assertEventData(t, event, "CommandLine", "cmd.exe /c whoami")
	assertEventData(t, event, "ParentProcessName", `C:\Windows\explorer.exe`)

	// Test hex integer parsing helper.
	pid := event.EventDataGetInt("NewProcessId")
	if pid != 0x1a2b {
		t.Errorf("NewProcessId (hex) = %d, want %d", pid, 0x1a2b)
	}
}

func TestParseSysmon1XML(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-03-14T14:00:00.000000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WORKSTATION-02</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">technique_id=T1059.001,technique_name=PowerShell</Data>
    <Data Name="UtcTime">2026-03-14 14:00:00.000</Data>
    <Data Name="ProcessGuid">{12345678-aaaa-bbbb-cccc-ddddeeeeeeee}</Data>
    <Data Name="ProcessId">5678</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
    <Data Name="ParentProcessGuid">{12345678-1111-2222-3333-444444444444}</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentCommandLine">cmd.exe</Data>
    <Data Name="Hashes">SHA256=e3b0c44298fc1c149afbf4c8996fb924,MD5=d41d8cd98f00b204e9800998ecf8427e</Data>
    <Data Name="User">CORP\jsmith</Data>
    <Data Name="IntegrityLevel">High</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
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
	assertEventData(t, event, "ParentImage", `C:\Windows\System32\cmd.exe`)
	assertEventData(t, event, "Hashes", "SHA256=e3b0c44298fc1c149afbf4c8996fb924,MD5=d41d8cd98f00b204e9800998ecf8427e")
	assertEventData(t, event, "User", `CORP\jsmith`)
	assertEventData(t, event, "IntegrityLevel", "High")
}

func TestParseMinimalXML(t *testing.T) {
	// Only System block, no EventData at all.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1000</EventID>
    <Channel>Application</Channel>
    <Computer>MYPC</Computer>
    <TimeCreated SystemTime="2026-03-14T10:00:00Z" />
  </System>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 1000 {
		t.Errorf("EventID = %d, want 1000", event.EventID)
	}
	if len(event.EventData) != 0 {
		t.Errorf("EventData should be empty, got %d entries", len(event.EventData))
	}
	if event.Provider != "" {
		t.Errorf("Provider should be empty, got %q", event.Provider)
	}
	if event.UserID != "" {
		t.Errorf("UserID should be empty, got %q", event.UserID)
	}
}

func TestParseUserDataXML(t *testing.T) {
	// Some Windows events use UserData instead of EventData.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNS-Server-Service" />
    <EventID>541</EventID>
    <TimeCreated SystemTime="2026-03-14T15:00:00Z" />
    <Channel>DNS Server</Channel>
    <Computer>DNS01</Computer>
  </System>
  <UserData>
    <EventInfo>
      <Zone>corp.local</Zone>
      <Source>192.168.1.1</Source>
      <QNAME>evil.example.com</QNAME>
      <QTYPE>A</QTYPE>
    </EventInfo>
  </UserData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventID != 541 {
		t.Errorf("EventID = %d, want 541", event.EventID)
	}
	assertEventData(t, event, "Zone", "corp.local")
	assertEventData(t, event, "QNAME", "evil.example.com")
	assertEventData(t, event, "QTYPE", "A")
	assertEventData(t, event, "Source", "192.168.1.1")
}

func TestParseNamelessData(t *testing.T) {
	// Some events have <Data> without Name attributes.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1001</EventID>
    <TimeCreated SystemTime="2026-03-14T16:00:00Z" />
    <Channel>Application</Channel>
    <Computer>MYPC</Computer>
  </System>
  <EventData>
    <Data>first value</Data>
    <Data>second value</Data>
    <Data Name="Named">named value</Data>
    <Data>third value</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertEventData(t, event, "_0", "first value")
	assertEventData(t, event, "_1", "second value")
	assertEventData(t, event, "Named", "named value")
	assertEventData(t, event, "_2", "third value")
}

func TestParseBatch(t *testing.T) {
	doc1 := []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID><Channel>Security</Channel><Computer>DC01</Computer>
  <TimeCreated SystemTime="2026-03-14T10:00:00Z" /></System></Event>`)

	doc2 := []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID><Channel>Security</Channel><Computer>WS01</Computer>
  <TimeCreated SystemTime="2026-03-14T11:00:00Z" /></System></Event>`)

	events, errs := ParseWinEventXMLBatch([][]byte{doc1, doc2})
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
// Timestamp edge cases
// ============================================================================

func TestParseTimestampFormats(t *testing.T) {
	cases := []struct {
		name   string
		ts     string
		wantNs int // expected nanosecond component
	}{
		{"RFC3339_no_frac", "2026-03-14T12:00:00Z", 0},
		{"RFC3339_3_frac", "2026-03-14T12:00:00.123Z", 123000000},
		{"RFC3339_7_frac", "2026-03-14T12:00:00.1234567Z", 123456700},
		{"RFC3339_9_frac", "2026-03-14T12:00:00.123456789Z", 123456789},
		{"space_separator", "2026-03-14 12:00:00", 0},
		{"RFC3339_6_frac", "2026-03-14T12:00:00.123456Z", 123456000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xml := fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="%s" />
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
  </System>
</Event>`, tc.ts)

			event, err := ParseWinEventXML([]byte(xml))
			if err != nil {
				t.Fatalf("failed to parse timestamp %q: %v", tc.ts, err)
			}
			if event.TimeCreated.Nanosecond() != tc.wantNs {
				t.Errorf("nanoseconds = %d, want %d", event.TimeCreated.Nanosecond(), tc.wantNs)
			}
		})
	}
}

func TestParseTimestampWithTimezone(t *testing.T) {
	// Ensure non-UTC timezone is converted to UTC.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-03-14T12:00:00+05:00" />
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
  </System>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 12:00 +05:00 = 07:00 UTC
	if event.TimeCreated.Hour() != 7 {
		t.Errorf("hour = %d, want 7 (UTC)", event.TimeCreated.Hour())
	}
}

func TestParseNoTimestamp(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
  </System>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !event.TimeCreated.IsZero() {
		t.Errorf("expected zero time, got %v", event.TimeCreated)
	}
}

// ============================================================================
// Breaking / adversarial tests
// ============================================================================

func TestParseEmptyInput(t *testing.T) {
	_, err := ParseWinEventXML([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseNilInput(t *testing.T) {
	_, err := ParseWinEventXML(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestParseMalformedXML(t *testing.T) {
	cases := []struct {
		name string
		xml  string
	}{
		{"unclosed_tag", "<Event><System><EventID>1</EventID></System>"},
		{"not_xml", "this is not xml at all"},
		{"json_instead", `{"EventID": 4624}`},
		{"partial_tag", "<Event><Sys"},
		{"binary_garbage", "\x00\x01\x02\x03\x04\x05"},
		{"empty_element", "<Event></Event>"},
		{"wrong_root", "<NotAnEvent><System><EventID>1</EventID></System></NotAnEvent>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWinEventXML([]byte(tc.xml))
			// Most should error, but some (like empty Event) may parse with zero values.
			// The key is: no panic.
			_ = err
		})
	}
}

func TestParseInvalidEventID(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>not_a_number</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
</Event>`

	_, err := ParseWinEventXML([]byte(xml))
	if err == nil {
		t.Fatal("expected error for non-numeric EventID")
	}
}

func TestParseInvalidTimestamp(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="not-a-timestamp" />
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
  </System>
</Event>`

	_, err := ParseWinEventXML([]byte(xml))
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

func TestParseHugeEventData(t *testing.T) {
	// 100 EventData fields — should handle without issue.
	var dataFields strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&dataFields, `    <Data Name="Field%d">value%d</Data>`+"\n", i, i)
	}

	xml := fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>9999</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
%s  </EventData>
</Event>`, dataFields.String())

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData) != 100 {
		t.Errorf("EventData count = %d, want 100", len(event.EventData))
	}
	assertEventData(t, event, "Field0", "value0")
	assertEventData(t, event, "Field99", "value99")
}

func TestParseEventDataWithSpecialChars(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
    <Data Name="CommandLine">cmd.exe /c "echo &lt;hello&gt; &amp; whoami"</Data>
    <Data Name="Path">C:\Users\john&apos;s files\test.exe</Data>
    <Data Name="Unicode">日本語テスト</Data>
    <Data Name="Empty"></Data>
    <Data Name="Newlines">line1
line2
line3</Data>
    <Data Name="Tabs">col1	col2	col3</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertEventData(t, event, "CommandLine", `cmd.exe /c "echo <hello> & whoami"`)
	assertEventData(t, event, "Path", `C:\Users\john's files\test.exe`)
	assertEventData(t, event, "Unicode", "日本語テスト")
	assertEventData(t, event, "Empty", "")
	if !strings.Contains(event.EventData["Newlines"], "line2") {
		t.Errorf("Newlines field should contain 'line2', got %q", event.EventData["Newlines"])
	}
	if !strings.Contains(event.EventData["Tabs"], "col2") {
		t.Errorf("Tabs field should contain 'col2', got %q", event.EventData["Tabs"])
	}
}

func TestParseDuplicateEventDataKeys(t *testing.T) {
	// If two <Data Name="Foo"> appear, last one wins (map behavior).
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
    <Data Name="Duplicate">first</Data>
    <Data Name="Duplicate">second</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Last value should win.
	assertEventData(t, event, "Duplicate", "second")
}

func TestParseEventIDWithQualifiers(t *testing.T) {
	// Some Windows versions use <EventID Qualifiers="0">4624</EventID>.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID Qualifiers="16384">4624</EventID>
    <Channel>Security</Channel>
    <Computer>DC01</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", event.EventID)
	}
}

func TestParseEventIDWithWhitespace(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>
      4624
    </EventID>
    <Channel>Security</Channel>
    <Computer>DC01</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", event.EventID)
	}
}

func TestParseWithBOM(t *testing.T) {
	// UTF-8 BOM (0xEF 0xBB 0xBF) at start of document.
	xml := "\xef\xbb\xbf" + `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
</Event>`

	// Go's xml.Unmarshal may or may not handle BOM. We should not panic.
	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		// BOM might cause parse error — that's acceptable, not a panic.
		t.Logf("BOM handling: %v (acceptable)", err)
		return
	}
	if event.EventID != 1 {
		t.Errorf("EventID = %d, want 1", event.EventID)
	}
}

func TestParseNoNamespace(t *testing.T) {
	// Some forwarded events may lack the namespace.
	xml := `<Event>
  <System>
    <EventID>7045</EventID>
    <Channel>System</Channel>
    <Computer>SERVER01</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
    <Data Name="ServiceName">EvilService</Data>
    <Data Name="ImagePath">C:\temp\evil.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != 7045 {
		t.Errorf("EventID = %d, want 7045", event.EventID)
	}
	assertEventData(t, event, "ServiceName", "EvilService")
}

func TestParseBothEventDataAndUserData(t *testing.T) {
	// If both are present, EventData takes precedence.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
    <Data Name="FromEventData">edvalue</Data>
  </EventData>
  <UserData>
    <Info>
      <FromUserData>udvalue</FromUserData>
    </Info>
  </UserData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// EventData should be populated, UserData ignored when EventData present.
	assertEventData(t, event, "FromEventData", "edvalue")
	if _, found := event.EventData["FromUserData"]; found {
		t.Error("UserData should not be parsed when EventData is present")
	}
}

func TestParseBatchMixedValidInvalid(t *testing.T) {
	valid := []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>1</EventID><Channel>Test</Channel><Computer>TEST</Computer>
  <TimeCreated SystemTime="2026-03-14T12:00:00Z" /></System></Event>`)
	invalid := []byte(`<Not valid XML`)
	empty := []byte{}

	events, errs := ParseWinEventXMLBatch([][]byte{valid, invalid, empty, valid})
	if len(events) != 2 {
		t.Errorf("events = %d, want 2", len(events))
	}
	if len(errs) != 2 {
		t.Errorf("errors = %d, want 2", len(errs))
	}
}

func TestParseVeryLargeEventDataValue(t *testing.T) {
	// 50KB value in a single field (e.g., PowerShell ScriptBlockText).
	largeValue := strings.Repeat("A", 50000)
	xml := fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
    <Data Name="ScriptBlockText">%s</Data>
  </EventData>
</Event>`, largeValue)

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData["ScriptBlockText"]) != 50000 {
		t.Errorf("ScriptBlockText length = %d, want 50000", len(event.EventData["ScriptBlockText"]))
	}
}

func TestParseEmptyEventData(t *testing.T) {
	// <EventData> present but no <Data> children.
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Channel>Test</Channel>
    <Computer>TEST</Computer>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
  </System>
  <EventData>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.EventData) != 0 {
		t.Errorf("EventData should be empty, got %d entries", len(event.EventData))
	}
}

// ============================================================================
// Helper method tests
// ============================================================================

func TestEventDataGet(t *testing.T) {
	event := &WinEvent{
		EventData: map[string]string{
			"Present": "value",
			"Empty":   "",
		},
	}

	if v := event.EventDataGet("Present", "default"); v != "value" {
		t.Errorf("Present = %q, want %q", v, "value")
	}
	if v := event.EventDataGet("Empty", "default"); v != "default" {
		t.Errorf("Empty = %q, want %q (default for empty string)", v, "default")
	}
	if v := event.EventDataGet("Missing", "default"); v != "default" {
		t.Errorf("Missing = %q, want %q", v, "default")
	}
}

func TestEventDataGetInt(t *testing.T) {
	event := &WinEvent{
		EventData: map[string]string{
			"Decimal":  "1234",
			"Hex":      "0x1A2B",
			"HexUpper": "0X3C4D",
			"Invalid":  "not_a_number",
			"Empty":    "",
			"Negative": "-42",
			"Zero":     "0",
		},
	}

	cases := []struct {
		key  string
		want int
	}{
		{"Decimal", 1234},
		{"Hex", 0x1A2B},
		{"HexUpper", 0x3C4D},
		{"Invalid", 0},
		{"Empty", 0},
		{"Missing", 0},
		{"Negative", -42},
		{"Zero", 0},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got := event.EventDataGetInt(tc.key)
			if got != tc.want {
				t.Errorf("EventDataGetInt(%q) = %d, want %d", tc.key, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Roundtrip: parse then serialize WinEvent as JSON (verifies no data loss)
// ============================================================================

func TestWinEventJSONRoundTrip(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-03-14T12:30:45.123Z" />
    <EventRecordID>98765</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>`

	event, err := ParseWinEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Marshal to JSON.
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json marshal error: %v", err)
	}

	// Should contain key fields.
	jsonStr := string(data)
	for _, expected := range []string{"4624", "Security", "DC01.corp.local", "jsmith"} {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("JSON missing expected value %q", expected)
		}
	}
}

// ============================================================================
// Helpers
// ============================================================================

func assertEventData(t *testing.T, event *WinEvent, key, want string) {
	t.Helper()
	got, ok := event.EventData[key]
	if !ok {
		t.Errorf("EventData[%q] not found", key)
		return
	}
	if got != want {
		t.Errorf("EventData[%q] = %q, want %q", key, got, want)
	}
}
