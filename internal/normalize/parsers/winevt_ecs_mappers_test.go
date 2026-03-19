package parsers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// ============================================================================
// Helper to build WinEvent for testing
// ============================================================================

func makeWinEvent(eventID int, channel, computer string, data map[string]string) *WinEvent {
	if data == nil {
		data = make(map[string]string)
	}
	return &WinEvent{
		Provider:    "Microsoft-Windows-Security-Auditing",
		EventID:     eventID,
		TimeCreated: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Channel:     channel,
		Computer:    computer,
		EventData:   data,
	}
}

func makeSysmonEvent(eventID int, data map[string]string) *WinEvent {
	if data == nil {
		data = make(map[string]string)
	}
	return &WinEvent{
		Provider:    "Microsoft-Windows-Sysmon",
		EventID:     eventID,
		TimeCreated: time.Date(2026, 3, 14, 14, 0, 0, 0, time.UTC),
		Channel:     "Microsoft-Windows-Sysmon/Operational",
		Computer:    "WORKSTATION-02",
		EventData:   data,
	}
}

// ============================================================================
// 4624 — Successful Logon
// ============================================================================

func TestMapper4624Interactive(t *testing.T) {
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName":   "jsmith",
		"TargetDomainName": "CORP",
		"TargetUserSid":    "S-1-5-21-1234-5678-9012-1001",
		"LogonType":        "2",
		"IpAddress":        "192.168.1.50",
		"IpPort":           "54321",
	})

	event := MapWinEventToECS(w)

	assertECSCategory(t, event, "authentication")
	assertECSType(t, event, "start")
	if event.Event.Action != "logon-interactive" {
		t.Errorf("action = %q, want %q", event.Event.Action, "logon-interactive")
	}
	if event.Event.Outcome != "success" {
		t.Errorf("outcome = %q, want %q", event.Event.Outcome, "success")
	}
	if event.User.Name != "jsmith" {
		t.Errorf("user.name = %q, want %q", event.User.Name, "jsmith")
	}
	if event.User.Domain != "CORP" {
		t.Errorf("user.domain = %q, want %q", event.User.Domain, "CORP")
	}
	if event.Source == nil || event.Source.IP != "192.168.1.50" {
		t.Errorf("source.ip = %v, want %q", event.Source, "192.168.1.50")
	}
	if event.Source.Port != 54321 {
		t.Errorf("source.port = %d, want 54321", event.Source.Port)
	}
	if event.Host.Name != "DC01" {
		t.Errorf("host.name = %q, want %q", event.Host.Name, "DC01")
	}
}

func TestMapper4624Network(t *testing.T) {
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName": "admin",
		"LogonType":      "3",
		"IpAddress":      "10.0.0.5",
	})

	event := MapWinEventToECS(w)
	if event.Event.Action != "logon-network" {
		t.Errorf("action = %q, want %q", event.Event.Action, "logon-network")
	}
}

func TestMapper4624RemoteInteractive(t *testing.T) {
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName": "admin",
		"LogonType":      "10",
		"IpAddress":      "172.16.0.1",
	})

	event := MapWinEventToECS(w)
	if event.Event.Action != "logon-remoteinteractive" {
		t.Errorf("action = %q, want %q", event.Event.Action, "logon-remoteinteractive")
	}
}

func TestMapper4624MissingIP(t *testing.T) {
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName": "localuser",
		"LogonType":      "2",
	})

	event := MapWinEventToECS(w)
	if event.Source != nil {
		t.Error("source should be nil for local logon without IP")
	}
}

func TestMapper4624DashIP(t *testing.T) {
	// Windows reports "-" for local logons.
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName": "localuser",
		"LogonType":      "2",
		"IpAddress":      "-",
	})

	event := MapWinEventToECS(w)
	if event.Source != nil {
		t.Error("source should be nil when IpAddress is '-'")
	}
}

// ============================================================================
// 4625 — Failed Logon
// ============================================================================

func TestMapper4625(t *testing.T) {
	w := makeWinEvent(4625, "Security", "DC01", map[string]string{
		"TargetUserName":   "jsmith",
		"TargetDomainName": "CORP",
		"LogonType":        "10",
		"IpAddress":        "10.0.0.99",
		"Status":           "0xC000006D",
		"SubStatus":        "0xC000006A",
	})

	event := MapWinEventToECS(w)

	assertECSCategory(t, event, "authentication")
	if event.Event.Action != "logon-failed-remoteinteractive" {
		t.Errorf("action = %q, want %q", event.Event.Action, "logon-failed-remoteinteractive")
	}
	if event.Event.Outcome != "failure" {
		t.Errorf("outcome = %q, want %q", event.Event.Outcome, "failure")
	}
}

// ============================================================================
// 4688 — Process Creation
// ============================================================================

func TestMapper4688(t *testing.T) {
	w := makeWinEvent(4688, "Security", "WS01", map[string]string{
		"NewProcessId":     "0x1a2b",
		"NewProcessName":   `C:\Windows\System32\cmd.exe`,
		"CommandLine":      "cmd.exe /c whoami",
		"ParentProcessName": `C:\Windows\explorer.exe`,
		"SubjectUserName":  "jsmith",
		"SubjectDomainName": "CORP",
		"SubjectUserSid":   "S-1-5-21-1234",
	})

	event := MapWinEventToECS(w)

	assertECSCategory(t, event, "process")
	assertECSType(t, event, "start")
	if event.Process.PID != 0x1a2b {
		t.Errorf("process.pid = %d, want %d", event.Process.PID, 0x1a2b)
	}
	if event.Process.Executable != `C:\Windows\System32\cmd.exe` {
		t.Errorf("process.executable = %q", event.Process.Executable)
	}
	if event.Process.Name != "cmd.exe" {
		t.Errorf("process.name = %q, want %q", event.Process.Name, "cmd.exe")
	}
	if event.Process.CommandLine != "cmd.exe /c whoami" {
		t.Errorf("process.command_line = %q", event.Process.CommandLine)
	}
	if event.Process.Parent == nil {
		t.Fatal("process.parent is nil")
	}
	if event.Process.Parent.Executable != `C:\Windows\explorer.exe` {
		t.Errorf("process.parent.executable = %q", event.Process.Parent.Executable)
	}
	if event.Process.Parent.Name != "explorer.exe" {
		t.Errorf("process.parent.name = %q", event.Process.Parent.Name)
	}
	if event.User.Name != "jsmith" {
		t.Errorf("user.name = %q", event.User.Name)
	}
}

func TestMapper4688MissingCommandLine(t *testing.T) {
	w := makeWinEvent(4688, "Security", "WS01", map[string]string{
		"NewProcessId":   "0x100",
		"NewProcessName": `C:\test.exe`,
	})

	event := MapWinEventToECS(w)
	if event.Process.CommandLine != "" {
		t.Errorf("process.command_line = %q, want empty", event.Process.CommandLine)
	}
	if event.Process.Parent != nil {
		t.Error("process.parent should be nil when ParentProcessName is missing")
	}
}

// ============================================================================
// 4768 — Kerberos TGT
// ============================================================================

func TestMapper4768Success(t *testing.T) {
	w := makeWinEvent(4768, "Security", "DC01", map[string]string{
		"TargetUserName":   "jsmith",
		"TargetDomainName": "CORP.LOCAL",
		"IpAddress":        "::ffff:192.168.1.50",
		"Status":           "0x0",
	})

	event := MapWinEventToECS(w)

	assertECSCategory(t, event, "authentication")
	if event.Event.Action != "kerberos-tgt-request" {
		t.Errorf("action = %q", event.Event.Action)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("outcome = %q, want %q", event.Event.Outcome, "success")
	}
	// Should strip ::ffff: prefix.
	if event.Source == nil || event.Source.IP != "192.168.1.50" {
		t.Errorf("source.ip = %v, want 192.168.1.50", event.Source)
	}
}

func TestMapper4768Failure(t *testing.T) {
	w := makeWinEvent(4768, "Security", "DC01", map[string]string{
		"TargetUserName": "baduser",
		"Status":         "0x6",
	})

	event := MapWinEventToECS(w)
	if event.Event.Outcome != "failure" {
		t.Errorf("outcome = %q, want %q", event.Event.Outcome, "failure")
	}
}

func TestMapper4768UnknownStatus(t *testing.T) {
	w := makeWinEvent(4768, "Security", "DC01", map[string]string{
		"TargetUserName": "user",
		"Status":         "0xDEADBEEF",
	})

	event := MapWinEventToECS(w)
	if event.Event.Outcome != "failure" {
		t.Errorf("outcome = %q, want %q for non-zero status", event.Event.Outcome, "failure")
	}
}

func TestMapper4768EmptyStatus(t *testing.T) {
	w := makeWinEvent(4768, "Security", "DC01", map[string]string{
		"TargetUserName": "user",
	})

	event := MapWinEventToECS(w)
	if event.Event.Outcome != "unknown" {
		t.Errorf("outcome = %q, want %q for missing status", event.Event.Outcome, "unknown")
	}
}

// ============================================================================
// 4769 — Kerberos Service Ticket
// ============================================================================

func TestMapper4769(t *testing.T) {
	w := makeWinEvent(4769, "Security", "DC01", map[string]string{
		"TargetUserName": "jsmith@CORP.LOCAL",
		"ServiceName":    "krbtgt/CORP.LOCAL",
		"IpAddress":      "192.168.1.50",
		"Status":         "0x0",
	})

	event := MapWinEventToECS(w)

	if event.Event.Action != "kerberos-service-ticket" {
		t.Errorf("action = %q", event.Event.Action)
	}
	if event.Destination == nil || event.Destination.Domain != "krbtgt/CORP.LOCAL" {
		t.Errorf("destination.domain = %v", event.Destination)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("outcome = %q", event.Event.Outcome)
	}
}

// ============================================================================
// 7045 — Service Install
// ============================================================================

func TestMapper7045(t *testing.T) {
	w := makeWinEvent(7045, "System", "SERVER01", map[string]string{
		"ServiceName": "EvilService",
		"ImagePath":   `C:\temp\evil.exe`,
		"ServiceType": "user mode service",
		"StartType":   "auto start",
	})

	event := MapWinEventToECS(w)

	assertECSCategory(t, event, "configuration")
	assertECSType(t, event, "creation")
	if event.Event.Action != "service-install" {
		t.Errorf("action = %q", event.Event.Action)
	}
	if event.Process.Executable != `C:\temp\evil.exe` {
		t.Errorf("process.executable = %q", event.Process.Executable)
	}
	if event.Process.Name != "EvilService" {
		t.Errorf("process.name = %q, want %q", event.Process.Name, "EvilService")
	}
}

func TestMapper7045EmptyImagePath(t *testing.T) {
	w := makeWinEvent(7045, "System", "SERVER01", map[string]string{
		"ServiceName": "WeirdService",
	})

	event := MapWinEventToECS(w)
	if event.Process.Executable != "" {
		t.Errorf("process.executable = %q, want empty", event.Process.Executable)
	}
}

// ============================================================================
// Sysmon 1 — Process Create
// ============================================================================

func TestMapperSysmon1(t *testing.T) {
	w := makeSysmonEvent(1, map[string]string{
		"ProcessId":          "5678",
		"Image":              `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine":        "powershell.exe -nop -enc SQBFAFgA",
		"ParentProcessId":    "1234",
		"ParentImage":        `C:\Windows\System32\cmd.exe`,
		"ParentCommandLine":  "cmd.exe",
		"Hashes":             "SHA256=e3b0c44298fc1c149afbf4c8996fb924,MD5=d41d8cd98f00b204e9800998ecf8427e",
		"User":               `CORP\jsmith`,
		"IntegrityLevel":     "High",
	})

	event := MapWinEventToECSWithSysmon(w)

	assertECSCategory(t, event, "process")
	assertECSType(t, event, "start")
	if event.Process.PID != 5678 {
		t.Errorf("process.pid = %d, want 5678", event.Process.PID)
	}
	if event.Process.Name != "powershell.exe" {
		t.Errorf("process.name = %q", event.Process.Name)
	}
	if event.Process.Parent == nil {
		t.Fatal("process.parent is nil")
	}
	if event.Process.Parent.PID != 1234 {
		t.Errorf("process.parent.pid = %d, want 1234", event.Process.Parent.PID)
	}
	if event.Process.Parent.Name != "cmd.exe" {
		t.Errorf("process.parent.name = %q", event.Process.Parent.Name)
	}
	if event.Process.Parent.CommandLine != "cmd.exe" {
		t.Errorf("process.parent.command_line = %q", event.Process.Parent.CommandLine)
	}

	// Hashes.
	if event.File == nil || event.File.Hash == nil {
		t.Fatal("file.hash is nil")
	}
	if event.File.Hash.SHA256 != "e3b0c44298fc1c149afbf4c8996fb924" {
		t.Errorf("file.hash.sha256 = %q", event.File.Hash.SHA256)
	}
	if event.File.Hash.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("file.hash.md5 = %q", event.File.Hash.MD5)
	}

	// User.
	if event.User == nil {
		t.Fatal("user is nil")
	}
	if event.User.Name != "jsmith" {
		t.Errorf("user.name = %q", event.User.Name)
	}
	if event.User.Domain != "CORP" {
		t.Errorf("user.domain = %q", event.User.Domain)
	}
}

// ============================================================================
// Sysmon 3 — Network Connect
// ============================================================================

func TestMapperSysmon3(t *testing.T) {
	w := makeSysmonEvent(3, map[string]string{
		"ProcessId":       "4567",
		"Image":           `C:\Windows\System32\svchost.exe`,
		"Protocol":        "tcp",
		"Initiated":       "true",
		"SourceIp":        "192.168.1.100",
		"SourcePort":      "54321",
		"DestinationIp":   "10.0.0.50",
		"DestinationPort": "443",
		"User":            `NT AUTHORITY\SYSTEM`,
	})

	event := MapWinEventToECSWithSysmon(w)

	assertECSCategory(t, event, "network")
	assertECSType(t, event, "connection")
	if event.Source.IP != "192.168.1.100" {
		t.Errorf("source.ip = %q", event.Source.IP)
	}
	if event.Source.Port != 54321 {
		t.Errorf("source.port = %d", event.Source.Port)
	}
	if event.Destination.IP != "10.0.0.50" {
		t.Errorf("destination.ip = %q", event.Destination.IP)
	}
	if event.Destination.Port != 443 {
		t.Errorf("destination.port = %d", event.Destination.Port)
	}
	if event.Network.Protocol != "tcp" {
		t.Errorf("network.protocol = %q", event.Network.Protocol)
	}
	if event.Network.Direction != "outbound" {
		t.Errorf("network.direction = %q, want %q", event.Network.Direction, "outbound")
	}
	if event.Process.Name != "svchost.exe" {
		t.Errorf("process.name = %q", event.Process.Name)
	}
}

func TestMapperSysmon3Inbound(t *testing.T) {
	w := makeSysmonEvent(3, map[string]string{
		"Initiated":       "false",
		"SourceIp":        "10.0.0.50",
		"DestinationIp":   "192.168.1.100",
		"DestinationPort": "80",
	})

	event := MapWinEventToECSWithSysmon(w)
	if event.Network.Direction != "inbound" {
		t.Errorf("network.direction = %q, want %q", event.Network.Direction, "inbound")
	}
}

// ============================================================================
// Sysmon 11 — File Create
// ============================================================================

func TestMapperSysmon11(t *testing.T) {
	w := makeSysmonEvent(11, map[string]string{
		"ProcessId":      "1234",
		"Image":          `C:\Windows\explorer.exe`,
		"TargetFilename": `C:\Users\jsmith\Downloads\payload.exe`,
		"User":           `CORP\jsmith`,
	})

	event := MapWinEventToECSWithSysmon(w)

	assertECSCategory(t, event, "file")
	assertECSType(t, event, "creation")
	if event.File.Path != `C:\Users\jsmith\Downloads\payload.exe` {
		t.Errorf("file.path = %q", event.File.Path)
	}
	if event.File.Name != "payload.exe" {
		t.Errorf("file.name = %q", event.File.Name)
	}
	if event.Process.Name != "explorer.exe" {
		t.Errorf("process.name = %q", event.Process.Name)
	}
}

// ============================================================================
// Default mapper
// ============================================================================

func TestMapperDefault(t *testing.T) {
	w := makeWinEvent(9999, "Application", "MYPC", map[string]string{
		"SomeField": "somevalue",
	})

	event := MapWinEventToECS(w)

	if event.Event.Action != "winevt-9999" {
		t.Errorf("action = %q, want %q", event.Event.Action, "winevt-9999")
	}
	if event.Host.Name != "MYPC" {
		t.Errorf("host.name = %q", event.Host.Name)
	}
	assertECSCategory(t, event, "event")
	assertECSType(t, event, "info")
}

func TestMapperEventID0(t *testing.T) {
	w := makeWinEvent(0, "Application", "MYPC", nil)

	event := MapWinEventToECS(w)
	if event.Event.Action != "winevt-0" {
		t.Errorf("action = %q, want %q", event.Event.Action, "winevt-0")
	}
}

// ============================================================================
// Adversarial: nil/empty inputs
// ============================================================================

func TestMapperNilWinEvent(t *testing.T) {
	event := MapWinEventToECS(nil)
	if event == nil {
		t.Fatal("expected non-nil event for nil WinEvent")
	}
	if event.Event.Kind != "event" {
		t.Errorf("event.kind = %q", event.Event.Kind)
	}
}

func TestMapperNilEventData(t *testing.T) {
	w := &WinEvent{
		EventID:     4624,
		TimeCreated: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Channel:     "Security",
		Computer:    "DC01",
		EventData:   nil,
	}

	// Should not panic.
	event := MapWinEventToECS(w)
	if event.User.Name != "" {
		t.Errorf("user.name = %q, want empty for nil EventData", event.User.Name)
	}
}

func TestMapperEmptyEventData(t *testing.T) {
	w := makeWinEvent(4688, "Security", "WS01", map[string]string{})

	event := MapWinEventToECS(w)
	// Should produce valid event with empty fields, no panic.
	if event.Process == nil {
		t.Fatal("process should not be nil")
	}
	if event.Process.PID != 0 {
		t.Errorf("process.pid = %d, want 0", event.Process.PID)
	}
}

// ============================================================================
// Adversarial: hash parsing
// ============================================================================

func TestParseSysmonHashes(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		sha256 string
		md5    string
		sha1   string
		isNil  bool
	}{
		{"normal", "SHA256=abc123,MD5=def456", "abc123", "def456", "", false},
		{"all_three", "SHA256=aaa,MD5=bbb,SHA1=ccc", "aaa", "bbb", "ccc", false},
		{"sha256_only", "SHA256=abc123", "abc123", "", "", false},
		{"empty", "", "", "", "", true},
		{"no_equals", "garbage", "", "", "", true},
		{"equals_only", "SHA256=", "", "", "", true},
		{"equals_no_algo", "=value", "", "", "", true},
		{"unknown_algo", "IMPHASH=abc123", "", "", "", true},
		{"mixed_known_unknown", "SHA256=abc,IMPHASH=def,MD5=ghi", "abc", "ghi", "", false},
		{"whitespace", " SHA256=abc , MD5=def ", "abc", "def", "", false},
		{"lowercase", "sha256=abc,md5=def", "abc", "def", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := parseSysmonHashes(tc.input)
			if tc.isNil {
				if h != nil {
					t.Errorf("expected nil, got %+v", h)
				}
				return
			}
			if h == nil {
				t.Fatal("expected non-nil HashFields")
			}
			if h.SHA256 != tc.sha256 {
				t.Errorf("sha256 = %q, want %q", h.SHA256, tc.sha256)
			}
			if h.MD5 != tc.md5 {
				t.Errorf("md5 = %q, want %q", h.MD5, tc.md5)
			}
			if h.SHA1 != tc.sha1 {
				t.Errorf("sha1 = %q, want %q", h.SHA1, tc.sha1)
			}
		})
	}
}

// ============================================================================
// Adversarial: domain\user parsing
// ============================================================================

func TestParseDomainUser(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		user   string
		domain string
	}{
		{"backslash", `CORP\jsmith`, "jsmith", "CORP"},
		{"at_sign", "jsmith@CORP.LOCAL", "jsmith", "CORP.LOCAL"},
		{"no_domain", "localuser", "localuser", ""},
		{"nt_authority", `NT AUTHORITY\SYSTEM`, "SYSTEM", "NT AUTHORITY"},
		{"empty", "", "", ""},
		{"only_backslash", `\user`, "user", ""},
		{"only_at", "@domain", "", "domain"},
		{"double_backslash", `A\B\C`, "B\\C", "A"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := parseDomainUser(tc.input)
			if u.Name != tc.user {
				t.Errorf("name = %q, want %q", u.Name, tc.user)
			}
			if u.Domain != tc.domain {
				t.Errorf("domain = %q, want %q", u.Domain, tc.domain)
			}
		})
	}
}

// ============================================================================
// Adversarial: logon type mapping
// ============================================================================

func TestLogonTypeToString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"2", "interactive"},
		{"3", "network"},
		{"4", "batch"},
		{"5", "service"},
		{"7", "unlock"},
		{"8", "networkcleartext"},
		{"9", "newcredentials"},
		{"10", "remoteinteractive"},
		{"11", "cachedinteractive"},
		{"0", "type0"},
		{"99", "type99"},
		{"", "unknown"},
		{"abc", "unknown"},
		{" 10 ", "remoteinteractive"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := logonTypeToString(tc.input)
			if got != tc.want {
				t.Errorf("logonTypeToString(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Adversarial: Kerberos status
// ============================================================================

func TestKerberosStatusToOutcome(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"0x0", "success"},
		{"0x00000000", "success"},
		{"0x6", "failure"},
		{"0xC000006D", "failure"},
		{"0xDEADBEEF", "failure"},
		{"", "unknown"},
		{"  0x0  ", "success"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := kerberosStatusToOutcome(tc.input)
			if got != tc.want {
				t.Errorf("kerberosStatusToOutcome(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Adversarial: Sysmon 3 with bad port strings
// ============================================================================

func TestMapperSysmon3BadPorts(t *testing.T) {
	w := makeSysmonEvent(3, map[string]string{
		"SourcePort":      "not_a_port",
		"DestinationPort": "",
		"SourceIp":        "1.2.3.4",
		"DestinationIp":   "5.6.7.8",
	})

	event := MapWinEventToECSWithSysmon(w)
	// Should not panic; ports default to 0.
	if event.Source.Port != 0 {
		t.Errorf("source.port = %d, want 0", event.Source.Port)
	}
	if event.Destination.Port != 0 {
		t.Errorf("destination.port = %d, want 0", event.Destination.Port)
	}
}

// ============================================================================
// Sysmon EventID collision: Security EventID 1 vs Sysmon EventID 1
// ============================================================================

func TestSysmonVsSecurityEventIDCollision(t *testing.T) {
	// Security EventID 1 — should NOT use Sysmon mapper.
	securityEvent := makeWinEvent(1, "Security", "DC01", map[string]string{
		"SomeField": "value",
	})
	securityEvent.Provider = "Microsoft-Windows-Security-Auditing"

	ecsFromSecurity := MapWinEventToECSWithSysmon(securityEvent)

	// Sysmon EventID 1 — should use Sysmon mapper.
	sysmonEvent := makeSysmonEvent(1, map[string]string{
		"Image":       `C:\test.exe`,
		"CommandLine": "test.exe",
		"ProcessId":   "100",
	})

	ecsFromSysmon := MapWinEventToECSWithSysmon(sysmonEvent)

	// Security event should be default mapped (no process fields from Sysmon).
	if ecsFromSecurity.Event.Action != "winevt-1" {
		t.Errorf("Security EventID 1: action = %q, want %q", ecsFromSecurity.Event.Action, "winevt-1")
	}

	// Sysmon event should have process fields.
	if ecsFromSysmon.Event.Action != "process-created" {
		t.Errorf("Sysmon EventID 1: action = %q, want %q", ecsFromSysmon.Event.Action, "process-created")
	}
	if ecsFromSysmon.Process.Executable != `C:\test.exe` {
		t.Errorf("Sysmon EventID 1: process.executable = %q", ecsFromSysmon.Process.Executable)
	}
}

// ============================================================================
// Parser integration: JSON → ECS round-trip
// ============================================================================

func TestWinEvtJSONParserIntegration(t *testing.T) {
	parser := NewWinEvtJSONParser()

	if parser.SourceType() != "winevt_json" {
		t.Errorf("source_type = %q", parser.SourceType())
	}

	raw := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:00:00Z",
		"winlog": {
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"event_id": 4688,
			"channel": "Security",
			"computer_name": "WORKSTATION-01",
			"event_data": {
				"NewProcessId": "0x100",
				"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c whoami",
				"ParentProcessName": "C:\\Windows\\explorer.exe",
				"SubjectUserName": "jsmith"
			}
		}
	}`)

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	assertECSCategory(t, event, "process")
	if event.Process.Name != "cmd.exe" {
		t.Errorf("process.name = %q", event.Process.Name)
	}
	if event.Host.Name != "WORKSTATION-01" {
		t.Errorf("host.name = %q", event.Host.Name)
	}
}

// ============================================================================
// Parser integration: XML → ECS round-trip
// ============================================================================

func TestWinEvtXMLParserIntegration(t *testing.T) {
	parser := NewWinEvtXMLParser()

	if parser.SourceType() != "winevt_xml" {
		t.Errorf("source_type = %q", parser.SourceType())
	}

	xmlContent := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
    <Channel>Security</Channel>
    <Computer>DC01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
  </EventData>
</Event>`

	// Wrap XML in JSON envelope.
	envelope := map[string]string{
		"source_type": "winevt_xml",
		"xml":         xmlContent,
	}
	raw, _ := json.Marshal(envelope)

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	assertECSCategory(t, event, "authentication")
	if event.Event.Action != "logon-network" {
		t.Errorf("action = %q", event.Event.Action)
	}
	if event.User.Name != "admin" {
		t.Errorf("user.name = %q", event.User.Name)
	}
	if event.Host.Name != "DC01" {
		t.Errorf("host.name = %q", event.Host.Name)
	}
}

// ============================================================================
// JSON and XML produce same ECS output
// ============================================================================

func TestXMLAndJSONProduceSameECS(t *testing.T) {
	xmlContent := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
    <Channel>Security</Channel>
    <Computer>WS01</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x100</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">CORP</Data>
  </EventData>
</Event>`

	xmlEnvelope, _ := json.Marshal(map[string]string{
		"source_type": "winevt_xml",
		"xml":         xmlContent,
	})

	jsonData := json.RawMessage(`{
		"@timestamp": "2026-03-14T12:00:00Z",
		"winlog": {
			"provider_name": "Microsoft-Windows-Security-Auditing",
			"event_id": 4688,
			"channel": "Security",
			"computer_name": "WS01",
			"event_data": {
				"NewProcessId": "0x100",
				"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
				"CommandLine": "cmd.exe /c whoami",
				"ParentProcessName": "C:\\Windows\\explorer.exe",
				"SubjectUserName": "jsmith",
				"SubjectDomainName": "CORP"
			}
		}
	}`)

	xmlParser := NewWinEvtXMLParser()
	jsonParser := NewWinEvtJSONParser()

	xmlEvent, err := xmlParser.Parse(xmlEnvelope)
	if err != nil {
		t.Fatalf("XML parse error: %v", err)
	}

	jsonEvent, err := jsonParser.Parse(jsonData)
	if err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Compare key ECS fields.
	if xmlEvent.Event.Action != jsonEvent.Event.Action {
		t.Errorf("action: XML=%q, JSON=%q", xmlEvent.Event.Action, jsonEvent.Event.Action)
	}
	if xmlEvent.Process.Name != jsonEvent.Process.Name {
		t.Errorf("process.name: XML=%q, JSON=%q", xmlEvent.Process.Name, jsonEvent.Process.Name)
	}
	if xmlEvent.Process.CommandLine != jsonEvent.Process.CommandLine {
		t.Errorf("process.command_line: XML=%q, JSON=%q", xmlEvent.Process.CommandLine, jsonEvent.Process.CommandLine)
	}
	if xmlEvent.Process.PID != jsonEvent.Process.PID {
		t.Errorf("process.pid: XML=%d, JSON=%d", xmlEvent.Process.PID, jsonEvent.Process.PID)
	}
	if xmlEvent.Host.Name != jsonEvent.Host.Name {
		t.Errorf("host.name: XML=%q, JSON=%q", xmlEvent.Host.Name, jsonEvent.Host.Name)
	}
	if xmlEvent.User.Name != jsonEvent.User.Name {
		t.Errorf("user.name: XML=%q, JSON=%q", xmlEvent.User.Name, jsonEvent.User.Name)
	}
	if xmlEvent.Process.Parent.Name != jsonEvent.Process.Parent.Name {
		t.Errorf("process.parent.name: XML=%q, JSON=%q", xmlEvent.Process.Parent.Name, jsonEvent.Process.Parent.Name)
	}
}

// ============================================================================
// Adversarial: unknown Sysmon EventID
// ============================================================================

func TestMapperUnknownSysmonEventID(t *testing.T) {
	w := makeSysmonEvent(255, map[string]string{"SomeField": "value"})

	event := MapWinEventToECSWithSysmon(w)
	if event.Event.Action != "winevt-255" {
		t.Errorf("action = %q, want %q", event.Event.Action, "winevt-255")
	}
}

// ============================================================================
// Timestamp propagation
// ============================================================================

func TestMapperTimestampPropagation(t *testing.T) {
	expected := time.Date(2026, 3, 14, 12, 30, 45, 0, time.UTC)
	w := makeWinEvent(4624, "Security", "DC01", map[string]string{
		"TargetUserName": "admin",
		"LogonType":      "3",
	})
	w.TimeCreated = expected

	event := MapWinEventToECS(w)
	if !event.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", event.Timestamp, expected)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func assertECSCategory(t *testing.T, event *common.ECSEvent, want string) {
	t.Helper()
	if event.Event == nil {
		t.Fatal("event.Event is nil")
	}
	found := false
	for _, cat := range event.Event.Category {
		if cat == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("event.category = %v, want to contain %q", event.Event.Category, want)
	}
}

func assertECSType(t *testing.T, event *common.ECSEvent, want string) {
	t.Helper()
	if event.Event == nil {
		t.Fatal("event.Event is nil")
	}
	found := false
	for _, typ := range event.Event.Type {
		if typ == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("event.type = %v, want to contain %q", event.Event.Type, want)
	}
}
