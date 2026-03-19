package parsers

import (
	"encoding/json"
	"testing"
)

// helper to build a full SIEM-envelope-wrapped EDR event.
func makeEDREvent(source, severity string, payload map[string]any) json.RawMessage {
	inner := map[string]any{
		"eventId":   "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2026-03-14T12:00:00Z",
		"source":    source,
		"severity":  severity,
		"process": map[string]any{
			"pid":             1234,
			"parentPid":       5678,
			"threadId":        100,
			"sessionId":       1,
			"imagePath":       `C:\Windows\System32\cmd.exe`,
			"commandLine":     `cmd.exe /c whoami`,
			"userSid":         "S-1-5-21-123456789-1001",
			"integrityLevel":  8192,
			"isElevated":      false,
			"parentImagePath": `C:\Windows\explorer.exe`,
		},
		"payload": payload,
	}

	envelope := map[string]any{
		"schema":      "akeso/v1",
		"source_type": "akeso_edr",
		"host":        "WORKSTATION-01",
		"agent_id":    "agent-abc-123",
		"timestamp":   "2026-03-14T12:00:00Z",
		"event":       inner,
	}

	data, _ := json.Marshal(envelope)
	return data
}

func TestSourceType(t *testing.T) {
	p := Newakeso_edrParser()
	if got := p.SourceType(); got != "akeso_edr" {
		t.Fatalf("SourceType() = %q, want %q", got, "akeso_edr")
	}
}

func TestCommonFields(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverProcess", "Medium", map[string]any{
		"isCreate":        true,
		"newProcessId":    9999,
		"parentProcessId": 5678,
		"imagePath":       `C:\Windows\notepad.exe`,
		"commandLine":     "notepad.exe test.txt",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Timestamp
	if ecs.Timestamp.IsZero() {
		t.Error("@timestamp is zero")
	}
	if ecs.Timestamp.Year() != 2026 {
		t.Errorf("@timestamp year = %d, want 2026", ecs.Timestamp.Year())
	}

	// Host
	if ecs.Host == nil || ecs.Host.Name != "WORKSTATION-01" {
		t.Errorf("host.name = %v, want WORKSTATION-01", ecs.Host)
	}

	// User
	if ecs.User == nil || ecs.User.ID != "S-1-5-21-123456789-1001" {
		t.Errorf("user.id = %v, want S-1-5-21-123456789-1001", ecs.User)
	}

	// Severity
	if ecs.Event.Severity != 50 {
		t.Errorf("event.severity = %d, want 50 (Medium)", ecs.Event.Severity)
	}
}

func TestProcessCreate(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverProcess", "Low", map[string]any{
		"isCreate":        true,
		"newProcessId":    9999,
		"parentProcessId": 5678,
		"imagePath":       `C:\Windows\notepad.exe`,
		"commandLine":     "notepad.exe test.txt",
		"integrityLevel":  8192,
		"isElevated":      false,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"start"})
	assertEqual(t, "event.action", ecs.Event.Action, "process_created")
	assertEqual(t, "process.pid", ecs.Process.PID, 9999)
	assertEqual(t, "process.executable", ecs.Process.Executable, `C:\Windows\notepad.exe`)
	assertEqual(t, "process.name", ecs.Process.Name, "notepad.exe")
	assertEqual(t, "process.command_line", ecs.Process.CommandLine, "notepad.exe test.txt")
	assertEqual(t, "process.parent.pid", ecs.Process.Parent.PID, 5678)
}

func TestProcessTerminate(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverProcess", "Informational", map[string]any{
		"isCreate":   false,
		"exitStatus": "0x00000000",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"end"})
	assertEqual(t, "event.action", ecs.Event.Action, "process_terminated")
	assertEqual(t, "event.severity", ecs.Event.Severity, 0)
}

func TestThreadRemote(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverThread", "High", map[string]any{
		"isCreate":          true,
		"threadId":          200,
		"owningProcessId":   1234,
		"creatingProcessId": 5678,
		"startAddress":      "0x7FFE12340000",
		"isRemote":          true,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"start"})
	assertEqual(t, "event.action", ecs.Event.Action, "remote_thread_created")
	assertEqual(t, "event.severity", ecs.Event.Severity, 75)
}

func TestThreadLocal(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverThread", "Informational", map[string]any{
		"isCreate":          true,
		"threadId":          200,
		"owningProcessId":   1234,
		"creatingProcessId": 1234,
		"startAddress":      "0x7FFE12340000",
		"isRemote":          false,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "event.action", ecs.Event.Action, "thread_created")
}

func TestObjectHandle(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverObject", "High", map[string]any{
		"operation":       "Create",
		"objectType":      "Process",
		"sourceProcessId": 1234,
		"targetProcessId": 696,
		"targetImagePath": `C:\Windows\System32\lsass.exe`,
		"desiredAccess":   "0x1FFFFF",
		"grantedAccess":   "0x1FFFFF",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"access"})
	assertEqual(t, "event.action", ecs.Event.Action, "object_handle_create")
}

func TestImageLoad(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverImageLoad", "Informational", map[string]any{
		"processId":        1234,
		"imagePath":        `C:\Windows\System32\ntdll.dll`,
		"imageBase":        "0x7FFE00000000",
		"imageSize":        "0x1A0000",
		"isKernelImage":    false,
		"isSigned":         true,
		"isSignatureValid": true,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"info"})
	assertEqual(t, "event.action", ecs.Event.Action, "image_loaded")
	if ecs.File == nil {
		t.Fatal("file is nil")
	}
	assertEqual(t, "file.path", ecs.File.Path, `C:\Windows\System32\ntdll.dll`)
	assertEqual(t, "file.name", ecs.File.Name, "ntdll.dll")
}

func TestRegistrySetValue(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverRegistry", "Medium", map[string]any{
		"operation": "SetValue",
		"keyPath":   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"valueName": "Malware",
		"dataType":  1,
		"dataSize":  100,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"registry"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"change"})
	assertEqual(t, "event.action", ecs.Event.Action, "registry_setvalue")
	if ecs.Registry == nil {
		t.Fatal("registry is nil")
	}
	assertEqual(t, "registry.key", ecs.Registry.Key, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
	assertEqual(t, "registry.value", ecs.Registry.Value, "Malware")
}

func TestRegistryCreateKey(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverRegistry", "Low", map[string]any{
		"operation": "CreateKey",
		"keyPath":   `HKLM\SOFTWARE\TestKey`,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"creation"})
}

func TestRegistryDeleteKey(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverRegistry", "Low", map[string]any{
		"operation": "DeleteKey",
		"keyPath":   `HKLM\SOFTWARE\TestKey`,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"deletion"})
}

func TestFileCreate(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverMinifilter", "Medium", map[string]any{
		"operation": "Create",
		"processId": 1234,
		"filePath":  `C:\Users\user\Downloads\malware.exe`,
		"fileSize":  102400,
		"sha256":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"file"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"creation"})
	assertEqual(t, "event.action", ecs.Event.Action, "file_create")
	if ecs.File == nil {
		t.Fatal("file is nil")
	}
	assertEqual(t, "file.path", ecs.File.Path, `C:\Users\user\Downloads\malware.exe`)
	assertEqual(t, "file.name", ecs.File.Name, "malware.exe")
	assertEqual(t, "file.size", ecs.File.Size, int64(102400))
	if ecs.File.Hash == nil {
		t.Fatal("file.hash is nil")
	}
	assertEqual(t, "file.hash.sha256", ecs.File.Hash.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}

func TestFileNoHash(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverMinifilter", "Informational", map[string]any{
		"operation":   "Write",
		"processId":   1234,
		"filePath":    `C:\Temp\bigfile.iso`,
		"fileSize":    5368709120,
		"hashSkipped": true,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if ecs.File.Hash != nil {
		t.Error("file.hash should be nil when hash skipped")
	}
}

func TestNamedPipe(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverPipe", "High", map[string]any{
		"pipeName":          `\Device\NamedPipe\msagent_47`,
		"creatingProcessId": 1234,
		"accessMode":        "0x03",
		"isSuspicious":      true,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"file"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"creation"})
	assertEqual(t, "event.action", ecs.Event.Action, "named_pipe_created")
	if ecs.File == nil {
		t.Fatal("file is nil")
	}
	assertEqual(t, "file.name", ecs.File.Name, `\Device\NamedPipe\msagent_47`)
}

func TestNetworkOutbound(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverNetwork", "Medium", map[string]any{
		"direction":  "Outbound",
		"processId":  1234,
		"protocol":   6,
		"localAddr":  "192.168.1.100",
		"localPort":  49152,
		"remoteAddr": "10.0.0.1",
		"remotePort": 443,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"network"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"connection"})
	assertEqual(t, "event.action", ecs.Event.Action, "network_outbound")
	if ecs.Source == nil {
		t.Fatal("source is nil")
	}
	assertEqual(t, "source.ip", ecs.Source.IP, "192.168.1.100")
	assertEqual(t, "source.port", ecs.Source.Port, 49152)
	if ecs.Destination == nil {
		t.Fatal("destination is nil")
	}
	assertEqual(t, "destination.ip", ecs.Destination.IP, "10.0.0.1")
	assertEqual(t, "destination.port", ecs.Destination.Port, 443)
	if ecs.Network == nil {
		t.Fatal("network is nil")
	}
	assertEqual(t, "network.protocol", ecs.Network.Protocol, "tcp")
	assertEqual(t, "network.direction", ecs.Network.Direction, "outbound")
}

func TestNetworkUDP(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverNetwork", "Informational", map[string]any{
		"direction":  "Outbound",
		"processId":  1234,
		"protocol":   17,
		"localAddr":  "192.168.1.100",
		"localPort":  12345,
		"remoteAddr": "8.8.8.8",
		"remotePort": 53,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "network.protocol", ecs.Network.Protocol, "udp")
}

func TestHookDll(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("HookDll", "Medium", map[string]any{
		"function":      "NtProtectVirtualMemory",
		"targetPid":     1234,
		"baseAddress":   "0x7FFE00000000",
		"regionSize":    "0x1000",
		"protection":    "0x20",
		"returnAddress": "0x7FFE12345678",
		"callingModule": `C:\Users\user\malware.exe`,
		"stackHash":     "0xABCDEF01",
		"returnStatus":  "0x00000000",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"change"})
	assertEqual(t, "event.action", ecs.Event.Action, "NtProtectVirtualMemory")
}

func TestETWDnsClient(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Etw", "Informational", map[string]any{
		"provider":    "DnsClient",
		"eventId":     3018,
		"level":       4,
		"processId":   1234,
		"threadId":    100,
		"queryName":   "evil-c2.example.com",
		"queryType":   1,
		"queryStatus": 0,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"network"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"protocol"})
	assertEqual(t, "event.action", ecs.Event.Action, "dns_query")
	assertEqual(t, "network.protocol", ecs.Network.Protocol, "dns")
	if ecs.Destination == nil {
		t.Fatal("destination is nil")
	}
	assertEqual(t, "destination.domain", ecs.Destination.Domain, "evil-c2.example.com")
}

func TestETWDotNET(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Etw", "Medium", map[string]any{
		"provider":     "DotNETRuntime",
		"eventId":      152,
		"level":        4,
		"processId":    1234,
		"assemblyName": "Seatbelt",
		"className":    "Seatbelt.Program",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"process"})
	assertEqual(t, "event.action", ecs.Event.Action, "dotnet_assembly_loaded")
}

func TestETWPowerShell(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Etw", "Medium", map[string]any{
		"provider":    "PowerShell",
		"eventId":     4104,
		"level":       5,
		"processId":   1234,
		"scriptBlock": "Invoke-Mimikatz",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "event.action", ecs.Event.Action, "powershell_script_block")
}

func TestETWKerberos(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Etw", "Medium", map[string]any{
		"provider":   "Kerberos",
		"eventId":    14,
		"processId":  1234,
		"targetName": "krbtgt/DOMAIN.COM",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"authentication"})
	assertEqual(t, "event.action", ecs.Event.Action, "kerberos_ticket_request")
}

func TestETWUnknownProvider(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Etw", "Informational", map[string]any{
		"provider":  "FutureProvider",
		"eventId":   1,
		"processId": 1234,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"host"})
	assertEqual(t, "event.action", ecs.Event.Action, "etw_futureprovider")
}

func TestAMSIMalware(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Amsi", "Critical", map[string]any{
		"appName":     "PowerShell",
		"contentSize": 4096,
		"scanResult":  "Malware",
		"matchedRule": "Invoke-Mimikatz",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"intrusion_detection"})
	assertEqual(t, "event.action", ecs.Event.Action, "amsi_scan")
	assertEqual(t, "event.outcome", ecs.Event.Outcome, "failure")
	assertEqual(t, "event.severity", ecs.Event.Severity, 100)
}

func TestAMSIClean(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Amsi", "Informational", map[string]any{
		"appName":     "PowerShell",
		"contentSize": 256,
		"scanResult":  "Clean",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "event.outcome", ecs.Event.Outcome, "success")
}

func TestScannerMatch(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Scanner", "High", map[string]any{
		"scanType":        "OnAccess",
		"targetPath":      `C:\Users\user\Downloads\malware.exe`,
		"targetProcessId": 0,
		"isMatch":         true,
		"yaraRule":        "CobaltStrike_Beacon",
		"sha256":          "abcdef0123456789",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"malware"})
	assertEqual(t, "event.action", ecs.Event.Action, "yara_scan_onaccess")
	assertEqual(t, "event.outcome", ecs.Event.Outcome, "failure")
	if ecs.File == nil {
		t.Fatal("file is nil")
	}
	assertEqual(t, "file.path", ecs.File.Path, `C:\Users\user\Downloads\malware.exe`)
	assertEqual(t, "file.hash.sha256", ecs.File.Hash.SHA256, "abcdef0123456789")
}

func TestScannerClean(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("Scanner", "Informational", map[string]any{
		"scanType":   "OnDemand",
		"targetPath": `C:\Windows\notepad.exe`,
		"isMatch":    false,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "event.outcome", ecs.Event.Outcome, "success")
}

func TestRuleEngineAlert(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("RuleEngine", "Critical", map[string]any{
		"ruleName":       "Credential Dumping via lsass Handle",
		"severity":       "Critical",
		"triggerSource":  "DriverObject",
		"triggerEventId": "550e8400-e29b-41d4-a716-446655440001",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertEqual(t, "event.kind", ecs.Event.Kind, "alert")
	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"intrusion_detection"})
	assertStringSlice(t, "event.type", ecs.Event.Type, []string{"indicator"})
	assertEqual(t, "event.action", ecs.Event.Action, "Credential Dumping via lsass Handle")
	assertEqual(t, "event.severity", ecs.Event.Severity, 100)
}

func TestSelfProtectTamper(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("SelfProtect", "Critical", map[string]any{
		"tamperType": "HookRemoved",
		"processId":  1234,
		"detail":     "NtProtectVirtualMemory hook overwritten",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"intrusion_detection"})
	assertEqual(t, "event.action", ecs.Event.Action, "tamper_hookremoved")
}

func TestUnknownSource(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("FutureSource", "Low", map[string]any{
		"someField": "someValue",
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() should not error on unknown source, got: %v", err)
	}

	// Common fields should still be populated.
	assertEqual(t, "event.kind", ecs.Event.Kind, "event")
	assertEqual(t, "host.name", ecs.Host.Name, "WORKSTATION-01")
	assertEqual(t, "process.pid", ecs.Process.PID, 1234)
	assertStringSlice(t, "event.category", ecs.Event.Category, []string{"host"})
	assertEqual(t, "event.action", ecs.Event.Action, "FutureSource")
}

func TestMissingOptionalFields(t *testing.T) {
	p := Newakeso_edrParser()
	// Minimal event — no parent image path, sparse payload.
	inner := map[string]any{
		"eventId":   "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2026-03-14T12:00:00Z",
		"source":    "DriverProcess",
		"severity":  "Low",
		"process": map[string]any{
			"pid":       1234,
			"imagePath": `C:\test.exe`,
		},
		"payload": map[string]any{
			"isCreate": true,
		},
	}

	envelope := map[string]any{
		"schema":      "akeso/v1",
		"source_type": "akeso_edr",
		"host":        "HOST-01",
		"timestamp":   "2026-03-14T12:00:00Z",
		"event":       inner,
	}

	data, _ := json.Marshal(envelope)
	ecs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Should not panic, common fields still populated.
	assertEqual(t, "host.name", ecs.Host.Name, "HOST-01")
	assertEqual(t, "process.pid", ecs.Process.PID, 1234)
	// User should be nil (no userSid).
	if ecs.User != nil {
		t.Error("user should be nil when userSid is empty")
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"Informational", 0},
		{"Low", 25},
		{"Medium", 50},
		{"High", 75},
		{"Critical", 100},
		{"Unknown", 0},
		{"", 0},
	}

	for _, tc := range cases {
		got := mapSeverity(tc.input)
		if got != tc.want {
			t.Errorf("mapSeverity(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestFileNameFromPath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`C:\Windows\System32\cmd.exe`, "cmd.exe"},
		{`/usr/bin/bash`, "bash"},
		{`notepad.exe`, "notepad.exe"},
		{"", ""},
		{`C:\Program Files\App\app.exe`, "app.exe"},
	}

	for _, tc := range cases {
		got := fileNameFromPath(tc.input)
		if got != tc.want {
			t.Errorf("fileNameFromPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRoundTripMarshalUnmarshal(t *testing.T) {
	p := Newakeso_edrParser()
	raw := makeEDREvent("DriverNetwork", "Medium", map[string]any{
		"direction":  "Outbound",
		"processId":  1234,
		"protocol":   6,
		"localAddr":  "192.168.1.100",
		"localPort":  49152,
		"remoteAddr": "10.0.0.1",
		"remotePort": 443,
	})

	ecs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Marshal to JSON and back.
	data, err := json.Marshal(ecs)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var roundTrip map[string]any
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	// Verify key fields survived round-trip.
	network, ok := roundTrip["network"].(map[string]any)
	if !ok {
		t.Fatal("network field missing after round-trip")
	}
	if network["protocol"] != "tcp" {
		t.Errorf("network.protocol after round-trip = %v, want tcp", network["protocol"])
	}
	if network["direction"] != "outbound" {
		t.Errorf("network.direction after round-trip = %v, want outbound", network["direction"])
	}
}

// --- Test helpers ---

func assertEqual[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}

func assertStringSlice(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", field, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", field, i, got[i], want[i])
		}
	}
}
