package parsers

import (
	"encoding/json"
	"testing"
)

func makeAVEvent(eventType string, payload map[string]any) json.RawMessage {
	event := map[string]any{
		"source_type": "akeso_av",
		"timestamp":   "2026-03-14T12:00:00Z",
		"hostname":    "WORKSTATION-01",
		"event_type":  eventType,
		"user": map[string]any{
			"sid":  "S-1-5-21-1234",
			"name": "jsmith",
		},
		"payload": payload,
	}
	data, _ := json.Marshal(event)
	return data
}

func TestAVSourceType(t *testing.T) {
	p := NewAkesoAVParser()
	if p.SourceType() != "akeso_av" {
		t.Errorf("SourceType() = %q, want %q", p.SourceType(), "akeso_av")
	}
}

func TestAVCommonFields(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path":  `C:\Users\jsmith\Downloads\test.exe`,
		"verdict":    "clean",
		"engine":     "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Timestamp
	if event.Timestamp.Year() != 2026 || event.Timestamp.Month() != 3 {
		t.Errorf("timestamp: got %v", event.Timestamp)
	}

	// Host
	if event.Host == nil || event.Host.Name != "WORKSTATION-01" {
		t.Error("expected host.name = WORKSTATION-01")
	}

	// User
	if event.User == nil || event.User.ID != "S-1-5-21-1234" {
		t.Error("expected user.id = S-1-5-21-1234")
	}
	if event.User.Name != "jsmith" {
		t.Error("expected user.name = jsmith")
	}
}

func TestAVScanResultMalicious(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path":      `C:\Users\jsmith\Downloads\malware.exe`,
		"file_size":      102400,
		"hash_md5":       "d41d8cd98f00b204e9800998ecf8427e",
		"hash_sha1":      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"hash_sha256":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"verdict":        "malicious",
		"signature_name": "Mimikatz_Binary",
		"engine":         "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Event metadata
	if event.Event.Category[0] != "malware" {
		t.Errorf("event.category = %v, want [malware]", event.Event.Category)
	}
	if event.Event.Type[0] != "info" {
		t.Errorf("event.type = %v, want [info]", event.Event.Type)
	}
	if event.Event.Action != "scan_result" {
		t.Errorf("event.action = %q, want scan_result", event.Event.Action)
	}
	if event.Event.Outcome != "failure" {
		t.Errorf("event.outcome = %q, want failure (malicious verdict)", event.Event.Outcome)
	}

	// File
	if event.File == nil {
		t.Fatal("expected file fields")
	}
	if event.File.Path != `C:\Users\jsmith\Downloads\malware.exe` {
		t.Errorf("file.path = %q", event.File.Path)
	}
	if event.File.Name != "malware.exe" {
		t.Errorf("file.name = %q, want malware.exe", event.File.Name)
	}
	if event.File.Size != 102400 {
		t.Errorf("file.size = %d, want 102400", event.File.Size)
	}

	// File hashes
	if event.File.Hash == nil {
		t.Fatal("expected file.hash fields")
	}
	if event.File.Hash.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("file.hash.md5 mismatch")
	}
	if event.File.Hash.SHA1 != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("file.hash.sha1 mismatch")
	}
	if event.File.Hash.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("file.hash.sha256 mismatch")
	}

	// AV fields
	if event.AV == nil {
		t.Fatal("expected av fields")
	}
	if event.AV.Scan == nil || event.AV.Scan.Result != "malicious" {
		t.Errorf("av.scan.result = %v, want malicious", event.AV.Scan)
	}
	if event.AV.Scan.Engine != "akeso-yara" {
		t.Errorf("av.scan.engine = %q, want akeso-yara", event.AV.Scan.Engine)
	}
	if event.AV.Signature == nil || event.AV.Signature.Name != "Mimikatz_Binary" {
		t.Errorf("av.signature.name = %v, want Mimikatz_Binary", event.AV.Signature)
	}
}

func TestAVScanResultClean(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path": `C:\Windows\System32\notepad.exe`,
		"verdict":   "clean",
		"engine":    "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Outcome != "success" {
		t.Errorf("event.outcome = %q, want success (clean verdict)", event.Event.Outcome)
	}
	if event.AV.Scan.Result != "clean" {
		t.Errorf("av.scan.result = %q, want clean", event.AV.Scan.Result)
	}
	if event.AV.Signature != nil {
		t.Error("expected no signature for clean scan")
	}
}

func TestAVScanResultSuspicious(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path":      `C:\temp\dropper.exe`,
		"verdict":        "suspicious",
		"signature_name": "Generic.Suspicious.Packer",
		"engine":         "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Outcome != "failure" {
		t.Errorf("event.outcome = %q, want failure (suspicious verdict)", event.Event.Outcome)
	}
	if event.AV.Scan.Result != "suspicious" {
		t.Errorf("av.scan.result = %q, want suspicious", event.AV.Scan.Result)
	}
}

func TestAVQuarantine(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:quarantine", map[string]any{
		"file_path":     `C:\ProgramData\Sentinel\Quarantine\abc123`,
		"original_path": `C:\Users\jsmith\Downloads\trojan.exe`,
		"hash_sha256":   "abcd1234567890",
		"file_size":     51200,
		"rule":          "Trojan.GenericDropper",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "malware" {
		t.Errorf("event.category = %v, want [malware]", event.Event.Category)
	}
	if event.Event.Type[0] != "deletion" {
		t.Errorf("event.type = %v, want [deletion]", event.Event.Type)
	}
	if event.Event.Action != "quarantine" {
		t.Errorf("event.action = %q, want quarantine", event.Event.Action)
	}

	// Should use original_path when available.
	if event.File.Path != `C:\Users\jsmith\Downloads\trojan.exe` {
		t.Errorf("file.path = %q, want original_path", event.File.Path)
	}
	if event.File.Name != "trojan.exe" {
		t.Errorf("file.name = %q, want trojan.exe", event.File.Name)
	}
	if event.File.Hash == nil || event.File.Hash.SHA256 != "abcd1234567890" {
		t.Error("expected file.hash.sha256")
	}

	if event.AV == nil || event.AV.Action != "quarantine" {
		t.Errorf("av.action = %v, want quarantine", event.AV)
	}
	if event.AV.Signature == nil || event.AV.Signature.Name != "Trojan.GenericDropper" {
		t.Error("expected av.signature.name = Trojan.GenericDropper")
	}
}

func TestAVQuarantineNoOriginalPath(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:quarantine", map[string]any{
		"file_path": `C:\ProgramData\Sentinel\Quarantine\abc123`,
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Falls back to file_path when original_path is missing.
	if event.File.Path != `C:\ProgramData\Sentinel\Quarantine\abc123` {
		t.Errorf("file.path = %q, want fallback to file_path", event.File.Path)
	}
}

func TestAVRealtimeBlock(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:realtime_block", map[string]any{
		"file_path":            `C:\Users\jsmith\Downloads\ransomware.exe`,
		"hash_sha256":          "deadbeef",
		"file_size":            204800,
		"process_pid":          4567,
		"process_executable":   `C:\Windows\explorer.exe`,
		"process_command_line": `explorer.exe /select,"ransomware.exe"`,
		"reason":               "on-access scan blocked execution",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "malware" {
		t.Errorf("event.category = %v, want [malware]", event.Event.Category)
	}
	if event.Event.Type[0] != "denied" {
		t.Errorf("event.type = %v, want [denied]", event.Event.Type)
	}
	if event.Event.Action != "realtime_block" {
		t.Errorf("event.action = %q, want realtime_block", event.Event.Action)
	}

	// Process fields (blocked process).
	if event.Process == nil {
		t.Fatal("expected process fields")
	}
	if event.Process.PID != 4567 {
		t.Errorf("process.pid = %d, want 4567", event.Process.PID)
	}
	if event.Process.Executable != `C:\Windows\explorer.exe` {
		t.Errorf("process.executable = %q", event.Process.Executable)
	}
	if event.Process.Name != "explorer.exe" {
		t.Errorf("process.name = %q, want explorer.exe", event.Process.Name)
	}

	// File fields.
	if event.File.Path != `C:\Users\jsmith\Downloads\ransomware.exe` {
		t.Errorf("file.path = %q", event.File.Path)
	}
	if event.File.Hash == nil || event.File.Hash.SHA256 != "deadbeef" {
		t.Error("expected file.hash.sha256")
	}

	// AV action.
	if event.AV == nil || event.AV.Action != "block" {
		t.Errorf("av.action = %v, want block", event.AV)
	}
}

func TestAVSignatureUpdate(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:signature_update", map[string]any{
		"version":         "2026.03.14.001",
		"signature_count": 50000,
		"engine":          "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "configuration" {
		t.Errorf("event.category = %v, want [configuration]", event.Event.Category)
	}
	if event.Event.Type[0] != "change" {
		t.Errorf("event.type = %v, want [change]", event.Event.Type)
	}
	if event.Event.Action != "signature_update" {
		t.Errorf("event.action = %q, want signature_update", event.Event.Action)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("event.outcome = %q, want success", event.Event.Outcome)
	}

	if event.AV == nil || event.AV.Scan == nil {
		t.Fatal("expected av.scan fields")
	}
	if event.AV.Scan.Engine != "akeso-yara" {
		t.Errorf("av.scan.engine = %q, want akeso-yara", event.AV.Scan.Engine)
	}
}

func TestAVScanError(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_error", map[string]any{
		"file_path": `C:\Users\jsmith\locked.docx`,
		"reason":    "file locked by another process",
		"engine":    "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "malware" {
		t.Errorf("event.category = %v, want [malware]", event.Event.Category)
	}
	if event.Event.Action != "scan_error" {
		t.Errorf("event.action = %q, want scan_error", event.Event.Action)
	}
	if event.Event.Outcome != "failure" {
		t.Errorf("event.outcome = %q, want failure", event.Event.Outcome)
	}

	if event.File == nil || event.File.Path != `C:\Users\jsmith\locked.docx` {
		t.Error("expected file.path")
	}

	if event.AV == nil || event.AV.Scan == nil || event.AV.Scan.Result != "error" {
		t.Error("expected av.scan.result = error")
	}
}

func TestAVUnknownEventType(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:future_feature", map[string]any{
		"data": "something new",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Action != "av:future_feature" {
		t.Errorf("event.action = %q, want av:future_feature", event.Event.Action)
	}
	if event.Host == nil || event.Host.Name != "WORKSTATION-01" {
		t.Error("expected common fields populated on unknown event type")
	}
}

func TestAVMissingOptionalFields(t *testing.T) {
	p := NewAkesoAVParser()
	// Minimal scan_result — no hashes, no signature, no file_size.
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path": `C:\test.exe`,
		"verdict":   "clean",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.File.Hash != nil {
		t.Error("expected no file.hash when hashes not provided")
	}
	if event.AV.Signature != nil {
		t.Error("expected no av.signature when not provided")
	}
	if event.File.Size != 0 {
		t.Errorf("file.size = %d, want 0", event.File.Size)
	}
}

func TestAVNoUserField(t *testing.T) {
	// Event without user info.
	event := map[string]any{
		"source_type": "akeso_av",
		"timestamp":   "2026-03-14T12:00:00Z",
		"hostname":    "SERVER-01",
		"event_type":  "av:signature_update",
		"payload": map[string]any{
			"version":         "2026.03.14.001",
			"signature_count": 50000,
			"engine":          "akeso-yara",
		},
	}
	data, _ := json.Marshal(event)

	p := NewAkesoAVParser()
	parsed, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.User != nil {
		t.Error("expected no user field when user not provided")
	}
}

func TestAVRoundTripMarshalUnmarshal(t *testing.T) {
	p := NewAkesoAVParser()
	raw := makeAVEvent("av:scan_result", map[string]any{
		"file_path":      `C:\malware.exe`,
		"file_size":      1024,
		"hash_sha256":    "abcdef",
		"verdict":        "malicious",
		"signature_name": "Trojan.Test",
		"engine":         "akeso-yara",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Marshal to JSON.
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify key fields present in JSON.
	expectedKeys := []string{"@timestamp", "event", "host", "user", "file", "av"}
	for _, key := range expectedKeys {
		if _, ok := decoded[key]; !ok {
			t.Errorf("expected key %q in JSON output", key)
		}
	}
}
