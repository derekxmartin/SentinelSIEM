package parsers

import (
	"encoding/json"
	"testing"
)

func makeDLPEvent(eventType string, payload map[string]any) json.RawMessage {
	event := map[string]any{
		"source_type": "akeso_dlp",
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

func TestDLPSourceType(t *testing.T) {
	p := NewAkesoDLPParser()
	if p.SourceType() != "akeso_dlp" {
		t.Errorf("SourceType() = %q, want %q", p.SourceType(), "akeso_dlp")
	}
}

func TestDLPCommonFields(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:policy_violation", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\financials.xlsx`,
		"policy_name":    "PCI-DSS",
		"classification": "confidential",
		"channel":        "email",
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

func TestDLPPolicyViolation(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:policy_violation", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\financials.xlsx`,
		"file_size":      51200,
		"policy_name":    "PCI-DSS",
		"policy_action":  "alert",
		"classification": "confidential",
		"channel":        "email",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Event metadata
	if event.Event.Category[0] != "file" {
		t.Errorf("event.category = %v, want [file]", event.Event.Category)
	}
	if event.Event.Type[0] != "access" {
		t.Errorf("event.type = %v, want [access]", event.Event.Type)
	}
	if event.Event.Action != "violation" {
		t.Errorf("event.action = %q, want violation", event.Event.Action)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("event.outcome = %q, want success", event.Event.Outcome)
	}

	// File
	if event.File == nil {
		t.Fatal("expected file fields")
	}
	if event.File.Path != `C:\Users\jsmith\Documents\financials.xlsx` {
		t.Errorf("file.path = %q", event.File.Path)
	}
	if event.File.Name != "financials.xlsx" {
		t.Errorf("file.name = %q, want financials.xlsx", event.File.Name)
	}
	if event.File.Size != 51200 {
		t.Errorf("file.size = %d, want 51200", event.File.Size)
	}

	// DLP fields
	if event.DLP == nil {
		t.Fatal("expected dlp fields")
	}
	if event.DLP.Policy == nil {
		t.Fatal("expected dlp.policy fields")
	}
	if event.DLP.Policy.Name != "PCI-DSS" {
		t.Errorf("dlp.policy.name = %q, want PCI-DSS", event.DLP.Policy.Name)
	}
	if event.DLP.Policy.Action != "alert" {
		t.Errorf("dlp.policy.action = %q, want alert", event.DLP.Policy.Action)
	}
	if event.DLP.Classification != "confidential" {
		t.Errorf("dlp.classification = %q, want confidential", event.DLP.Classification)
	}
	if event.DLP.Channel != "email" {
		t.Errorf("dlp.channel = %q, want email", event.DLP.Channel)
	}
}

func TestDLPClassification(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:classification", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\report.docx`,
		"file_size":      10240,
		"classification": "internal",
		"previous_label": "public",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "file" {
		t.Errorf("event.category = %v, want [file]", event.Event.Category)
	}
	if event.Event.Type[0] != "change" {
		t.Errorf("event.type = %v, want [change]", event.Event.Type)
	}
	if event.Event.Action != "classification" {
		t.Errorf("event.action = %q, want classification", event.Event.Action)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("event.outcome = %q, want success", event.Event.Outcome)
	}

	// File
	if event.File == nil || event.File.Path != `C:\Users\jsmith\Documents\report.docx` {
		t.Error("expected file.path")
	}
	if event.File.Name != "report.docx" {
		t.Errorf("file.name = %q, want report.docx", event.File.Name)
	}

	// DLP — classification only, no policy.
	if event.DLP == nil {
		t.Fatal("expected dlp fields")
	}
	if event.DLP.Classification != "internal" {
		t.Errorf("dlp.classification = %q, want internal", event.DLP.Classification)
	}
	if event.DLP.Policy != nil {
		t.Error("expected no dlp.policy for classification event")
	}
}

func TestDLPBlock(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:block", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\secrets.pdf`,
		"file_size":      204800,
		"policy_name":    "HIPAA",
		"policy_action":  "block",
		"classification": "restricted",
		"channel":        "upload",
		"reason":         "upload to unauthorized cloud service",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "file" {
		t.Errorf("event.category = %v, want [file]", event.Event.Category)
	}
	if event.Event.Type[0] != "denied" {
		t.Errorf("event.type = %v, want [denied]", event.Event.Type)
	}
	if event.Event.Action != "block" {
		t.Errorf("event.action = %q, want block", event.Event.Action)
	}
	if event.Event.Outcome != "failure" {
		t.Errorf("event.outcome = %q, want failure", event.Event.Outcome)
	}

	// File
	if event.File == nil || event.File.Path != `C:\Users\jsmith\Documents\secrets.pdf` {
		t.Error("expected file.path")
	}
	if event.File.Size != 204800 {
		t.Errorf("file.size = %d, want 204800", event.File.Size)
	}

	// DLP fields
	if event.DLP == nil {
		t.Fatal("expected dlp fields")
	}
	if event.DLP.Policy == nil || event.DLP.Policy.Name != "HIPAA" {
		t.Error("expected dlp.policy.name = HIPAA")
	}
	if event.DLP.Policy.Action != "block" {
		t.Errorf("dlp.policy.action = %q, want block", event.DLP.Policy.Action)
	}
	if event.DLP.Classification != "restricted" {
		t.Errorf("dlp.classification = %q, want restricted", event.DLP.Classification)
	}
	if event.DLP.Channel != "upload" {
		t.Errorf("dlp.channel = %q, want upload", event.DLP.Channel)
	}
}

func TestDLPAudit(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:audit", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\employee_list.csv`,
		"file_size":      8192,
		"policy_name":    "PII-Monitor",
		"policy_action":  "audit",
		"classification": "internal",
		"channel":        "share",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "file" {
		t.Errorf("event.category = %v, want [file]", event.Event.Category)
	}
	if event.Event.Type[0] != "access" {
		t.Errorf("event.type = %v, want [access]", event.Event.Type)
	}
	if event.Event.Action != "audit" {
		t.Errorf("event.action = %q, want audit", event.Event.Action)
	}
	if event.Event.Outcome != "success" {
		t.Errorf("event.outcome = %q, want success (allowed access)", event.Event.Outcome)
	}

	// DLP fields
	if event.DLP == nil {
		t.Fatal("expected dlp fields")
	}
	if event.DLP.Policy == nil || event.DLP.Policy.Name != "PII-Monitor" {
		t.Error("expected dlp.policy.name = PII-Monitor")
	}
	if event.DLP.Channel != "share" {
		t.Errorf("dlp.channel = %q, want share", event.DLP.Channel)
	}
}

func TestDLPRemovableMedia(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:removable_media", map[string]any{
		"file_path":      `E:\backup\database.sql`,
		"file_size":      1048576,
		"device_id":      "USB\\VID_0781&PID_5583\\12345",
		"device_label":   "SanDisk Ultra",
		"policy_name":    "USB-Restrict",
		"policy_action":  "alert",
		"classification": "confidential",
		"channel":        "usb",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Category[0] != "file" {
		t.Errorf("event.category = %v, want [file]", event.Event.Category)
	}
	if event.Event.Type[0] != "creation" {
		t.Errorf("event.type = %v, want [creation]", event.Event.Type)
	}
	if event.Event.Action != "removable_media_write" {
		t.Errorf("event.action = %q, want removable_media_write", event.Event.Action)
	}

	// File
	if event.File == nil || event.File.Path != `E:\backup\database.sql` {
		t.Error("expected file.path")
	}
	if event.File.Name != "database.sql" {
		t.Errorf("file.name = %q, want database.sql", event.File.Name)
	}
	if event.File.Size != 1048576 {
		t.Errorf("file.size = %d, want 1048576", event.File.Size)
	}

	// Destination (device info)
	if event.Destination == nil {
		t.Fatal("expected destination fields for device info")
	}
	if event.Destination.Address != "USB\\VID_0781&PID_5583\\12345" {
		t.Errorf("destination.address (device_id) = %q", event.Destination.Address)
	}
	if event.Destination.Domain != "SanDisk Ultra" {
		t.Errorf("destination.domain (device_label) = %q, want SanDisk Ultra", event.Destination.Domain)
	}

	// DLP fields
	if event.DLP == nil {
		t.Fatal("expected dlp fields")
	}
	if event.DLP.Channel != "usb" {
		t.Errorf("dlp.channel = %q, want usb", event.DLP.Channel)
	}
	if event.DLP.Classification != "confidential" {
		t.Errorf("dlp.classification = %q, want confidential", event.DLP.Classification)
	}
	if event.DLP.Policy == nil || event.DLP.Policy.Name != "USB-Restrict" {
		t.Error("expected dlp.policy.name = USB-Restrict")
	}
}

func TestDLPRemovableMediaDefaultChannel(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:removable_media", map[string]any{
		"file_path": `E:\data.csv`,
		"device_id": "USB\\DEVICE\\001",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should default to "usb" when channel not specified.
	if event.DLP == nil || event.DLP.Channel != "usb" {
		t.Errorf("dlp.channel = %v, want usb (default)", event.DLP)
	}
}

func TestDLPRemovableMediaNoDevice(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:removable_media", map[string]any{
		"file_path": `E:\data.csv`,
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// No device_id → no destination.
	if event.Destination != nil {
		t.Error("expected no destination when device_id not provided")
	}
}

func TestDLPUnknownEventType(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:future_feature", map[string]any{
		"data": "something new",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.Event.Action != "dlp:future_feature" {
		t.Errorf("event.action = %q, want dlp:future_feature", event.Event.Action)
	}
	if event.Host == nil || event.Host.Name != "WORKSTATION-01" {
		t.Error("expected common fields populated on unknown event type")
	}
}

func TestDLPMissingOptionalFields(t *testing.T) {
	p := NewAkesoDLPParser()
	// Minimal policy_violation — no file_size, no policy_action.
	raw := makeDLPEvent("dlp:policy_violation", map[string]any{
		"file_path":      `C:\test.docx`,
		"policy_name":    "Test-Policy",
		"classification": "public",
		"channel":        "print",
	})

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if event.File.Size != 0 {
		t.Errorf("file.size = %d, want 0", event.File.Size)
	}
	if event.DLP.Policy.Action != "" {
		t.Errorf("dlp.policy.action = %q, want empty", event.DLP.Policy.Action)
	}
}

func TestDLPNoUserField(t *testing.T) {
	// Event without user info.
	event := map[string]any{
		"source_type": "akeso_dlp",
		"timestamp":   "2026-03-14T12:00:00Z",
		"hostname":    "SERVER-01",
		"event_type":  "dlp:classification",
		"payload": map[string]any{
			"file_path":      `C:\data\file.txt`,
			"classification": "internal",
		},
	}
	data, _ := json.Marshal(event)

	p := NewAkesoDLPParser()
	parsed, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.User != nil {
		t.Error("expected no user field when user not provided")
	}
}

func TestDLPAllChannels(t *testing.T) {
	p := NewAkesoDLPParser()
	channels := []string{"email", "upload", "usb", "print", "share"}

	for _, ch := range channels {
		raw := makeDLPEvent("dlp:policy_violation", map[string]any{
			"file_path":      `C:\test.docx`,
			"policy_name":    "Test",
			"classification": "internal",
			"channel":        ch,
		})

		event, err := p.Parse(raw)
		if err != nil {
			t.Fatalf("Parse failed for channel %q: %v", ch, err)
		}

		if event.DLP == nil || event.DLP.Channel != ch {
			t.Errorf("channel %q: dlp.channel = %v", ch, event.DLP)
		}
	}
}

func TestDLPRoundTripMarshalUnmarshal(t *testing.T) {
	p := NewAkesoDLPParser()
	raw := makeDLPEvent("dlp:policy_violation", map[string]any{
		"file_path":      `C:\Users\jsmith\Documents\data.xlsx`,
		"file_size":      1024,
		"policy_name":    "PCI-DSS",
		"policy_action":  "alert",
		"classification": "confidential",
		"channel":        "email",
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
	expectedKeys := []string{"@timestamp", "event", "host", "user", "file", "dlp"}
	for _, key := range expectedKeys {
		if _, ok := decoded[key]; !ok {
			t.Errorf("expected key %q in JSON output", key)
		}
	}
}
