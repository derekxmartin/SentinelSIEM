package common

import (
	"encoding/json"
	"testing"
	"time"
)

func TestECSEventRoundTrip(t *testing.T) {
	original := ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &EventFields{
			Kind:     "event",
			Category: []string{"process", "network"},
			Type:     []string{"start", "connection"},
			Action:   "process_created",
			Outcome:  "success",
			Severity: 3,
		},
		Process: &ProcessFields{
			PID:         1234,
			Name:        "cmd.exe",
			Executable:  `C:\Windows\System32\cmd.exe`,
			CommandLine: `cmd.exe /c whoami`,
			Parent: &ParentProcess{
				PID:        5678,
				Name:       "explorer.exe",
				Executable: `C:\Windows\explorer.exe`,
			},
		},
		Source: &EndpointFields{
			IP:     "192.168.1.100",
			Port:   54321,
			Domain: "workstation.local",
			User:   &UserFields{Name: "jsmith", Domain: "CORP", ID: "S-1-5-21-1234"},
		},
		Destination: &EndpointFields{
			IP:   "10.0.0.50",
			Port: 443,
		},
		User: &UserFields{
			Name:   "jsmith",
			Domain: "CORP",
			ID:     "S-1-5-21-1234",
		},
		Host: &HostFields{
			Name: "WORKSTATION-01",
			IP:   []string{"192.168.1.100", "fe80::1"},
			OS: &OSFields{
				Name:     "Windows 11",
				Platform: "windows",
				Version:  "10.0.26200",
			},
		},
		File: &FileFields{
			Name: "payload.exe",
			Path: `C:\Users\jsmith\Downloads\payload.exe`,
			Hash: &HashFields{
				MD5:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Size: 102400,
		},
		Registry: &RegistryFields{
			Key:   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			Value: "Updater",
			Data: &RegistryDataFields{
				Type:    "REG_SZ",
				Strings: []string{`C:\temp\updater.exe`},
			},
		},
		Network: &NetworkFields{
			Protocol:  "tcp",
			Direction: "outbound",
			Bytes:     4096,
		},
		Threat: &ThreatFields{
			Technique: []ThreatTechnique{
				{ID: "T1059.003", Name: "Windows Command Shell"},
				{ID: "T1547.001", Name: "Registry Run Keys"},
			},
		},
		DLP: &DLPFields{
			Policy:         &DLPPolicy{Name: "PCI-DSS", Action: "block"},
			Classification: "confidential",
			Channel:        "usb",
		},
		AV: &AVFields{
			Scan:      &AVScan{Result: "malicious", Engine: "akeso-yara"},
			Signature: &AVSignature{Name: "Mimikatz_Binary"},
			Action:    "quarantine",
		},
		Raw: json.RawMessage(`{"source_type":"edr","original":"data"}`),
	}

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal
	var decoded ECSEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify all field groups survived round-trip
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("timestamp: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}

	// Event
	if decoded.Event.Kind != "event" {
		t.Errorf("event.kind: got %q, want %q", decoded.Event.Kind, "event")
	}
	if len(decoded.Event.Category) != 2 || decoded.Event.Category[0] != "process" {
		t.Errorf("event.category: got %v, want [process network]", decoded.Event.Category)
	}
	if len(decoded.Event.Type) != 2 || decoded.Event.Type[0] != "start" {
		t.Errorf("event.type: got %v, want [start connection]", decoded.Event.Type)
	}

	// Process + parent
	if decoded.Process.PID != 1234 {
		t.Errorf("process.pid: got %d, want 1234", decoded.Process.PID)
	}
	if decoded.Process.Parent.PID != 5678 {
		t.Errorf("process.parent.pid: got %d, want 5678", decoded.Process.Parent.PID)
	}

	// Source + nested user
	if decoded.Source.IP != "192.168.1.100" {
		t.Errorf("source.ip: got %q, want %q", decoded.Source.IP, "192.168.1.100")
	}
	if decoded.Source.User.Name != "jsmith" {
		t.Errorf("source.user.name: got %q, want %q", decoded.Source.User.Name, "jsmith")
	}

	// Destination
	if decoded.Destination.Port != 443 {
		t.Errorf("destination.port: got %d, want 443", decoded.Destination.Port)
	}

	// User
	if decoded.User.Domain != "CORP" {
		t.Errorf("user.domain: got %q, want %q", decoded.User.Domain, "CORP")
	}

	// Host + OS
	if decoded.Host.Name != "WORKSTATION-01" {
		t.Errorf("host.name: got %q, want %q", decoded.Host.Name, "WORKSTATION-01")
	}
	if len(decoded.Host.IP) != 2 {
		t.Errorf("host.ip: got %d entries, want 2", len(decoded.Host.IP))
	}
	if decoded.Host.OS.Platform != "windows" {
		t.Errorf("host.os.platform: got %q, want %q", decoded.Host.OS.Platform, "windows")
	}

	// File + hash
	if decoded.File.Name != "payload.exe" {
		t.Errorf("file.name: got %q, want %q", decoded.File.Name, "payload.exe")
	}
	if decoded.File.Hash.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("file.hash.sha256 mismatch")
	}
	if decoded.File.Size != 102400 {
		t.Errorf("file.size: got %d, want 102400", decoded.File.Size)
	}

	// Registry + data
	if decoded.Registry.Value != "Updater" {
		t.Errorf("registry.value: got %q, want %q", decoded.Registry.Value, "Updater")
	}
	if decoded.Registry.Data.Type != "REG_SZ" {
		t.Errorf("registry.data.type: got %q, want %q", decoded.Registry.Data.Type, "REG_SZ")
	}

	// Network
	if decoded.Network.Protocol != "tcp" {
		t.Errorf("network.protocol: got %q, want %q", decoded.Network.Protocol, "tcp")
	}
	if decoded.Network.Bytes != 4096 {
		t.Errorf("network.bytes: got %d, want 4096", decoded.Network.Bytes)
	}

	// Threat
	if len(decoded.Threat.Technique) != 2 {
		t.Errorf("threat.technique: got %d, want 2", len(decoded.Threat.Technique))
	}
	if decoded.Threat.Technique[0].ID != "T1059.003" {
		t.Errorf("threat.technique[0].id: got %q, want %q", decoded.Threat.Technique[0].ID, "T1059.003")
	}

	// DLP
	if decoded.DLP.Policy.Name != "PCI-DSS" {
		t.Errorf("dlp.policy.name: got %q, want %q", decoded.DLP.Policy.Name, "PCI-DSS")
	}
	if decoded.DLP.Channel != "usb" {
		t.Errorf("dlp.channel: got %q, want %q", decoded.DLP.Channel, "usb")
	}

	// AV
	if decoded.AV.Scan.Result != "malicious" {
		t.Errorf("av.scan.result: got %q, want %q", decoded.AV.Scan.Result, "malicious")
	}
	if decoded.AV.Signature.Name != "Mimikatz_Binary" {
		t.Errorf("av.signature.name: got %q, want %q", decoded.AV.Signature.Name, "Mimikatz_Binary")
	}

	// Raw
	if string(decoded.Raw) != `{"source_type":"edr","original":"data"}` {
		t.Errorf("raw: got %q", string(decoded.Raw))
	}
}

func TestECSEventOmitEmpty(t *testing.T) {
	// Sparse event — only timestamp and event fields set.
	sparse := ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &EventFields{
			Kind:     "alert",
			Category: []string{"intrusion_detection"},
		},
	}

	data, err := json.Marshal(sparse)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify omitted groups are not in JSON output.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	omittedKeys := []string{"process", "source", "destination", "user", "host", "file", "registry", "network", "threat", "dlp", "av", "raw"}
	for _, key := range omittedKeys {
		if _, exists := raw[key]; exists {
			t.Errorf("expected %q to be omitted from sparse event JSON", key)
		}
	}

	// Verify present fields are there.
	if _, exists := raw["@timestamp"]; !exists {
		t.Error("expected @timestamp in JSON")
	}
	if _, exists := raw["event"]; !exists {
		t.Error("expected event in JSON")
	}
}
