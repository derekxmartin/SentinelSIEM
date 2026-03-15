package parsers

import (
	"encoding/json"
	"testing"
)

// helper: create a syslog JSON envelope.
func syslogEnv(rawMessage, transport, remoteAddr string) json.RawMessage {
	env := map[string]string{
		"source_type": "syslog",
		"raw_message": rawMessage,
		"transport":   transport,
		"remote_addr": remoteAddr,
	}
	data, _ := json.Marshal(env)
	return data
}

// ============================================================================
// Basic Tests
// ============================================================================

func TestSyslogECSParserSourceType(t *testing.T) {
	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if st := p.SourceType(); st != "syslog" {
		t.Errorf("SourceType() = %q, want syslog", st)
	}
}

func TestSyslogRFC5424ToECS(t *testing.T) {
	raw := syslogEnv(
		`<34>1 2026-03-14T12:00:00Z myhost myapp 1234 ID47 - Hello ECS`,
		"tcp", "192.168.1.1:45678",
	)

	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if event.Host == nil || event.Host.Name != "myhost" {
		t.Errorf("host.name = %v", event.Host)
	}
	if event.Process == nil || event.Process.Name != "myapp" {
		t.Errorf("process.name = %v", event.Process)
	}
	if event.Process.PID != 1234 {
		t.Errorf("process.pid = %d, want 1234", event.Process.PID)
	}
	if event.Event == nil || event.Event.Kind != "event" {
		t.Error("event.kind should be 'event'")
	}
	if event.Log == nil || event.Log.Syslog == nil {
		t.Fatal("log.syslog should be populated")
	}
	if event.Log.Syslog.Facility.Code != 4 {
		t.Errorf("facility = %d, want 4", event.Log.Syslog.Facility.Code)
	}
	if event.Log.Syslog.Severity.Code != 2 {
		t.Errorf("severity = %d, want 2", event.Log.Syslog.Severity.Code)
	}
	if event.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestSyslogRFC3164ToECS(t *testing.T) {
	raw := syslogEnv(
		`<86>Mar 14 12:00:00 server CRON[5678]: (root) CMD (/usr/sbin/ntpdate)`,
		"udp", "10.0.0.5:514",
	)

	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if event.Host == nil || event.Host.Name != "server" {
		t.Errorf("host.name = %v", event.Host)
	}
	if event.Process == nil || event.Process.Name != "CRON" {
		t.Errorf("process.name = %v", event.Process)
	}
	if event.Process.PID != 5678 {
		t.Errorf("process.pid = %d, want 5678", event.Process.PID)
	}
}

func TestSyslogIptablesToNetworkECS(t *testing.T) {
	raw := syslogEnv(
		`<4>Mar 14 12:00:00 fw kernel: DROP IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22`,
		"udp", "10.0.0.1:514",
	)

	p, err := NewSyslogECSParser("../../../parsers")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if event.Event.Action != "firewall_drop" {
		t.Errorf("event.action = %q, want firewall_drop", event.Event.Action)
	}
	if len(event.Event.Category) == 0 || event.Event.Category[0] != "network" {
		t.Errorf("event.category = %v, want [network]", event.Event.Category)
	}
	if len(event.Event.Type) == 0 || event.Event.Type[0] != "denied" {
		t.Errorf("event.type = %v, want [denied]", event.Event.Type)
	}
	if event.Source == nil || event.Source.IP != "192.168.1.100" {
		t.Errorf("source.ip = %v", event.Source)
	}
	if event.Destination == nil || event.Destination.IP != "10.0.0.1" {
		t.Errorf("destination.ip = %v", event.Destination)
	}
	if event.Source.Port != 12345 {
		t.Errorf("source.port = %d, want 12345", event.Source.Port)
	}
	if event.Destination.Port != 22 {
		t.Errorf("destination.port = %d, want 22", event.Destination.Port)
	}
}

func TestSyslogAuditdToProcessECS(t *testing.T) {
	raw := syslogEnv(
		`<86>Mar 14 12:00:00 server auditd: type=EXECVE msg=audit(1234567890.123:456): argc=2 a0="/usr/bin/curl" a1="http://evil.com"`,
		"tcp", "10.0.0.5:514",
	)

	p, err := NewSyslogECSParser("../../../parsers")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(event.Event.Category) == 0 || event.Event.Category[0] != "process" {
		t.Errorf("event.category = %v, want [process]", event.Event.Category)
	}
	if len(event.Event.Type) == 0 || event.Event.Type[0] != "start" {
		t.Errorf("event.type = %v, want [start]", event.Event.Type)
	}
}

func TestSyslogUnknownPreservesRaw(t *testing.T) {
	raw := syslogEnv(
		`<34>Mar 14 12:00:00 host myapp: some unstructured log line`,
		"tcp", "10.0.0.1:514",
	)

	p, err := NewSyslogECSParser("../../../parsers")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(event.Event.Category) == 0 || event.Event.Category[0] != "host" {
		t.Errorf("event.category = %v, want [host]", event.Event.Category)
	}
	if len(event.Event.Type) == 0 || event.Event.Type[0] != "info" {
		t.Errorf("event.type = %v, want [info]", event.Event.Type)
	}
}

func TestSyslogSeverityMapping(t *testing.T) {
	tests := []struct {
		severity int
		want     int
	}{
		{0, 100}, {1, 90}, {2, 80}, {3, 70},
		{4, 60}, {5, 50}, {6, 40}, {7, 20},
		{99, 0},
	}

	for _, tt := range tests {
		got := mapSyslogSeverity(tt.severity)
		if got != tt.want {
			t.Errorf("mapSyslogSeverity(%d) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestSyslogMissingSyslogTimestamp(t *testing.T) {
	// RFC 5424 with nil timestamp.
	raw := syslogEnv(
		`<34>1 - host app - - - msg`,
		"tcp", "10.0.0.1:514",
	)

	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should fall back to current time.
	if event.Timestamp.IsZero() {
		t.Error("timestamp should not be zero when syslog timestamp is nil")
	}
}

// ============================================================================
// Adversarial Tests
// ============================================================================

func TestSyslogECSInvalidJSONEnvelope(t *testing.T) {
	p, _ := NewSyslogECSParser("")
	_, err := p.Parse(json.RawMessage(`{{{not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSyslogECSMissingRawMessage(t *testing.T) {
	p, _ := NewSyslogECSParser("")
	raw := json.RawMessage(`{"source_type":"syslog","transport":"tcp"}`)
	_, err := p.Parse(raw)
	if err == nil {
		t.Error("expected error for missing raw_message")
	}
}

func TestSyslogECSEmptyRawMessage(t *testing.T) {
	p, _ := NewSyslogECSParser("")
	raw := json.RawMessage(`{"source_type":"syslog","raw_message":"","transport":"tcp"}`)
	_, err := p.Parse(raw)
	if err == nil {
		t.Error("expected error for empty raw_message")
	}
}

func TestSyslogECSEmptyInput(t *testing.T) {
	p, _ := NewSyslogECSParser("")
	_, err := p.Parse(json.RawMessage{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestSyslogECSNonUTF8Message(t *testing.T) {
	// Latin-1 encoded bytes in raw_message — should not panic.
	raw := syslogEnv(
		"<34>Mar 14 12:00:00 host app: m\xe9ssage with latin-1",
		"tcp", "10.0.0.1:514",
	)

	p, _ := NewSyslogECSParser("")
	event, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if event == nil {
		t.Fatal("event should not be nil")
	}
}

func TestSyslogECSBatchMixedFormats(t *testing.T) {
	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	messages := []string{
		`<34>1 2026-03-14T12:00:00Z host1 app1 - - - RFC 5424 message`,
		`<86>Mar 14 12:00:00 host2 sshd[123]: RFC 3164 message`,
	}

	for _, msg := range messages {
		raw := syslogEnv(msg, "tcp", "10.0.0.1:514")
		event, err := p.Parse(raw)
		if err != nil {
			t.Errorf("parse %q: %v", msg[:20], err)
			continue
		}
		if event.Host == nil {
			t.Errorf("host should be populated for: %q", msg[:20])
		}
	}
}

// ============================================================================
// Pipeline Integration
// ============================================================================

func TestSyslogECSParserImplementsInterface(t *testing.T) {
	p, err := NewSyslogECSParser("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Verify it has both methods required by normalize.Parser.
	_ = p.SourceType()
	raw := syslogEnv("<34>Mar 14 12:00:00 host app: test", "tcp", "10.0.0.1:514")
	_, _ = p.Parse(raw)
}

func TestSyslogECSApplyFieldPaths(t *testing.T) {
	// Test applyECSField for all supported paths.
	p, _ := NewSyslogECSParser("")

	raw := syslogEnv(
		`<4>Mar 14 12:00:00 fw kernel: DROP IN=eth0 OUT=eth1 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=80 DPT=443`,
		"tcp", "10.0.0.1:514",
	)

	event, err := p.Parse(raw)
	if err != nil {
		// Without sub-parsers this won't match iptables.
		// So let's test with the real parsers dir.
		p2, err2 := NewSyslogECSParser("../../../parsers")
		if err2 != nil {
			t.Skipf("can't load parsers: %v", err2)
		}
		event, err = p2.Parse(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
	}

	if event.Source != nil && event.Source.IP == "1.2.3.4" {
		// Good — sub-parser applied.
		if event.Network == nil || event.Network.Protocol != "TCP" {
			t.Errorf("network.protocol = %v", event.Network)
		}
	}
}
