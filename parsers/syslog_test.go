package parsers

import (
	"strings"
	"testing"
	"time"
)

// ============================================================================
// RFC 5424 Tests
// ============================================================================

func TestRFC5424Full(t *testing.T) {
	raw := `<34>1 2026-03-14T12:00:00.123456Z myhost myapp 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Hello, world!`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Format != "rfc5424" {
		t.Errorf("format = %q, want rfc5424", msg.Format)
	}
	if msg.Priority != 34 {
		t.Errorf("priority = %d, want 34", msg.Priority)
	}
	if msg.Facility != 4 { // 34/8
		t.Errorf("facility = %d, want 4", msg.Facility)
	}
	if msg.Severity != 2 { // 34%8
		t.Errorf("severity = %d, want 2", msg.Severity)
	}
	if msg.Version != 1 {
		t.Errorf("version = %d, want 1", msg.Version)
	}
	if msg.Hostname != "myhost" {
		t.Errorf("hostname = %q, want myhost", msg.Hostname)
	}
	if msg.AppName != "myapp" {
		t.Errorf("appname = %q, want myapp", msg.AppName)
	}
	if msg.ProcID != "1234" {
		t.Errorf("procid = %q, want 1234", msg.ProcID)
	}
	if msg.MsgID != "ID47" {
		t.Errorf("msgid = %q, want ID47", msg.MsgID)
	}
	if msg.Message != "Hello, world!" {
		t.Errorf("message = %q, want %q", msg.Message, "Hello, world!")
	}

	// Check structured data.
	sd, ok := msg.StructuredData["exampleSDID@32473"]
	if !ok {
		t.Fatal("missing structured data element exampleSDID@32473")
	}
	if sd["iut"] != "3" {
		t.Errorf("sd[iut] = %q, want 3", sd["iut"])
	}
	if sd["eventSource"] != "Application" {
		t.Errorf("sd[eventSource] = %q, want Application", sd["eventSource"])
	}

	// Timestamp.
	expected := time.Date(2026, 3, 14, 12, 0, 0, 123456000, time.UTC)
	if !msg.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", msg.Timestamp, expected)
	}
}

func TestRFC5424NilValues(t *testing.T) {
	raw := `<13>1 - - - - - - No structured data or headers`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Format != "rfc5424" {
		t.Errorf("format = %q, want rfc5424", msg.Format)
	}
	if msg.Hostname != "" {
		t.Errorf("hostname = %q, want empty", msg.Hostname)
	}
	if msg.AppName != "" {
		t.Errorf("appname = %q, want empty", msg.AppName)
	}
	if msg.StructuredData != nil {
		t.Errorf("structured data = %v, want nil", msg.StructuredData)
	}
	if msg.Message != "No structured data or headers" {
		t.Errorf("message = %q", msg.Message)
	}
}

func TestRFC5424MultipleSD(t *testing.T) {
	raw := `<165>1 2026-03-14T12:00:00Z host app - - [sdA k1="v1"][sdB k2="v2"] msg`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(msg.StructuredData) != 2 {
		t.Fatalf("sd count = %d, want 2", len(msg.StructuredData))
	}
	if msg.StructuredData["sdA"]["k1"] != "v1" {
		t.Errorf("sdA.k1 = %q", msg.StructuredData["sdA"]["k1"])
	}
	if msg.StructuredData["sdB"]["k2"] != "v2" {
		t.Errorf("sdB.k2 = %q", msg.StructuredData["sdB"]["k2"])
	}
}

func TestRFC5424EscapedSD(t *testing.T) {
	raw := `<14>1 2026-03-14T12:00:00Z host app - - [test esc="val\"with\\escapes\]end"] msg`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	val := msg.StructuredData["test"]["esc"]
	expected := `val"with\escapes]end`
	if val != expected {
		t.Errorf("sd[test][esc] = %q, want %q", val, expected)
	}
}

func TestRFC5424NoMessage(t *testing.T) {
	raw := `<14>1 2026-03-14T12:00:00Z host app - - -`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Message != "" {
		t.Errorf("message = %q, want empty", msg.Message)
	}
}

func TestRFC5424NanosecondTimestamp(t *testing.T) {
	raw := `<14>1 2026-03-14T12:00:00.123456789Z host app - - - msg`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Timestamp.Nanosecond() != 123456789 {
		t.Errorf("nanosecond = %d, want 123456789", msg.Timestamp.Nanosecond())
	}
}

func TestRFC5424TimestampWithOffset(t *testing.T) {
	raw := `<14>1 2026-03-14T12:00:00+05:30 host app - - - msg`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be converted to UTC.
	expected := time.Date(2026, 3, 14, 6, 30, 0, 0, time.UTC)
	if !msg.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", msg.Timestamp, expected)
	}
}

// ============================================================================
// RFC 3164 Tests
// ============================================================================

func TestRFC3164Full(t *testing.T) {
	raw := `<34>Mar 14 12:00:00 myhost sshd[1234]: Failed password for root`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Format != "rfc3164" {
		t.Errorf("format = %q, want rfc3164", msg.Format)
	}
	if msg.Hostname != "myhost" {
		t.Errorf("hostname = %q, want myhost", msg.Hostname)
	}
	if msg.AppName != "sshd" {
		t.Errorf("appname = %q, want sshd", msg.AppName)
	}
	if msg.ProcID != "1234" {
		t.Errorf("procid = %q, want 1234", msg.ProcID)
	}
	if msg.Message != "Failed password for root" {
		t.Errorf("message = %q", msg.Message)
	}
	if msg.Timestamp.Month() != time.March || msg.Timestamp.Day() != 14 {
		t.Errorf("timestamp = %v, want March 14", msg.Timestamp)
	}
}

func TestRFC3164WithPID(t *testing.T) {
	raw := `<86>Mar 14 12:00:00 server CRON[5678]: (root) CMD (/usr/sbin/ntpdate)`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.AppName != "CRON" {
		t.Errorf("appname = %q, want CRON", msg.AppName)
	}
	if msg.ProcID != "5678" {
		t.Errorf("procid = %q, want 5678", msg.ProcID)
	}
}

func TestRFC3164SingleDigitDay(t *testing.T) {
	raw := `<34>Mar  5 12:00:00 host sshd: test`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.Timestamp.Day() != 5 {
		t.Errorf("day = %d, want 5", msg.Timestamp.Day())
	}
}

func TestRFC3164NoTag(t *testing.T) {
	raw := `<34>Mar 14 12:00:00 host just a message without a tag`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without a colon within 48 chars, the whole message body stays as Message.
	if msg.Hostname != "host" {
		t.Errorf("hostname = %q, want host", msg.Hostname)
	}
	if !strings.Contains(msg.Message, "just a message") {
		t.Errorf("message = %q, want to contain 'just a message'", msg.Message)
	}
}

// ============================================================================
// Format Detection
// ============================================================================

func TestDetectSyslogFormatRFC5424(t *testing.T) {
	if f := detectSyslogFormat("1 2026-03-14T12:00:00Z host app - - - msg"); f != "rfc5424" {
		t.Errorf("got %q, want rfc5424", f)
	}
}

func TestDetectSyslogFormatRFC3164(t *testing.T) {
	if f := detectSyslogFormat("Mar 14 12:00:00 host msg"); f != "rfc3164" {
		t.Errorf("got %q, want rfc3164", f)
	}
}

// ============================================================================
// Adversarial Tests
// ============================================================================

func TestSyslogEmptyInput(t *testing.T) {
	_, err := ParseSyslog("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestSyslogNoPRI(t *testing.T) {
	msg, err := ParseSyslog("No angle brackets here")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall through to raw message.
	if msg.Message != "No angle brackets here" {
		t.Errorf("message = %q", msg.Message)
	}
	if msg.Priority != -1 {
		t.Errorf("priority = %d, want -1 (no PRI)", msg.Priority)
	}
}

func TestSyslogInvalidPRI(t *testing.T) {
	// PRI > 191 is unusual but parseable.
	msg, err := ParseSyslog("<200>Mar 14 12:00:00 host msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Priority != 200 {
		t.Errorf("priority = %d, want 200", msg.Priority)
	}
}

func TestSyslogPRIOverflow(t *testing.T) {
	// Very large PRI — should fail to parse because > 3 digits means '>' at index > 5.
	msg, err := ParseSyslog("<999999999>Mar 14 12:00:00 host msg")
	if err != nil {
		t.Fatalf("unexpected error (should fallback to raw): %v", err)
	}
	// Falls through to raw message since PRI parsing fails.
	if msg.Priority != -1 {
		t.Errorf("priority = %d, want -1", msg.Priority)
	}
}

func TestSyslogMalformedTimestamp(t *testing.T) {
	raw := `<34>1 NOT-A-DATE hostname app - - - msg`
	_, err := ParseSyslog(raw)
	if err == nil {
		t.Error("expected error for invalid RFC 5424 timestamp")
	}
}

func TestSyslogExtremelyLongHostname(t *testing.T) {
	longHost := strings.Repeat("a", 300)
	raw := `<34>Mar 14 12:00:00 ` + longHost + ` sshd: msg`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Hostname != longHost {
		t.Errorf("hostname length = %d, want 300", len(msg.Hostname))
	}
}

func TestSyslogUnicodeMessage(t *testing.T) {
	raw := `<34>Mar 14 12:00:00 host app: 日本語メッセージ 🔥 with emoji`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg.Message, "🔥") {
		t.Errorf("message should contain emoji: %q", msg.Message)
	}
}

func TestSyslogOnlyPRI(t *testing.T) {
	raw := `<34>`
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty body after PRI — should produce a minimal message.
	if msg.Format != "rfc3164" {
		t.Errorf("format = %q, want rfc3164", msg.Format)
	}
}

func TestSyslogControlCharacters(t *testing.T) {
	raw := "<34>Mar 14 12:00:00 host app: message\twith\ttabs\x00and\x00nulls"
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg.Message, "\t") {
		t.Errorf("message should contain tabs: %q", msg.Message)
	}
}

func TestSyslogBOM(t *testing.T) {
	raw := "\xEF\xBB\xBF<34>Mar 14 12:00:00 host app: message"
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Hostname != "host" {
		t.Errorf("hostname = %q, want host", msg.Hostname)
	}
}

func TestSyslogTrailingNewlines(t *testing.T) {
	raw := "<34>Mar 14 12:00:00 host app: message\r\n"
	msg, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.HasSuffix(msg.Message, "\n") {
		t.Errorf("message should not end with newline: %q", msg.Message)
	}
}

// ============================================================================
// Helper function tests
// ============================================================================

func TestSyslogSeverityName(t *testing.T) {
	tests := []struct {
		sev  int
		want string
	}{
		{0, "emergency"}, {1, "alert"}, {2, "critical"}, {3, "error"},
		{4, "warning"}, {5, "notice"}, {6, "informational"}, {7, "debug"},
		{99, "unknown"}, {-1, "unknown"},
	}
	for _, tt := range tests {
		if got := SyslogSeverityName(tt.sev); got != tt.want {
			t.Errorf("SyslogSeverityName(%d) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSyslogFacilityName(t *testing.T) {
	if got := SyslogFacilityName(0); got != "kern" {
		t.Errorf("SyslogFacilityName(0) = %q, want kern", got)
	}
	if got := SyslogFacilityName(4); got != "auth" {
		t.Errorf("SyslogFacilityName(4) = %q, want auth", got)
	}
	if got := SyslogFacilityName(99); got != "unknown" {
		t.Errorf("SyslogFacilityName(99) = %q, want unknown", got)
	}
}
