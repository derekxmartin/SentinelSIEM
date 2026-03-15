package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: write a YAML sub-parser config to a temp dir and load it.
func loadTestSubParser(t *testing.T, yaml string) *SubParserRegistry {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "syslog_test.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	reg, err := LoadSubParsers(dir)
	if err != nil {
		t.Fatalf("load sub-parsers: %v", err)
	}
	return reg
}

// ============================================================================
// Functional Tests
// ============================================================================

func TestSubParserIptablesDrop(t *testing.T) {
	// Use the real iptables YAML.
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	msg := "DROP IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=192.168.1.100 DST=10.0.0.1 LEN=40 TOS=0x00 PROTO=TCP SPT=12345 DPT=22"
	result, ok := reg.Parse("kernel", msg)
	if !ok {
		t.Fatal("expected match")
	}

	if result.ParserName != "iptables" {
		t.Errorf("parser = %q, want iptables", result.ParserName)
	}
	if result.Action != "firewall_drop" {
		t.Errorf("action = %q, want firewall_drop", result.Action)
	}
	if result.Fields["source.ip"] != "192.168.1.100" {
		t.Errorf("source.ip = %q", result.Fields["source.ip"])
	}
	if result.Fields["destination.ip"] != "10.0.0.1" {
		t.Errorf("destination.ip = %q", result.Fields["destination.ip"])
	}
	if result.Fields["source.port"] != "12345" {
		t.Errorf("source.port = %q", result.Fields["source.port"])
	}
	if result.Fields["destination.port"] != "22" {
		t.Errorf("destination.port = %q", result.Fields["destination.port"])
	}

	if len(result.Category) == 0 || result.Category[0] != "network" {
		t.Errorf("category = %v, want [network]", result.Category)
	}
	if len(result.Type) == 0 || result.Type[0] != "denied" {
		t.Errorf("type = %v, want [denied]", result.Type)
	}
}

func TestSubParserIptablesAccept(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	msg := "ACCEPT IN=eth0 OUT=eth1 SRC=10.0.0.5 DST=10.0.0.1 PROTO=UDP SPT=53 DPT=1234"
	result, ok := reg.Parse("kernel", msg)
	if !ok {
		t.Fatal("expected match")
	}

	if result.Action != "firewall_accept" {
		t.Errorf("action = %q, want firewall_accept", result.Action)
	}
	if len(result.Type) == 0 || result.Type[0] != "allowed" {
		t.Errorf("type = %v, want [allowed]", result.Type)
	}
}

func TestSubParserAuditdExecve(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	msg := `type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="/usr/bin/curl" a1="http://example.com" a2="-o"`
	result, ok := reg.Parse("auditd", msg)
	if !ok {
		t.Fatal("expected match")
	}

	if result.ParserName != "auditd" {
		t.Errorf("parser = %q, want auditd", result.ParserName)
	}
	if len(result.Category) == 0 || result.Category[0] != "process" {
		t.Errorf("category = %v, want [process]", result.Category)
	}
}

func TestSubParserAuditdUserAuth(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	msg := `type=USER_AUTH msg=audit(1234567890.123:789): pid=1234 uid=0 acct="admin" res=success`
	result, ok := reg.Parse("auditd", msg)
	if !ok {
		t.Fatal("expected match")
	}

	if result.Fields["user.name"] != "admin" {
		t.Errorf("user.name = %q, want admin", result.Fields["user.name"])
	}
	if len(result.Category) == 0 || result.Category[0] != "authentication" {
		t.Errorf("category = %v, want [authentication]", result.Category)
	}
}

func TestSubParserNoMatch(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// A message that doesn't match any sub-parser.
	_, ok := reg.Parse("someapp", "just a plain log message with no special format")
	if ok {
		t.Error("expected no match for plain message")
	}
}

func TestSubParserPriority(t *testing.T) {
	// iptables match should take priority over generic KV when both could match.
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	msg := "DROP IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=80 DPT=443"
	result, ok := reg.Parse("kernel", msg)
	if !ok {
		t.Fatal("expected match")
	}
	if result.ParserName != "iptables" {
		t.Errorf("parser = %q, want iptables (priority over generic_kv)", result.ParserName)
	}
}

// ============================================================================
// YAML Loading Tests
// ============================================================================

func TestLoadValidYAML(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	names := reg.ParserNames()
	if len(names) < 3 {
		t.Errorf("expected at least 3 sub-parsers, got %d: %v", len(names), names)
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	reg, err := LoadSubParsers(dir)
	if err != nil {
		t.Fatalf("load empty dir: %v", err)
	}
	if len(reg.ParserNames()) != 0 {
		t.Errorf("expected 0 parsers, got %d", len(reg.ParserNames()))
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog_bad.yaml"), []byte("{{{{not yaml"), 0644)

	_, err := LoadSubParsers(dir)
	if err == nil {
		t.Error("expected error for malformed YAML")
	}
}

func TestLoadInvalidRegex(t *testing.T) {
	yaml := `
name: bad_regex
match: "test"
patterns:
  - name: bad
    regex: "["
    field_map: {}
`
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog_bad.yaml"), []byte(yaml), 0644)

	_, err := LoadSubParsers(dir)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestLoadEmptyRegex(t *testing.T) {
	yaml := `
name: empty_regex
match: "test"
patterns:
  - name: empty
    regex: ""
    field_map: {}
`
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog_empty.yaml"), []byte(yaml), 0644)

	_, err := LoadSubParsers(dir)
	if err == nil {
		t.Error("expected error for empty regex")
	}
}

func TestLoadMissingName(t *testing.T) {
	yaml := `
match: "test"
patterns: []
`
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog_noname.yaml"), []byte(yaml), 0644)

	_, err := LoadSubParsers(dir)
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestLoadMissingMatch(t *testing.T) {
	yaml := `
name: no_match
patterns: []
`
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog_nomatch.yaml"), []byte(yaml), 0644)

	_, err := LoadSubParsers(dir)
	if err == nil {
		t.Error("expected error for missing match")
	}
}

// ============================================================================
// Adversarial Tests
// ============================================================================

func TestSubParserRegexBacktracking(t *testing.T) {
	// Go's RE2 engine handles this in linear time.
	yaml := `
name: backtrack_test
match: "test"
patterns:
  - name: bt
    regex: "(a+)+b"
    field_map: {}
`
	reg := loadTestSubParser(t, yaml)

	// Input designed to cause backtracking in PCRE — should be fast with RE2.
	input := "test " + strings.Repeat("a", 30) + "c"
	_, _ = reg.Parse("test", input)
	// Main assertion: completes quickly (no catastrophic backtracking).
}

func TestSubParserVeryLongMessage(t *testing.T) {
	reg, err := LoadSubParsers("../../../parsers")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// 100KB message.
	msg := "IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=80 DPT=443 " + strings.Repeat("X", 100000)
	result, ok := reg.Parse("kernel", msg)
	if !ok {
		t.Fatal("expected iptables match")
	}
	if result.Fields["source.ip"] != "1.2.3.4" {
		t.Errorf("source.ip = %q", result.Fields["source.ip"])
	}
}

func TestSubParserRegexNoNamedGroups(t *testing.T) {
	yaml := `
name: no_groups
match: "pattern"
patterns:
  - name: ng
    regex: "hello (world)"
    field_map: {}
    action: matched
`
	reg := loadTestSubParser(t, yaml)

	result, ok := reg.Parse("pattern", "hello world")
	if !ok {
		t.Fatal("expected match")
	}
	if result.Action != "matched" {
		t.Errorf("action = %q, want matched", result.Action)
	}
}

// ============================================================================
// KV Parser Tests
// ============================================================================

func TestParseKVPairs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		{"simple", "foo=bar baz=qux", "foo", "bar"},
		{"quoted", `foo="hello world"`, "foo", "hello world"},
		{"equals_in_value", `path=/tmp/file.txt`, "path", "/tmp/file.txt"},
		{"empty_value", "key=", "key", ""},
		{"unicode", "name=日本語", "name", "日本語"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := ParseKVPairs(tt.input)
			if kv[tt.key] != tt.want {
				t.Errorf("kv[%q] = %q, want %q", tt.key, kv[tt.key], tt.want)
			}
		})
	}
}

func TestNilSubParserRegistry(t *testing.T) {
	var reg *SubParserRegistry
	_, ok := reg.Parse("app", "message")
	if ok {
		t.Error("nil registry should return false")
	}
	if names := reg.ParserNames(); names != nil {
		t.Errorf("nil registry ParserNames should be nil, got %v", names)
	}
}
