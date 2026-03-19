package correlate

import (
	"strings"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// --- getEventFieldValue tests ---

func TestGetEventFieldValue_EventAction(t *testing.T) {
	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "scanner_match"},
	}
	val, ok := getEventFieldValue(event, "event.action")
	if !ok || val != "scanner_match" {
		t.Errorf("expected scanner_match, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_EventCategory(t *testing.T) {
	event := &common.ECSEvent{
		Event: &common.EventFields{Category: []string{"network", "process"}},
	}
	val, ok := getEventFieldValue(event, "event.category")
	if !ok {
		t.Fatal("expected ok=true")
	}
	cats, ok := val.([]string)
	if !ok || len(cats) != 2 {
		t.Errorf("expected []string of length 2, got %T %v", val, val)
	}
}

func TestGetEventFieldValue_NestedField(t *testing.T) {
	event := &common.ECSEvent{
		AV: &common.AVFields{
			Scan: &common.AVScan{Result: "malicious"},
		},
	}
	val, ok := getEventFieldValue(event, "av.scan.result")
	if !ok || val != "malicious" {
		t.Errorf("expected malicious, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_DeepNested(t *testing.T) {
	event := &common.ECSEvent{
		Process: &common.ProcessFields{
			Parent: &common.ParentProcess{Name: "cmd.exe"},
		},
	}
	val, ok := getEventFieldValue(event, "process.parent.name")
	if !ok || val != "cmd.exe" {
		t.Errorf("expected cmd.exe, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_NilStruct(t *testing.T) {
	event := &common.ECSEvent{} // No Event struct set.
	_, ok := getEventFieldValue(event, "event.action")
	if ok {
		t.Error("expected ok=false for nil struct")
	}
}

func TestGetEventFieldValue_UnknownTopLevel(t *testing.T) {
	event := &common.ECSEvent{}
	_, ok := getEventFieldValue(event, "nonexistent.field")
	if ok {
		t.Error("expected ok=false for unknown top-level field")
	}
}

func TestGetEventFieldValue_UnknownSubfield(t *testing.T) {
	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "test"},
	}
	_, ok := getEventFieldValue(event, "event.nonexistent")
	if ok {
		t.Error("expected ok=false for unknown subfield")
	}
}

func TestGetEventFieldValue_EmptyStringField(t *testing.T) {
	event := &common.ECSEvent{
		Event: &common.EventFields{Action: ""},
	}
	_, ok := getEventFieldValue(event, "event.action")
	if ok {
		t.Error("expected ok=false for empty string field")
	}
}

func TestGetEventFieldValue_HostIP(t *testing.T) {
	event := &common.ECSEvent{
		Host: &common.HostFields{IP: []string{"10.0.0.1", "10.0.0.2"}},
	}
	val, ok := getEventFieldValue(event, "host.ip")
	if !ok {
		t.Fatal("expected ok=true for host.ip")
	}
	ips, ok := val.([]string)
	if !ok || len(ips) != 2 {
		t.Errorf("expected []string of length 2, got %T %v", val, val)
	}
}

func TestGetEventFieldValue_SourceIP(t *testing.T) {
	event := &common.ECSEvent{
		Source: &common.EndpointFields{IP: "192.168.1.1"},
	}
	val, ok := getEventFieldValue(event, "source.ip")
	if !ok || val != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_DestinationIP(t *testing.T) {
	event := &common.ECSEvent{
		Destination: &common.EndpointFields{IP: "8.8.8.8"},
	}
	val, ok := getEventFieldValue(event, "destination.ip")
	if !ok || val != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_NetworkDirection(t *testing.T) {
	event := &common.ECSEvent{
		Network: &common.NetworkFields{Direction: "outbound"},
	}
	val, ok := getEventFieldValue(event, "network.direction")
	if !ok || val != "outbound" {
		t.Errorf("expected outbound, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_DLPClassification(t *testing.T) {
	event := &common.ECSEvent{
		DLP: &common.DLPFields{Classification: "confidential"},
	}
	val, ok := getEventFieldValue(event, "dlp.classification")
	if !ok || val != "confidential" {
		t.Errorf("expected confidential, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_DNSQuestionName(t *testing.T) {
	event := &common.ECSEvent{
		DNS: &common.DNSFields{
			Question: &common.DNSQuestion{Name: "evil.example.com"},
		},
	}
	val, ok := getEventFieldValue(event, "dns.question.name")
	if !ok || val != "evil.example.com" {
		t.Errorf("expected evil.example.com, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_NDRDetectionName(t *testing.T) {
	event := &common.ECSEvent{
		NDR: &common.NDRFields{
			Detection: &common.NDRDetection{Name: "C2 Beacon"},
		},
	}
	val, ok := getEventFieldValue(event, "ndr.detection.name")
	if !ok || val != "C2 Beacon" {
		t.Errorf("expected C2 Beacon, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_FileHashSHA256(t *testing.T) {
	event := &common.ECSEvent{
		File: &common.FileFields{
			Hash: &common.HashFields{SHA256: "abc123"},
		},
	}
	val, ok := getEventFieldValue(event, "file.hash.sha256")
	if !ok || val != "abc123" {
		t.Errorf("expected abc123, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_TLSClientJA3(t *testing.T) {
	event := &common.ECSEvent{
		TLS: &common.TLSFields{
			Client: &common.TLSClientFields{JA3: "fingerprint123"},
		},
	}
	val, ok := getEventFieldValue(event, "tls.client.ja3")
	if !ok || val != "fingerprint123" {
		t.Errorf("expected fingerprint123, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_UserName(t *testing.T) {
	event := &common.ECSEvent{
		User: &common.UserFields{Name: "admin"},
	}
	val, ok := getEventFieldValue(event, "user.name")
	if !ok || val != "admin" {
		t.Errorf("expected admin, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_ProcessPID(t *testing.T) {
	event := &common.ECSEvent{
		Process: &common.ProcessFields{PID: 1234},
	}
	val, ok := getEventFieldValue(event, "process.pid")
	if !ok || val != 1234 {
		t.Errorf("expected 1234, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_SourceUser(t *testing.T) {
	event := &common.ECSEvent{
		Source: &common.EndpointFields{
			User: &common.UserFields{Name: "src_user"},
		},
	}
	val, ok := getEventFieldValue(event, "source.user.name")
	if !ok || val != "src_user" {
		t.Errorf("expected src_user, got %v (ok=%v)", val, ok)
	}
}

func TestGetEventFieldValue_ObserverName(t *testing.T) {
	event := &common.ECSEvent{
		Observer: &common.ObserverFields{Name: "firewall-01"},
	}
	val, ok := getEventFieldValue(event, "observer.name")
	if !ok || val != "firewall-01" {
		t.Errorf("expected firewall-01, got %v (ok=%v)", val, ok)
	}
}

// --- Condition parser tests ---

func TestParseCondition_SimpleRef(t *testing.T) {
	expr, err := parseCondition("selection")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ref, ok := expr.(*ConditionRef)
	if !ok {
		t.Fatalf("expected ConditionRef, got %T", expr)
	}
	if ref.Name != "selection" {
		t.Errorf("expected 'selection', got %q", ref.Name)
	}
	// Test evaluation.
	if !expr.Eval(map[string]bool{"selection": true}) {
		t.Error("expected true")
	}
	if expr.Eval(map[string]bool{"selection": false}) {
		t.Error("expected false")
	}
}

func TestParseCondition_AndNot(t *testing.T) {
	expr, err := parseCondition("selection and not filter")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// selection=true, filter=false → true.
	if !expr.Eval(map[string]bool{"selection": true, "filter": false}) {
		t.Error("expected true for selection=T, filter=F")
	}
	// selection=true, filter=true → false.
	if expr.Eval(map[string]bool{"selection": true, "filter": true}) {
		t.Error("expected false for selection=T, filter=T")
	}
	// selection=false → false.
	if expr.Eval(map[string]bool{"selection": false, "filter": false}) {
		t.Error("expected false for selection=F")
	}
}

func TestParseCondition_Or(t *testing.T) {
	expr, err := parseCondition("sel1 or sel2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expr.Eval(map[string]bool{"sel1": true, "sel2": false}) {
		t.Error("expected true for sel1=T")
	}
	if !expr.Eval(map[string]bool{"sel1": false, "sel2": true}) {
		t.Error("expected true for sel2=T")
	}
	if expr.Eval(map[string]bool{"sel1": false, "sel2": false}) {
		t.Error("expected false for both=F")
	}
}

func TestParseCondition_Parentheses(t *testing.T) {
	expr, err := parseCondition("(sel1 or sel2) and not filter")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// (T or F) and not F → true
	if !expr.Eval(map[string]bool{"sel1": true, "sel2": false, "filter": false}) {
		t.Error("expected true")
	}
	// (T or F) and not T → false
	if expr.Eval(map[string]bool{"sel1": true, "sel2": false, "filter": true}) {
		t.Error("expected false")
	}
}

func TestParseCondition_ComplexNested(t *testing.T) {
	expr, err := parseCondition("(sel1 and sel2) or (sel3 and not sel4)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// (T and T) or (...) → true
	if !expr.Eval(map[string]bool{"sel1": true, "sel2": true, "sel3": false, "sel4": false}) {
		t.Error("expected true: left branch")
	}
	// (F and F) or (T and not F) → true
	if !expr.Eval(map[string]bool{"sel1": false, "sel2": false, "sel3": true, "sel4": false}) {
		t.Error("expected true: right branch")
	}
	// (F and F) or (T and not T) → false
	if expr.Eval(map[string]bool{"sel1": false, "sel2": false, "sel3": true, "sel4": true}) {
		t.Error("expected false: both branches fail")
	}
}

func TestParseCondition_CaseInsensitiveKeywords(t *testing.T) {
	expr, err := parseCondition("selection AND NOT filter")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expr.Eval(map[string]bool{"selection": true, "filter": false}) {
		t.Error("expected true with uppercase keywords")
	}
}

func TestParseCondition_Empty(t *testing.T) {
	_, err := parseCondition("")
	if err == nil {
		t.Error("expected error for empty condition")
	}
}

func TestParseCondition_UnbalancedParen(t *testing.T) {
	_, err := parseCondition("(selection and filter")
	if err == nil {
		t.Error("expected error for unbalanced paren")
	}
}

func TestParseCondition_OneOfUnsupported(t *testing.T) {
	_, err := parseCondition("1 of selection*")
	if err == nil {
		t.Error("expected error for '1 of' syntax")
	}
}

func TestParseCondition_AllOfUnsupported(t *testing.T) {
	_, err := parseCondition("all of selection*")
	if err == nil {
		t.Error("expected error for 'all of' syntax")
	}
}

func TestParseCondition_DoubleNot(t *testing.T) {
	expr, err := parseCondition("not not selection")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Double negation → same as selection.
	if !expr.Eval(map[string]bool{"selection": true}) {
		t.Error("expected true for double-not")
	}
	if expr.Eval(map[string]bool{"selection": false}) {
		t.Error("expected false for double-not")
	}
}

func TestParseCondition_ExtraToken(t *testing.T) {
	_, err := parseCondition("selection extra")
	if err == nil {
		t.Error("expected error for extra token")
	}
}

// --- tokenizeCondition tests ---

func TestTokenizeCondition(t *testing.T) {
	tokens := tokenizeCondition("(sel1 or sel2) and not filter_internal")
	expected := []string{"(", "sel1", "or", "sel2", ")", "and", "not", "filter_internal"}
	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(tokens), tokens)
	}
	for i := range expected {
		if tokens[i] != expected[i] {
			t.Errorf("token %d: expected %q, got %q", i, expected[i], tokens[i])
		}
	}
}

// --- CompileDetection tests ---

func TestCompileDetection_Nil(t *testing.T) {
	_, err := CompileDetection(nil)
	if err == nil {
		t.Error("expected error for nil detection")
	}
}

func TestCompileDetection_InvalidCondition(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"test"}},
			}}},
		},
		Condition: "",
	}
	_, err := CompileDetection(det)
	if err == nil {
		t.Error("expected error for empty condition")
	}
}

func TestCompileDetection_InvalidRegex(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Modifiers: []string{"re"}, Values: []interface{}{"[invalid"}},
			}}},
		},
		Condition: "selection",
	}
	_, err := CompileDetection(det)
	if err == nil {
		t.Error("expected error for invalid regex in selection")
	}
}

// --- EvaluateEvent integration tests ---

func TestEvaluateEvent_SimpleMatch(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"scanner_match"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "scanner_match"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match")
	}

	event2 := &common.ECSEvent{
		Event: &common.EventFields{Action: "other"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match")
	}
}

func TestEvaluateEvent_CaseInsensitiveMatch(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"Scanner_Match"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "scanner_match"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected case-insensitive match")
	}
}

func TestEvaluateEvent_ContainsModifier(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Modifiers: []string{"contains"}, Values: []interface{}{"remote"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "remote_thread"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected contains match")
	}

	event2 := &common.ECSEvent{
		Event: &common.EventFields{Action: "local_process"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match for non-containing value")
	}
}

func TestEvaluateEvent_MultipleValues_OR(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Modifiers: []string{"contains"}, Values: []interface{}{
					"remote", "psexec", "lateral",
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	for _, action := range []string{"remote_thread", "psexec_service", "lateral_move"} {
		event := &common.ECSEvent{
			Event: &common.EventFields{Action: action},
		}
		if !EvaluateEvent(compiled, event) {
			t.Errorf("expected match for %q", action)
		}
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "normal_activity"},
	}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for unrelated action")
	}
}

func TestEvaluateEvent_MultipleFields_AND(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"scan_result"}},
				{Field: "av.scan.result", Values: []interface{}{"malicious"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Both fields present → match.
	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "scan_result"},
		AV:    &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match with both fields")
	}

	// Only one field → no match.
	event2 := &common.ECSEvent{
		Event: &common.EventFields{Action: "scan_result"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match with missing av.scan.result")
	}
}

func TestEvaluateEvent_SelectionAndNotFilter(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.category", Values: []interface{}{"network"}},
				{Field: "network.direction", Values: []interface{}{"outbound"}},
			}}},
			"filter_internal": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "destination.ip", Modifiers: []string{"cidr"}, Values: []interface{}{
					"10.0.0.0/8",
					"172.16.0.0/12",
					"192.168.0.0/16",
				}},
			}}},
		},
		Condition: "selection and not filter_internal",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// External destination → should match.
	event := &common.ECSEvent{
		Event:       &common.EventFields{Category: []string{"network"}},
		Network:     &common.NetworkFields{Direction: "outbound"},
		Destination: &common.EndpointFields{IP: "8.8.8.8"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match for external destination")
	}

	// Internal destination → filter_internal matches, so result is false.
	event2 := &common.ECSEvent{
		Event:       &common.EventFields{Category: []string{"network"}},
		Network:     &common.NetworkFields{Direction: "outbound"},
		Destination: &common.EndpointFields{IP: "10.1.2.3"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match for internal destination (filtered)")
	}

	// Not network → selection fails.
	event3 := &common.ECSEvent{
		Event:       &common.EventFields{Category: []string{"process"}},
		Network:     &common.NetworkFields{Direction: "outbound"},
		Destination: &common.EndpointFields{IP: "8.8.8.8"},
	}
	if EvaluateEvent(compiled, event3) {
		t.Error("expected no match for non-network category")
	}
}

func TestEvaluateEvent_NilEvent(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"test"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if EvaluateEvent(compiled, nil) {
		t.Error("expected false for nil event")
	}
}

func TestEvaluateEvent_NilCompiled(t *testing.T) {
	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "test"},
	}
	if EvaluateEvent(nil, event) {
		t.Error("expected false for nil compiled detection")
	}
}

func TestEvaluateEvent_EventCategorySliceMatch(t *testing.T) {
	// event.category is []string — the matcher should check if any element matches.
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.category", Values: []interface{}{"network"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Category: []string{"process", "network"}},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match: 'network' is in category slice")
	}

	event2 := &common.ECSEvent{
		Event: &common.EventFields{Category: []string{"process", "file"}},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match: 'network' not in category slice")
	}
}

func TestEvaluateEvent_RegexModifier(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "process.command_line", Modifiers: []string{"re"}, Values: []interface{}{
					`(?i)powershell.*-enc`,
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Process: &common.ProcessFields{CommandLine: "PowerShell.exe -Enc dGVzdA=="},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected regex match")
	}

	event2 := &common.ECSEvent{
		Process: &common.ProcessFields{CommandLine: "cmd.exe /c dir"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no regex match")
	}
}

func TestEvaluateEvent_ContainsAllModifier(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "process.command_line", Modifiers: []string{"contains", "all"}, Values: []interface{}{
					"powershell", "-enc",
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Process: &common.ProcessFields{CommandLine: "powershell.exe -enc abc123"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match: contains both powershell and -enc")
	}

	event2 := &common.ECSEvent{
		Process: &common.ProcessFields{CommandLine: "powershell.exe -command dir"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match: contains powershell but not -enc")
	}
}

func TestEvaluateEvent_MultipleEventMatchers_OR(t *testing.T) {
	// A selection with multiple event matchers (list-of-maps) means OR.
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {
				{FieldMatchers: []SigmaFieldMatcher{
					{Field: "event.action", Values: []interface{}{"alert_1"}},
				}},
				{FieldMatchers: []SigmaFieldMatcher{
					{Field: "event.action", Values: []interface{}{"alert_2"}},
				}},
			},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	for _, action := range []string{"alert_1", "alert_2"} {
		event := &common.ECSEvent{
			Event: &common.EventFields{Action: action},
		}
		if !EvaluateEvent(compiled, event) {
			t.Errorf("expected match for %q", action)
		}
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "alert_3"},
	}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for alert_3")
	}
}

func TestEvaluateEvent_MultipleSelections_OR(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"sel1": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"login"}},
			}}},
			"sel2": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"logout"}},
			}}},
		},
		Condition: "sel1 or sel2",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	for _, action := range []string{"login", "logout"} {
		event := &common.ECSEvent{
			Event: &common.EventFields{Action: action},
		}
		if !EvaluateEvent(compiled, event) {
			t.Errorf("expected match for %q", action)
		}
	}
}

// --- Test against real project Sigma rules ---

func TestEvaluateEvent_EDRBehavioralDetection(t *testing.T) {
	// Parse the EDR behavioral detection rule from edr_av_behavioral_static_confirmation.yml
	yamlStr := `
title: EDR Behavioral Detection
id: a1b2c3d4-e5f6-4a7b-8c9d-000000000001
status: experimental
logsource:
  product: akeso_edr
detection:
  selection:
    event.action|contains:
      - scanner_match
      - rule_engine_alert
      - amsi_detection
    event.kind: alert
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	compiled, err := CompileDetection(rules[0].Detection)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Matching event.
	event := &common.ECSEvent{
		Event: &common.EventFields{
			Action: "scanner_match_detected",
			Kind:   "alert",
		},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match for scanner_match + alert")
	}

	// Action matches but kind doesn't → no match (AND of fields).
	event2 := &common.ECSEvent{
		Event: &common.EventFields{
			Action: "scanner_match_detected",
			Kind:   "event",
		},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match: kind=event, not alert")
	}
}

func TestEvaluateEvent_OutboundDataTransferWithFilter(t *testing.T) {
	// Rule from full_chain_attack_lifecycle.yml — Stage 4.
	yamlStr := `
title: EDR Outbound Data Transfer
id: e5f6a7b8-c9d0-4e1f-2a3b-000000000004
status: experimental
logsource:
  product: akeso_edr
detection:
  selection:
    event.category: network
    network.direction: outbound
  filter_internal:
    destination.ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and not filter_internal
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	compiled, err := CompileDetection(rules[0].Detection)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	tests := []struct {
		name   string
		destIP string
		want   bool
	}{
		{"external IP", "203.0.113.50", true},
		{"10.x internal", "10.1.2.3", false},
		{"172.16.x internal", "172.16.0.1", false},
		{"192.168.x internal", "192.168.1.1", false},
		{"172.15.x external", "172.15.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &common.ECSEvent{
				Event:       &common.EventFields{Category: []string{"network"}},
				Network:     &common.NetworkFields{Direction: "outbound"},
				Destination: &common.EndpointFields{IP: tt.destIP},
			}
			got := EvaluateEvent(compiled, event)
			if got != tt.want {
				t.Errorf("destIP=%s: got %v, want %v", tt.destIP, got, tt.want)
			}
		})
	}
}

func TestEvaluateEvent_DLPSensitiveDataAccess(t *testing.T) {
	yamlStr := `
title: DLP Sensitive Data Access
id: e5f6a7b8-c9d0-4e1f-2a3b-000000000003
status: experimental
logsource:
  product: akeso_dlp
detection:
  selection:
    dlp.classification:
      - confidential
      - restricted
    event.action|contains:
      - violation
      - audit
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	compiled, err := CompileDetection(rules[0].Detection)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Match: confidential + violation.
	event := &common.ECSEvent{
		DLP:   &common.DLPFields{Classification: "confidential"},
		Event: &common.EventFields{Action: "policy_violation"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match for confidential + violation")
	}

	// Match: restricted + audit.
	event2 := &common.ECSEvent{
		DLP:   &common.DLPFields{Classification: "restricted"},
		Event: &common.EventFields{Action: "data_audit"},
	}
	if !EvaluateEvent(compiled, event2) {
		t.Error("expected match for restricted + audit")
	}

	// No match: public + violation.
	event3 := &common.ECSEvent{
		DLP:   &common.DLPFields{Classification: "public"},
		Event: &common.EventFields{Action: "policy_violation"},
	}
	if EvaluateEvent(compiled, event3) {
		t.Error("expected no match for public classification")
	}
}

func TestEvaluateEvent_AVDroppedTool(t *testing.T) {
	yamlStr := `
title: AV Dropped Tool Detection
id: e5f6a7b8-c9d0-4e1f-2a3b-000000000002
status: experimental
logsource:
  product: akeso_av
detection:
  selection:
    av.scan.result:
      - malicious
      - suspicious
    event.action:
      - scan_result
      - realtime_block
  condition: selection
`
	rules, err := ParseSigmaYAML(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	compiled, err := CompileDetection(rules[0].Detection)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Match: malicious + scan_result.
	event := &common.ECSEvent{
		AV:    &common.AVFields{Scan: &common.AVScan{Result: "malicious"}},
		Event: &common.EventFields{Action: "scan_result"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match")
	}

	// Match: suspicious + realtime_block.
	event2 := &common.ECSEvent{
		AV:    &common.AVFields{Scan: &common.AVScan{Result: "suspicious"}},
		Event: &common.EventFields{Action: "realtime_block"},
	}
	if !EvaluateEvent(compiled, event2) {
		t.Error("expected match")
	}

	// No match: clean + scan_result.
	event3 := &common.ECSEvent{
		AV:    &common.AVFields{Scan: &common.AVScan{Result: "clean"}},
		Event: &common.EventFields{Action: "scan_result"},
	}
	if EvaluateEvent(compiled, event3) {
		t.Error("expected no match for clean scan result")
	}
}

// --- Adversarial evaluator tests ---

func TestEvaluateEvent_MissingField(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "nonexistent.field.path", Values: []interface{}{"value"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "test"},
	}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for nonexistent field")
	}
}

func TestEvaluateEvent_EmptyEvent(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Values: []interface{}{"test"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Completely empty event.
	event := &common.ECSEvent{}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for empty event")
	}
}

func TestEvaluateEvent_IntFieldComparison(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.severity", Values: []interface{}{4}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Severity: 4},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match for int field")
	}

	event2 := &common.ECSEvent{
		Event: &common.EventFields{Severity: 3},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match for different int")
	}
}

func TestEvaluateEvent_SelectionNotInCondition(t *testing.T) {
	// A selection referenced in condition but not defined → always false.
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{},
		Condition:  "missing_selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Event: &common.EventFields{Action: "test"},
	}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for undefined selection")
	}
}

func TestEvaluateEvent_StartswithModifier(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "process.executable", Modifiers: []string{"startswith"}, Values: []interface{}{
					"C:\\Windows\\Temp\\",
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Process: &common.ProcessFields{Executable: "C:\\Windows\\Temp\\malware.exe"},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match for startswith")
	}

	event2 := &common.ECSEvent{
		Process: &common.ProcessFields{Executable: "C:\\Program Files\\app.exe"},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match for startswith")
	}
}

func TestEvaluateEvent_EndswithModifier(t *testing.T) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "file.name", Modifiers: []string{"endswith"}, Values: []interface{}{
					".ps1", ".vbs", ".bat",
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	for _, name := range []string{"script.ps1", "SCRIPT.VBS", "run.bat"} {
		event := &common.ECSEvent{
			File: &common.FileFields{Name: name},
		}
		if !EvaluateEvent(compiled, event) {
			t.Errorf("expected match for %q", name)
		}
	}

	event := &common.ECSEvent{
		File: &common.FileFields{Name: "readme.txt"},
	}
	if EvaluateEvent(compiled, event) {
		t.Error("expected no match for .txt")
	}
}

func TestEvaluateEvent_HostIPSliceWithCIDR(t *testing.T) {
	// host.ip is []string — CIDR matching should work on each element.
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "host.ip", Modifiers: []string{"cidr"}, Values: []interface{}{
					"10.0.0.0/8",
				}},
			}}},
		},
		Condition: "selection",
	}
	compiled, err := CompileDetection(det)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	event := &common.ECSEvent{
		Host: &common.HostFields{IP: []string{"192.168.1.1", "10.0.0.5"}},
	}
	if !EvaluateEvent(compiled, event) {
		t.Error("expected match: 10.0.0.5 is in 10.0.0.0/8")
	}

	event2 := &common.ECSEvent{
		Host: &common.HostFields{IP: []string{"192.168.1.1", "172.16.0.1"}},
	}
	if EvaluateEvent(compiled, event2) {
		t.Error("expected no match: no IP in 10.0.0.0/8")
	}
}

// --- Benchmark ---

func BenchmarkEvaluateEvent_SimpleMatch(b *testing.B) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.action", Modifiers: []string{"contains"}, Values: []interface{}{
					"remote", "psexec", "lateral",
				}},
				{Field: "event.kind", Values: []interface{}{"alert"}},
			}}},
		},
		Condition: "selection",
	}
	compiled, _ := CompileDetection(det)
	event := &common.ECSEvent{
		Event: &common.EventFields{
			Action: "remote_thread_injection",
			Kind:   "alert",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EvaluateEvent(compiled, event)
	}
}

func BenchmarkEvaluateEvent_FilteredCIDR(b *testing.B) {
	det := &SigmaDetection{
		Selections: map[string]SigmaSelection{
			"selection": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "event.category", Values: []interface{}{"network"}},
				{Field: "network.direction", Values: []interface{}{"outbound"}},
			}}},
			"filter_internal": {{FieldMatchers: []SigmaFieldMatcher{
				{Field: "destination.ip", Modifiers: []string{"cidr"}, Values: []interface{}{
					"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
				}},
			}}},
		},
		Condition: "selection and not filter_internal",
	}
	compiled, _ := CompileDetection(det)
	event := &common.ECSEvent{
		Event:       &common.EventFields{Category: []string{"network"}},
		Network:     &common.NetworkFields{Direction: "outbound"},
		Destination: &common.EndpointFields{IP: "203.0.113.50"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EvaluateEvent(compiled, event)
	}
}
