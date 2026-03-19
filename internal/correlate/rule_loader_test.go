package correlate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// writeRule writes a Sigma rule YAML file to the given directory.
func writeRule(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}
}

// writeLogsourceMap writes a logsource map YAML file to the given path.
func writeLogsourceMap(t *testing.T, path string) {
	t.Helper()
	content := `mappings:
  - logsource:
      category: process_creation
    conditions:
      event.category: process
      event.type: start
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write logsource map: %v", err)
	}
}

const testRule1 = `title: Test Rule 1
id: test-rule-001
status: test
logsource:
    category: process_creation
detection:
    selection:
        process.name: malware.exe
    condition: selection
level: high
`

const testRule2 = `title: Test Rule 2
id: test-rule-002
status: test
logsource:
    category: process_creation
detection:
    selection:
        process.name: ransomware.exe
    condition: selection
level: critical
`

func TestNewRuleLoaderEmptyDir(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)
	stats := loader.Stats()

	if stats.RulesCompiled != 0 {
		t.Errorf("expected 0 compiled rules with empty dir, got %d", stats.RulesCompiled)
	}
}

func TestNewRuleLoaderWithRules(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)
	stats := loader.Stats()

	if stats.RulesCompiled != 1 {
		t.Errorf("expected 1 compiled rule, got %d", stats.RulesCompiled)
	}
}

func TestRuleLoaderEvaluateMatchesRule(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	// Event that should match testRule1 (process.name == "malware.exe").
	event := &common.ECSEvent{
		Timestamp: time.Now(),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			Name: "malware.exe",
		},
	}

	alerts := loader.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "test-rule-001" {
		t.Errorf("alert rule ID = %q, want 'test-rule-001'", alerts[0].RuleID)
	}
}

func TestRuleLoaderEvaluateNoMatch(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	event := &common.ECSEvent{
		Timestamp: time.Now(),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			Name: "notepad.exe",
		},
	}

	alerts := loader.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for non-matching event, got %d", len(alerts))
	}
}

func TestRuleLoaderReload(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	stats := loader.Stats()
	if stats.RulesCompiled != 1 {
		t.Fatalf("initial: expected 1 rule, got %d", stats.RulesCompiled)
	}

	// Add a second rule and reload.
	writeRule(t, dir, "rule2.yml", testRule2)
	newStats, err := loader.Reload()
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}

	if newStats.RulesCompiled != 2 {
		t.Errorf("after reload: expected 2 rules, got %d", newStats.RulesCompiled)
	}

	// Verify the new rule is active.
	event := &common.ECSEvent{
		Timestamp: time.Now(),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			Name: "ransomware.exe",
		},
	}
	alerts := loader.Evaluate(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for new rule, got %d", len(alerts))
	}
	if alerts[0].RuleID != "test-rule-002" {
		t.Errorf("alert rule ID = %q, want 'test-rule-002'", alerts[0].RuleID)
	}
}

func TestRuleLoaderReloadRemovedRule(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)
	writeRule(t, dir, "rule2.yml", testRule2)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	stats := loader.Stats()
	if stats.RulesCompiled != 2 {
		t.Fatalf("initial: expected 2 rules, got %d", stats.RulesCompiled)
	}

	// Remove rule2 and reload.
	os.Remove(filepath.Join(dir, "rule2.yml"))
	newStats, _ := loader.Reload()

	if newStats.RulesCompiled != 1 {
		t.Errorf("after removal: expected 1 rule, got %d", newStats.RulesCompiled)
	}

	// Verify the removed rule no longer fires.
	event := &common.ECSEvent{
		Timestamp: time.Now(),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			Name: "ransomware.exe",
		},
	}
	alerts := loader.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for removed rule, got %d", len(alerts))
	}
}

func TestRuleLoaderFileWatcher(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	// Use a short poll interval for testing.
	loader := NewRuleLoader(dir, lsPath, 100*time.Millisecond)
	loader.StartWatcher()
	defer loader.Stop()

	stats := loader.Stats()
	if stats.RulesCompiled != 1 {
		t.Fatalf("initial: expected 1 rule, got %d", stats.RulesCompiled)
	}

	// Add a rule and wait for the watcher to pick it up.
	writeRule(t, dir, "rule2.yml", testRule2)

	// Poll until the reload is detected (up to 2s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if loader.Stats().RulesCompiled == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if loader.Stats().RulesCompiled != 2 {
		t.Errorf("watcher did not detect new rule: expected 2 compiled, got %d", loader.Stats().RulesCompiled)
	}
}

func TestRuleLoaderFileWatcherDetectsRemoval(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)
	writeRule(t, dir, "rule2.yml", testRule2)

	loader := NewRuleLoader(dir, lsPath, 100*time.Millisecond)
	loader.StartWatcher()
	defer loader.Stop()

	if loader.Stats().RulesCompiled != 2 {
		t.Fatalf("initial: expected 2 rules, got %d", loader.Stats().RulesCompiled)
	}

	// Remove a rule and wait for the watcher to detect it.
	os.Remove(filepath.Join(dir, "rule2.yml"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if loader.Stats().RulesCompiled == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if loader.Stats().RulesCompiled != 1 {
		t.Errorf("watcher did not detect rule removal: expected 1 compiled, got %d", loader.Stats().RulesCompiled)
	}
}

func TestRuleLoaderStop(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)

	loader := NewRuleLoader(dir, lsPath, 100*time.Millisecond)
	loader.StartWatcher()

	// Stop should return without blocking.
	done := make(chan struct{})
	go func() {
		loader.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s")
	}
}

func TestRuleLoaderReloadHandlerPost(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/reload", nil)
	w := httptest.NewRecorder()
	loader.ReloadHandler()(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("response status = %v, want 'ok'", resp["status"])
	}
	if resp["rules_compiled"] != float64(1) {
		t.Errorf("rules_compiled = %v, want 1", resp["rules_compiled"])
	}
}

func TestRuleLoaderReloadHandlerGetRejected(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/reload", nil)
	w := httptest.NewRecorder()
	loader.ReloadHandler()(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestRuleLoaderDefaultInterval(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)

	// Passing 0 should use default (10s).
	loader := NewRuleLoader(dir, lsPath, 0)
	if loader.reloadInterval != 10*time.Second {
		t.Errorf("default interval = %v, want 10s", loader.reloadInterval)
	}
}

func TestRuleLoaderChecksumStability(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	// Same directory state should produce the same checksum.
	c1 := loader.computeChecksum()
	c2 := loader.computeChecksum()
	if c1 != c2 {
		t.Error("checksum should be stable for unchanged directory")
	}
}

func TestRuleLoaderChecksumChangesOnFileAdd(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)
	c1 := loader.computeChecksum()

	writeRule(t, dir, "rule2.yml", testRule2)
	c2 := loader.computeChecksum()

	if c1 == c2 {
		t.Error("checksum should change when a file is added")
	}
}

func TestRuleLoaderChecksumChangesOnFileRemove(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)
	writeRule(t, dir, "rule1.yml", testRule1)
	writeRule(t, dir, "rule2.yml", testRule2)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)
	c1 := loader.computeChecksum()

	os.Remove(filepath.Join(dir, "rule2.yml"))
	c2 := loader.computeChecksum()

	if c1 == c2 {
		t.Error("checksum should change when a file is removed")
	}
}

func TestRuleLoaderSatisfiesRuleEvaluator(t *testing.T) {
	dir := t.TempDir()
	lsPath := filepath.Join(dir, "logsource_map.yaml")
	writeLogsourceMap(t, lsPath)

	loader := NewRuleLoader(dir, lsPath, 10*time.Second)

	// Compile-time check that RuleLoader satisfies RuleEvaluator.
	var _ RuleEvaluator = loader
}

func TestRuleEngineSatisfiesRuleEvaluator(t *testing.T) {
	// Compile-time check that *RuleEngine also satisfies RuleEvaluator.
	var _ RuleEvaluator = (*RuleEngine)(nil)
}
