package correlate

import (
	"fmt"
	"log"
	"sync"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// Alert is returned when an ECS event matches a Sigma rule's detection logic.
type Alert struct {
	RuleID      string
	Title       string
	Level       string
	Tags        []string
	Description string
	Author      string
	Ruleset     string // "sigma_single" or "sigma_correlation"
	Event       *common.ECSEvent
}

// EngineStats provides observability into the rule engine's state.
type EngineStats struct {
	TotalRulesLoaded int
	RulesCompiled    int
	RulesSkipped     int
	CompileErrors    []error
	BucketCount      int
}

// logsourceKey is a hashable triple for grouping rules by logsource.
type logsourceKey struct {
	Category string
	Product  string
	Service  string
}

// compiledRule bundles a parsed rule with its pre-compiled detection.
type compiledRule struct {
	rule     *SigmaRule
	compiled *CompiledDetection
}

// ruleGroup holds all compiled rules sharing a logsource triple,
// along with the pre-resolved ECS conditions for that logsource.
type ruleGroup struct {
	conditions []map[string]string // resolved logsource → ECS filter conditions
	rules      []*compiledRule
}

// RuleEngine evaluates incoming ECS events against pre-compiled Sigma rules.
// After initialization via NewRuleEngine, all fields are read-only.
// Evaluate is safe for concurrent use by multiple goroutines.
type RuleEngine struct {
	groups        map[logsourceKey]*ruleGroup
	wildcardGroup *ruleGroup // rules with empty logsource (match all events)
	stats         EngineStats
}

// NewRuleEngine creates a rule engine from a registry of parsed rules and a
// logsource map. It pre-compiles all single-event rule detections and groups
// them by logsource for efficient routing.
//
// Rules that fail to compile or have unmapped logsources are skipped with
// warnings logged. Correlation rules are excluded (handled separately in P5).
func NewRuleEngine(registry *RuleRegistry, lsMap *LogsourceMap) *RuleEngine {
	engine := &RuleEngine{
		groups: make(map[logsourceKey]*ruleGroup),
	}

	singleRules := registry.SingleEventRules()
	engine.stats.TotalRulesLoaded = len(singleRules)

	for _, rule := range singleRules {
		// Skip metadata-only documents (no detection block).
		if rule.Detection == nil {
			engine.stats.RulesSkipped++
			continue
		}

		// Pre-compile the detection logic.
		compiled, err := CompileDetection(rule.Detection)
		if err != nil {
			compileErr := fmt.Errorf("rule %q (%s): %w", rule.Title, rule.ID, err)
			engine.stats.CompileErrors = append(engine.stats.CompileErrors, compileErr)
			engine.stats.RulesSkipped++
			log.Printf("[rule-engine] skipping rule %q: compile error: %v", rule.Title, err)
			continue
		}

		cr := &compiledRule{rule: rule, compiled: compiled}
		key := logsourceKey{
			Category: rule.Logsource.Category,
			Product:  rule.Logsource.Product,
			Service:  rule.Logsource.Service,
		}

		// Wildcard: rule with no logsource fields matches all events.
		if key.Category == "" && key.Product == "" && key.Service == "" {
			if engine.wildcardGroup == nil {
				engine.wildcardGroup = &ruleGroup{}
			}
			engine.wildcardGroup.rules = append(engine.wildcardGroup.rules, cr)
			engine.stats.RulesCompiled++
			continue
		}

		// Resolve logsource to ECS conditions.
		conditions := lsMap.ResolveAll(key.Category, key.Product, key.Service)
		if len(conditions) == 0 {
			engine.stats.RulesSkipped++
			log.Printf("[rule-engine] skipping rule %q: unmapped logsource (category=%q, product=%q, service=%q)",
				rule.Title, key.Category, key.Product, key.Service)
			continue
		}

		// Add to existing group or create new one.
		grp, exists := engine.groups[key]
		if !exists {
			grp = &ruleGroup{conditions: conditions}
			engine.groups[key] = grp
		}
		grp.rules = append(grp.rules, cr)
		engine.stats.RulesCompiled++
	}

	engine.stats.BucketCount = len(engine.groups)
	if engine.wildcardGroup != nil {
		engine.stats.BucketCount++
	}

	return engine
}

// Evaluate routes an ECS event through the rule engine and returns any alerts.
// Returns nil if no rules match. Safe for concurrent use.
func (e *RuleEngine) Evaluate(event *common.ECSEvent) []Alert {
	if event == nil {
		return nil
	}

	var alerts []Alert

	// Check each logsource bucket.
	for _, grp := range e.groups {
		if !groupMatchesEvent(grp, event) {
			continue
		}
		alerts = evaluateGroup(grp, event, alerts)
	}

	// Wildcard rules always evaluate.
	if e.wildcardGroup != nil {
		alerts = evaluateGroup(e.wildcardGroup, event, alerts)
	}

	return alerts
}

// groupMatchesEvent checks if an event satisfies ANY of the group's logsource conditions.
func groupMatchesEvent(grp *ruleGroup, event *common.ECSEvent) bool {
	for _, conds := range grp.conditions {
		if MatchesEvent(conds, event) {
			return true
		}
	}
	return false
}

// evaluateGroup evaluates all rules in a group against the event,
// appending any alerts to the provided slice.
func evaluateGroup(grp *ruleGroup, event *common.ECSEvent, alerts []Alert) []Alert {
	for _, cr := range grp.rules {
		if EvaluateEvent(cr.compiled, event) {
			alerts = append(alerts, Alert{
				RuleID:      cr.rule.ID,
				Title:       cr.rule.Title,
				Level:       cr.rule.Level,
				Tags:        cr.rule.Tags,
				Description: cr.rule.Description,
				Author:      cr.rule.Author,
				Ruleset:     "sigma_single",
				Event:       event,
			})
		}
	}
	return alerts
}

// Stats returns engine statistics for observability.
func (e *RuleEngine) Stats() EngineStats {
	return e.stats
}

// EvaluateConcurrent evaluates a batch of events concurrently, returning
// all alerts. Uses a worker pool sized to numWorkers.
func (e *RuleEngine) EvaluateConcurrent(events []*common.ECSEvent, numWorkers int) []Alert {
	if len(events) == 0 || numWorkers <= 0 {
		return nil
	}
	if numWorkers > len(events) {
		numWorkers = len(events)
	}

	var mu sync.Mutex
	var allAlerts []Alert

	ch := make(chan *common.ECSEvent, len(events))
	for _, ev := range events {
		ch <- ev
	}
	close(ch)

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for ev := range ch {
				alerts := e.Evaluate(ev)
				if len(alerts) > 0 {
					mu.Lock()
					allAlerts = append(allAlerts, alerts...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	return allAlerts
}
