package correlate

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CorrelationType identifies the correlation strategy.
type CorrelationType string

const (
	CorrelationEventCount CorrelationType = "event_count"
	CorrelationValueCount CorrelationType = "value_count"
	CorrelationTemporal   CorrelationType = "temporal"
)

// ConditionOp is the comparison operator for correlation thresholds.
type ConditionOp string

const (
	OpGTE ConditionOp = "gte"
	OpGT  ConditionOp = "gt"
	OpLTE ConditionOp = "lte"
	OpLT  ConditionOp = "lt"
	OpEQ  ConditionOp = "eq"
)

// CorrelationRule is the fully validated, typed representation of a Sigma
// correlation rule. It is produced by ParseCorrelationRule from a SigmaRule
// that has Type == "correlation" (or one of the explicit subtypes).
type CorrelationRule struct {
	// Metadata (inherited from the SigmaRule).
	ID          string
	Title       string
	Level       string
	Tags        []string
	Description string
	Author      string

	// Correlation type: event_count, value_count, or temporal.
	Type CorrelationType

	// Rules lists the IDs of single-event rules that feed this correlation.
	Rules []string

	// GroupBy lists the ECS fields to partition events by (e.g. "user.name").
	GroupBy []string

	// Timespan is the sliding window for aggregation/matching.
	Timespan time.Duration

	// Condition is the comparison operator (gte, gt, lte, lt, eq).
	Condition ConditionOp

	// Threshold is the numeric value the condition is compared against.
	Threshold int

	// Ordered is true for temporal correlations requiring events in sequence.
	Ordered bool

	// ValueField is the ECS field whose distinct values are counted
	// (only used for value_count correlations).
	ValueField string
}

// ParseCorrelationRule converts a SigmaRule (with Type == "correlation" or an
// explicit subtype) into a validated CorrelationRule. Returns a clear error
// if required fields are missing or values are invalid.
func ParseCorrelationRule(rule *SigmaRule) (*CorrelationRule, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil rule")
	}

	cr := &CorrelationRule{
		ID:          rule.ID,
		Title:       rule.Title,
		Level:       rule.Level,
		Tags:        rule.Tags,
		Description: rule.Description,
		Author:      rule.Author,
		Rules:       rule.CorrelationRules,
		GroupBy:     rule.GroupBy,
		Ordered:     rule.Ordered,
		ValueField:  rule.ValueField,
	}

	// Determine correlation type.
	corrType, err := resolveCorrelationType(rule)
	if err != nil {
		return nil, fmt.Errorf("rule %q (%s): %w", rule.Title, rule.ID, err)
	}
	cr.Type = corrType

	// Parse timespan.
	if rule.Timespan == "" {
		return nil, fmt.Errorf("rule %q (%s): missing timespan", rule.Title, rule.ID)
	}
	ts, err := parseTimespan(rule.Timespan)
	if err != nil {
		return nil, fmt.Errorf("rule %q (%s): invalid timespan %q: %w", rule.Title, rule.ID, rule.Timespan, err)
	}
	cr.Timespan = ts

	// Parse condition.
	if len(rule.CorrelationCond) == 0 {
		return nil, fmt.Errorf("rule %q (%s): missing condition", rule.Title, rule.ID)
	}
	op, threshold, valueField, err := parseCorrelationCondition(rule.CorrelationCond)
	if err != nil {
		return nil, fmt.Errorf("rule %q (%s): %w", rule.Title, rule.ID, err)
	}
	cr.Condition = op
	cr.Threshold = threshold
	if valueField != "" {
		cr.ValueField = valueField
	}

	// Validate per-type requirements.
	if err := validateCorrelationRule(cr); err != nil {
		return nil, fmt.Errorf("rule %q (%s): %w", cr.Title, cr.ID, err)
	}

	return cr, nil
}

// resolveCorrelationType determines the correlation subtype from the rule.
// Supports:
//   - Explicit types: "event_count", "value_count", "temporal"
//   - Generic "correlation" with inference from fields
func resolveCorrelationType(rule *SigmaRule) (CorrelationType, error) {
	switch rule.Type {
	case "event_count":
		return CorrelationEventCount, nil
	case "value_count":
		return CorrelationValueCount, nil
	case "temporal":
		return CorrelationTemporal, nil
	case "correlation":
		return inferCorrelationType(rule)
	default:
		return "", fmt.Errorf("unknown correlation type %q", rule.Type)
	}
}

// inferCorrelationType infers the subtype from a generic "correlation" rule
// based on its fields.
func inferCorrelationType(rule *SigmaRule) (CorrelationType, error) {
	if rule.Ordered {
		return CorrelationTemporal, nil
	}
	// If the rule specifies a ValueField, it's a value_count.
	if rule.ValueField != "" {
		return CorrelationValueCount, nil
	}
	return CorrelationEventCount, nil
}

// parseTimespan parses duration strings like "5m", "1h", "30s", "60m".
func parseTimespan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty timespan")
	}

	// Extract the numeric part and the unit suffix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("no numeric value")
	}

	numStr := s[:i]
	unit := strings.ToLower(s[i:])

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", numStr, err)
	}
	if num <= 0 {
		return 0, fmt.Errorf("timespan must be positive, got %d", num)
	}

	switch unit {
	case "s", "sec", "second", "seconds":
		return time.Duration(num) * time.Second, nil
	case "m", "min", "minute", "minutes":
		return time.Duration(num) * time.Minute, nil
	case "h", "hr", "hour", "hours":
		return time.Duration(num) * time.Hour, nil
	case "d", "day", "days":
		return time.Duration(num) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown unit %q (expected s/m/h/d)", unit)
	}
}

// parseCorrelationCondition extracts the operator, threshold, and optional field from
// the condition map. Supports: gte, gt, lte, lt, eq.
// For value_count rules, the condition may contain a "field" entry (stored
// as an int 0 by the generic parser; we accept it and look for it separately).
func parseCorrelationCondition(cond map[string]int) (ConditionOp, int, string, error) {
	validOps := map[string]ConditionOp{
		"gte": OpGTE,
		"gt":  OpGT,
		"lte": OpLTE,
		"lt":  OpLT,
		"eq":  OpEQ,
	}

	var op ConditionOp
	var threshold int
	var valueField string
	found := false

	for k, v := range cond {
		if cop, ok := validOps[k]; ok {
			if found {
				return "", 0, "", fmt.Errorf("condition has multiple operators")
			}
			op = cop
			threshold = v
			found = true
		}
		// "field" is ignored here — handled via rule YAML extension below.
	}

	if !found {
		return "", 0, "", fmt.Errorf("condition missing operator (expected gte/gt/lte/lt/eq)")
	}

	return op, threshold, valueField, nil
}

// validateCorrelationRule checks per-type requirements.
func validateCorrelationRule(cr *CorrelationRule) error {
	// All types require at least one referenced rule.
	if len(cr.Rules) == 0 {
		return fmt.Errorf("correlation rule must reference at least one rule ID")
	}

	switch cr.Type {
	case CorrelationEventCount:
		if cr.Threshold < 0 {
			return fmt.Errorf("event_count threshold must be non-negative")
		}

	case CorrelationValueCount:
		if cr.ValueField == "" {
			return fmt.Errorf("value_count rule must specify a value field")
		}
		if cr.Threshold < 0 {
			return fmt.Errorf("value_count threshold must be non-negative")
		}

	case CorrelationTemporal:
		if !cr.Ordered {
			return fmt.Errorf("temporal correlation must have ordered: true")
		}
		if len(cr.Rules) < 2 {
			return fmt.Errorf("temporal correlation requires at least 2 rule references")
		}
		if len(cr.GroupBy) == 0 {
			return fmt.Errorf("temporal correlation requires at least one group-by field")
		}

	default:
		return fmt.Errorf("unknown correlation type %q", cr.Type)
	}

	return nil
}

// ParseCorrelationRules converts all correlation rules from a registry into
// validated CorrelationRules. Returns the successfully parsed rules and any
// errors encountered.
func ParseCorrelationRules(registry *RuleRegistry) ([]*CorrelationRule, []error) {
	var rules []*CorrelationRule
	var errs []error

	for _, sigmaRule := range registry.CorrelationRules() {
		cr, err := ParseCorrelationRule(sigmaRule)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, cr)
	}

	return rules, errs
}
