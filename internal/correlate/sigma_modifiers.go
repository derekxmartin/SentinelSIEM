package correlate

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// buildModifierChain builds a fieldMatchFunc for a set of Sigma modifiers and values.
// The modifier chain determines how values are compared to the event field.
//
// Sigma modifier semantics:
//   - No modifier: exact match (case-insensitive for strings)
//   - contains: substring match (case-insensitive)
//   - startswith: prefix match (case-insensitive)
//   - endswith: suffix match (case-insensitive)
//   - re: regular expression match
//   - cidr: CIDR network match for IP fields
//   - all: all values must match (changes OR→AND)
//   - base64: base64-encode the values before matching
//
// Multiple values default to OR. The "all" modifier changes this to AND.
func buildModifierChain(modifiers []string, values []interface{}) (fieldMatchFunc, error) {
	hasAll := false
	var matchType string // "", "contains", "startswith", "endswith", "re", "cidr"
	hasBase64 := false

	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "all":
			hasAll = true
		case "contains":
			matchType = "contains"
		case "startswith":
			matchType = "startswith"
		case "endswith":
			matchType = "endswith"
		case "re":
			matchType = "re"
		case "cidr":
			matchType = "cidr"
		case "gt":
			matchType = "gt"
		case "gte":
			matchType = "gte"
		case "lt":
			matchType = "lt"
		case "lte":
			matchType = "lte"
		case "base64":
			hasBase64 = true
		default:
			// Unknown modifiers are ignored to be forward-compatible.
		}
	}

	// If base64, encode string values before matching.
	if hasBase64 {
		values = base64EncodeValues(values)
	}

	// Build individual value matchers based on matchType.
	var valueFuncs []fieldMatchFunc
	for _, v := range values {
		fn, err := buildSingleValueMatcher(matchType, v)
		if err != nil {
			return nil, err
		}
		valueFuncs = append(valueFuncs, fn)
	}

	if len(valueFuncs) == 0 {
		// No values → match anything (null check semantics).
		return func(value interface{}) bool { return true }, nil
	}

	// Combine with AND (all) or OR (default).
	if hasAll {
		return func(value interface{}) bool {
			for _, fn := range valueFuncs {
				if !matchAnySliceElement(value, fn) {
					return false
				}
			}
			return true
		}, nil
	}

	return func(value interface{}) bool {
		for _, fn := range valueFuncs {
			if matchAnySliceElement(value, fn) {
				return true
			}
		}
		return false
	}, nil
}

// matchAnySliceElement applies fn to value. If value is a string slice,
// returns true if any element matches. This handles ECS fields like
// event.category ([]string) transparently.
func matchAnySliceElement(value interface{}, fn fieldMatchFunc) bool {
	switch v := value.(type) {
	case []string:
		for _, s := range v {
			if fn(s) {
				return true
			}
		}
		return false
	case []interface{}:
		for _, item := range v {
			if fn(item) {
				return true
			}
		}
		return false
	default:
		return fn(value)
	}
}

// buildSingleValueMatcher creates a matcher for a single value with the given match type.
func buildSingleValueMatcher(matchType string, ruleValue interface{}) (fieldMatchFunc, error) {
	switch matchType {
	case "contains":
		return buildContainsMatcher(ruleValue), nil
	case "startswith":
		return buildStartswithMatcher(ruleValue), nil
	case "endswith":
		return buildEndswithMatcher(ruleValue), nil
	case "re":
		return buildRegexMatcher(ruleValue)
	case "cidr":
		return buildCIDRMatcher(ruleValue)
	case "gt":
		return buildNumericMatcher(ruleValue, func(a, b float64) bool { return a > b })
	case "gte":
		return buildNumericMatcher(ruleValue, func(a, b float64) bool { return a >= b })
	case "lt":
		return buildNumericMatcher(ruleValue, func(a, b float64) bool { return a < b })
	case "lte":
		return buildNumericMatcher(ruleValue, func(a, b float64) bool { return a <= b })
	default:
		// Plain exact match (case-insensitive for strings).
		return buildExactMatcher(ruleValue), nil
	}
}

// buildExactMatcher matches the event field value exactly against the rule value.
// String comparison is case-insensitive per Sigma spec.
func buildExactMatcher(ruleValue interface{}) fieldMatchFunc {
	if ruleValue == nil {
		return func(value interface{}) bool { return value == nil }
	}
	ruleStr := fmt.Sprintf("%v", ruleValue)
	ruleStrLower := strings.ToLower(ruleStr)

	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		eventStr := fmt.Sprintf("%v", value)
		return strings.ToLower(eventStr) == ruleStrLower
	}
}

// buildContainsMatcher matches if the event field value contains the rule value.
func buildContainsMatcher(ruleValue interface{}) fieldMatchFunc {
	ruleStr := strings.ToLower(fmt.Sprintf("%v", ruleValue))
	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		eventStr := strings.ToLower(fmt.Sprintf("%v", value))
		return strings.Contains(eventStr, ruleStr)
	}
}

// buildStartswithMatcher matches if the event field value starts with the rule value.
func buildStartswithMatcher(ruleValue interface{}) fieldMatchFunc {
	ruleStr := strings.ToLower(fmt.Sprintf("%v", ruleValue))
	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		eventStr := strings.ToLower(fmt.Sprintf("%v", value))
		return strings.HasPrefix(eventStr, ruleStr)
	}
}

// buildEndswithMatcher matches if the event field value ends with the rule value.
func buildEndswithMatcher(ruleValue interface{}) fieldMatchFunc {
	ruleStr := strings.ToLower(fmt.Sprintf("%v", ruleValue))
	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		eventStr := strings.ToLower(fmt.Sprintf("%v", value))
		return strings.HasSuffix(eventStr, ruleStr)
	}
}

// buildRegexMatcher compiles and matches a regular expression.
func buildRegexMatcher(ruleValue interface{}) (fieldMatchFunc, error) {
	pattern := fmt.Sprintf("%v", ruleValue)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		eventStr := fmt.Sprintf("%v", value)
		return re.MatchString(eventStr)
	}, nil
}

// buildCIDRMatcher parses a CIDR notation and matches IP addresses.
func buildCIDRMatcher(ruleValue interface{}) (fieldMatchFunc, error) {
	cidrStr := fmt.Sprintf("%v", ruleValue)
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}
	return func(value interface{}) bool {
		if value == nil {
			return false
		}
		ipStr := fmt.Sprintf("%v", value)
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		return network.Contains(ip)
	}, nil
}

// buildNumericMatcher creates a matcher that compares numeric field values.
// Supports int, float64, and string representations of numbers.
func buildNumericMatcher(ruleValue interface{}, cmp func(float64, float64) bool) (fieldMatchFunc, error) {
	threshold, err := toFloat64(ruleValue)
	if err != nil {
		return nil, fmt.Errorf("numeric modifier: rule value %v: %w", ruleValue, err)
	}
	return func(value interface{}) bool {
		eventVal, err := toFloat64(value)
		if err != nil {
			return false
		}
		return cmp(eventVal, threshold)
	}, nil
}

// toFloat64 converts an interface value to float64.
func toFloat64(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case int32:
		return float64(n), nil
	case string:
		return strconv.ParseFloat(n, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

// base64EncodeValues encodes string values as base64.
func base64EncodeValues(values []interface{}) []interface{} {
	result := make([]interface{}, len(values))
	for i, v := range values {
		if s, ok := v.(string); ok {
			result[i] = base64.StdEncoding.EncodeToString([]byte(s))
		} else {
			result[i] = v
		}
	}
	return result
}
