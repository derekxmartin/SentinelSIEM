package parsers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SubParserConfig defines a syslog sub-parser loaded from YAML.
type SubParserConfig struct {
	Name        string          `yaml:"name"`
	Match       string          `yaml:"match"`
	ECSCategory []string        `yaml:"ecs_category"`
	ECSType     []string        `yaml:"ecs_type"`
	Patterns    []PatternConfig `yaml:"patterns"`
}

// PatternConfig defines a single regex pattern within a sub-parser.
type PatternConfig struct {
	Name     string            `yaml:"name"`
	Regex    string            `yaml:"regex"`
	FieldMap map[string]string `yaml:"field_map"`
	Action   string            `yaml:"action"`
	Category []string          `yaml:"category"`
	Type     []string          `yaml:"type"`
}

// SubParser is the compiled form of a SubParserConfig.
type SubParser struct {
	Name        string
	matchRe     *regexp.Regexp
	ecsCategory []string
	ecsType     []string
	patterns    []compiledPattern
}

type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	fieldMap map[string]string
	action   string
	category []string
	typ      []string
}

// SubParserResult holds the output of a sub-parser match.
type SubParserResult struct {
	ParserName string
	PatternName string
	Fields     map[string]string // captured fields mapped to ECS paths
	Action     string
	Category   []string
	Type       []string
}

// SubParserRegistry holds compiled sub-parsers in priority order.
type SubParserRegistry struct {
	parsers []*SubParser
}

// LoadSubParsers loads and compiles all syslog sub-parser YAML files from a directory.
// Files must be named syslog_*.yaml.
func LoadSubParsers(dir string) (*SubParserRegistry, error) {
	pattern := filepath.Join(dir, "syslog_*.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("sub-parsers: glob %q: %w", pattern, err)
	}

	registry := &SubParserRegistry{}

	for _, f := range files {
		sp, err := loadSubParserFile(f)
		if err != nil {
			return nil, fmt.Errorf("sub-parsers: loading %s: %w", filepath.Base(f), err)
		}
		registry.parsers = append(registry.parsers, sp)
	}

	return registry, nil
}

func loadSubParserFile(path string) (*SubParser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg SubParserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("YAML parse: %w", err)
	}

	if cfg.Name == "" {
		return nil, fmt.Errorf("missing 'name' field")
	}

	if cfg.Match == "" {
		return nil, fmt.Errorf("missing 'match' field in sub-parser %q", cfg.Name)
	}

	matchRe, err := regexp.Compile(cfg.Match)
	if err != nil {
		return nil, fmt.Errorf("invalid match regex in %q: %w", cfg.Name, err)
	}

	sp := &SubParser{
		Name:        cfg.Name,
		matchRe:     matchRe,
		ecsCategory: cfg.ECSCategory,
		ecsType:     cfg.ECSType,
	}

	for _, p := range cfg.Patterns {
		if p.Regex == "" {
			return nil, fmt.Errorf("empty regex in pattern %q of sub-parser %q", p.Name, cfg.Name)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in pattern %q of sub-parser %q: %w", p.Name, cfg.Name, err)
		}
		sp.patterns = append(sp.patterns, compiledPattern{
			name:     p.Name,
			re:       re,
			fieldMap: p.FieldMap,
			action:   p.Action,
			category: p.Category,
			typ:      p.Type,
		})
	}

	return sp, nil
}

// Parse attempts to match the message against loaded sub-parsers.
// Returns the result and true if a match was found, or nil and false otherwise.
func (r *SubParserRegistry) Parse(appName, message string) (*SubParserResult, bool) {
	if r == nil {
		return nil, false
	}

	combined := appName + " " + message

	for _, sp := range r.parsers {
		if !sp.matchRe.MatchString(combined) {
			continue
		}

		// This sub-parser matches — try patterns.
		for _, p := range sp.patterns {
			matches := p.re.FindStringSubmatch(message)
			if matches == nil {
				continue
			}

			// Extract named groups.
			fields := make(map[string]string)
			for i, name := range p.re.SubexpNames() {
				if i > 0 && name != "" && i < len(matches) && matches[i] != "" {
					if ecsPath, ok := p.fieldMap[name]; ok {
						fields[ecsPath] = matches[i]
					} else {
						// Preserve unmapped captures.
						fields[name] = matches[i]
					}
				}
			}

			// Determine category/type — pattern overrides parent.
			cat := sp.ecsCategory
			if len(p.category) > 0 {
				cat = p.category
			}
			typ := sp.ecsType
			if len(p.typ) > 0 {
				typ = p.typ
			}

			return &SubParserResult{
				ParserName:  sp.Name,
				PatternName: p.name,
				Fields:      fields,
				Action:      p.action,
				Category:    cat,
				Type:        typ,
			}, true
		}

		// Sub-parser matched but no pattern matched — still return match with defaults.
		return &SubParserResult{
			ParserName: sp.Name,
			Fields:     make(map[string]string),
			Category:   sp.ecsCategory,
			Type:       sp.ecsType,
		}, true
	}

	return nil, false
}

// ParserNames returns the names of all loaded sub-parsers.
func (r *SubParserRegistry) ParserNames() []string {
	if r == nil {
		return nil
	}
	names := make([]string, len(r.parsers))
	for i, p := range r.parsers {
		names[i] = p.Name
	}
	return names
}

// setECSFieldFromPath sets a field on a map by dot-notation path.
// This is used by the ECS parser to apply sub-parser results.
func setECSFieldFromPath(fields map[string]string, path string, value string) {
	fields[path] = value
}

// KnownECSPaths lists the ECS paths supported by field mapping.
var KnownECSPaths = map[string]bool{
	"source.ip":                         true,
	"source.port":                       true,
	"destination.ip":                    true,
	"destination.port":                  true,
	"network.protocol":                  true,
	"network.direction":                 true,
	"process.pid":                       true,
	"process.name":                      true,
	"process.executable":                true,
	"process.command_line":              true,
	"user.name":                         true,
	"user.id":                           true,
	"file.path":                         true,
	"file.name":                         true,
	"event.action":                      true,
	"event.outcome":                     true,
	"observer.ingress.interface.name":   true,
	"observer.egress.interface.name":    true,
}

// ParseKVPairs extracts key=value pairs from a string.
// Handles both unquoted (key=value) and quoted (key="value with spaces") forms.
func ParseKVPairs(s string) map[string]string {
	result := make(map[string]string)

	i := 0
	for i < len(s) {
		// Skip whitespace.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}

		// Find key (ends at '=').
		keyStart := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			// No '=' found — skip this token.
			for i < len(s) && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[keyStart:i]
		i++ // skip '='

		if i >= len(s) {
			result[key] = ""
			break
		}

		// Read value.
		if s[i] == '"' {
			// Quoted value.
			i++ // skip opening quote
			valStart := i
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++ // skip escaped char
				}
				i++
			}
			result[key] = s[valStart:i]
			if i < len(s) {
				i++ // skip closing quote
			}
		} else {
			// Unquoted value.
			valStart := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			result[key] = s[valStart:i]
		}
	}

	return result
}

// isSubParserMatch is a helper to check if a regex matches without extracting groups.
func isSubParserMatch(re *regexp.Regexp, s string) bool {
	return re.MatchString(s)
}

// lowerContains is a case-insensitive contains check.
func lowerContains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
