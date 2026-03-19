package correlate

import (
	"fmt"
	"os"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"gopkg.in/yaml.v3"
)

// LogsourceMapFile represents the top-level YAML structure of logsource_map.yaml.
type LogsourceMapFile struct {
	Mappings []LogsourceMapping `yaml:"mappings"`
}

// LogsourceMapping defines a single Sigma logsource → ECS conditions mapping.
type LogsourceMapping struct {
	Logsource  LogsourceSelector  `yaml:"logsource"`
	Conditions map[string]string  `yaml:"conditions"`
}

// LogsourceSelector holds the Sigma logsource fields used for matching.
type LogsourceSelector struct {
	Category string `yaml:"category,omitempty"`
	Product  string `yaml:"product,omitempty"`
	Service  string `yaml:"service,omitempty"`
}

// LogsourceMap provides lookup from Sigma logsource to ECS filter conditions.
type LogsourceMap struct {
	mappings []LogsourceMapping
}

// LoadLogsourceMap loads and parses a logsource_map.yaml file.
func LoadLogsourceMap(path string) (*LogsourceMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading logsource map: %w", err)
	}

	return ParseLogsourceMap(data)
}

// ParseLogsourceMap parses logsource map YAML from bytes.
func ParseLogsourceMap(data []byte) (*LogsourceMap, error) {
	var file LogsourceMapFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing logsource map: %w", err)
	}

	if len(file.Mappings) == 0 {
		return nil, fmt.Errorf("logsource map: no mappings defined")
	}

	// Validate each mapping has at least one logsource field and one condition.
	for i, m := range file.Mappings {
		if m.Logsource.Category == "" && m.Logsource.Product == "" && m.Logsource.Service == "" {
			return nil, fmt.Errorf("logsource map: mapping %d has no logsource fields", i)
		}
		if len(m.Conditions) == 0 {
			return nil, fmt.Errorf("logsource map: mapping %d has no conditions", i)
		}
	}

	return &LogsourceMap{mappings: file.Mappings}, nil
}

// Resolve returns the ECS filter conditions for a given Sigma logsource.
// More specific matches (more logsource fields matched) take priority.
// Returns nil if no mapping matches.
func (lm *LogsourceMap) Resolve(category, product, service string) map[string]string {
	var bestMatch *LogsourceMapping
	bestScore := 0

	for i := range lm.mappings {
		m := &lm.mappings[i]
		score := lm.matchScore(m, category, product, service)
		if score > 0 && score > bestScore {
			bestMatch = m
			bestScore = score
		}
	}

	if bestMatch == nil {
		return nil
	}

	// Return a copy to prevent mutation.
	result := make(map[string]string, len(bestMatch.Conditions))
	for k, v := range bestMatch.Conditions {
		result[k] = v
	}
	return result
}

// ResolveAll returns all matching ECS filter conditions for a given Sigma logsource.
// This is useful for category-level rules that should match events from multiple products.
func (lm *LogsourceMap) ResolveAll(category, product, service string) []map[string]string {
	var results []map[string]string

	for i := range lm.mappings {
		m := &lm.mappings[i]
		if lm.matchScore(m, category, product, service) > 0 {
			conds := make(map[string]string, len(m.Conditions))
			for k, v := range m.Conditions {
				conds[k] = v
			}
			results = append(results, conds)
		}
	}

	return results
}

// matchScore returns how well a mapping matches the given logsource fields.
// Returns 0 if no match. Higher scores = more specific match.
func (lm *LogsourceMap) matchScore(m *LogsourceMapping, category, product, service string) int {
	score := 0

	// Each mapping field that is set must match the query.
	if m.Logsource.Category != "" {
		if m.Logsource.Category != category {
			return 0
		}
		score++
	}
	if m.Logsource.Product != "" {
		if m.Logsource.Product != product {
			return 0
		}
		score++
	}
	if m.Logsource.Service != "" {
		if m.Logsource.Service != service {
			return 0
		}
		score++
	}

	// Query fields that are set but not in the mapping don't disqualify,
	// but the mapping must have matched at least one field.
	return score
}

// MatchesEvent checks whether an ECS event satisfies the given logsource conditions.
// This is used at evaluation time to filter events before rule matching.
func MatchesEvent(conditions map[string]string, event *common.ECSEvent) bool {
	for field, expected := range conditions {
		if !eventFieldEquals(event, field, expected) {
			return false
		}
	}
	return true
}

// eventFieldEquals checks if an ECS event field matches an expected value.
func eventFieldEquals(event *common.ECSEvent, field, expected string) bool {
	switch field {
	case "source_type":
		return event.SourceType == expected

	// event.* fields
	case "event.category":
		return event.Event != nil && stringSliceContains(event.Event.Category, expected)
	case "event.type":
		return event.Event != nil && stringSliceContains(event.Event.Type, expected)
	case "event.action":
		return event.Event != nil && event.Event.Action == expected
	case "event.kind":
		return event.Event != nil && event.Event.Kind == expected
	case "event.outcome":
		return event.Event != nil && event.Event.Outcome == expected

	// host.* fields
	case "host.name":
		return event.Host != nil && event.Host.Name == expected

	// network.* fields
	case "network.protocol":
		return event.Network != nil && event.Network.Protocol == expected
	case "network.direction":
		return event.Network != nil && event.Network.Direction == expected

	// Windows Event Log metadata fields.
	case "winevt.channel":
		return event.WinEvt != nil && event.WinEvt.Channel == expected
	case "winevt.provider":
		return event.WinEvt != nil && event.WinEvt.Provider == expected

	// process.* fields
	case "process.name":
		return event.Process != nil && event.Process.Name == expected

	// network.community_id for cross-source correlation
	case "network.community_id":
		return event.Network != nil && event.Network.CommunityID == expected
	case "network.transport":
		return event.Network != nil && event.Network.Transport == expected

	// ndr.* fields
	case "ndr.detection.name":
		return event.NDR != nil && event.NDR.Detection != nil && event.NDR.Detection.Name == expected
	case "ndr.detection.category":
		return event.NDR != nil && event.NDR.Detection != nil && event.NDR.Detection.Category == expected
	case "ndr.host_score.quadrant":
		return event.NDR != nil && event.NDR.HostScore != nil && event.NDR.HostScore.Quadrant == expected

	// dns.* fields
	case "dns.question.name":
		return event.DNS != nil && event.DNS.Question != nil && event.DNS.Question.Name == expected
	case "dns.response_code":
		return event.DNS != nil && event.DNS.ResponseCode == expected

	// tls.* fields
	case "tls.client.server_name":
		return event.TLS != nil && event.TLS.Client != nil && event.TLS.Client.ServerName == expected
	case "tls.client.ja3":
		return event.TLS != nil && event.TLS.Client != nil && event.TLS.Client.JA3 == expected
	case "tls.version":
		return event.TLS != nil && event.TLS.Version == expected

	// smb.* fields
	case "smb.action":
		return event.SMB != nil && event.SMB.Action == expected
	case "smb.filename":
		return event.SMB != nil && event.SMB.Filename == expected

	// ssh.* fields
	case "ssh.hassh":
		return event.SSH != nil && event.SSH.HASSH == expected

	default:
		// Unknown field — no match.
		return false
	}
}

// stringSliceContains checks if a string slice contains a value.
func stringSliceContains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// MappingCount returns the number of loaded mappings.
func (lm *LogsourceMap) MappingCount() int {
	return len(lm.mappings)
}
