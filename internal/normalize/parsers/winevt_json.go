package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// winlogbeatEnvelope is the top-level Winlogbeat JSON structure.
type winlogbeatEnvelope struct {
	Timestamp  string          `json:"@timestamp"`
	SourceType string          `json:"source_type"`
	Winlog     *winlogSection  `json:"winlog"`
}

type winlogSection struct {
	ProviderName string            `json:"provider_name"`
	ProviderGUID string            `json:"provider_guid"`
	EventID      winlogEventID     `json:"event_id"`
	Version      int               `json:"version"`
	Level        string            `json:"level"`
	Task         string            `json:"task"`
	Opcode       string            `json:"opcode"`
	Keywords     []string          `json:"keywords"`
	RecordID     int64             `json:"record_id"`
	Channel      string            `json:"channel"`
	ComputerName string            `json:"computer_name"`
	User         *winlogUser       `json:"user"`
	EventData    map[string]string `json:"event_data"`
	UserData     map[string]string `json:"user_data"`
}

// winlogEventID handles both integer and object forms of event_id.
// Winlogbeat sends integer, but some forwarders send {"value": 4624, "qualifiers": 0}.
type winlogEventID struct {
	Value int
}

func (w *winlogEventID) UnmarshalJSON(data []byte) error {
	// Try integer first.
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		w.Value = n
		return nil
	}

	// Try object form: {"value": 4624}.
	var obj struct {
		Value int `json:"value"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		w.Value = obj.Value
		return nil
	}

	// Try string form.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			w.Value = 0
			return nil
		}
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			w.Value = n
			return nil
		}
	}

	return fmt.Errorf("winevt_json: cannot parse event_id from %s", string(data))
}

type winlogUser struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Domain     string `json:"domain"`
}

// ParseWinEventJSON parses a Winlogbeat-style JSON document into a WinEvent.
// This produces the same intermediate struct as ParseWinEventXML, so downstream
// ECS mappers (P2-T3) work identically for both formats.
func ParseWinEventJSON(raw json.RawMessage) (*WinEvent, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("winevt_json: empty input")
	}

	var envelope winlogbeatEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("winevt_json: %w", err)
	}

	if envelope.Winlog == nil {
		return nil, fmt.Errorf("winevt_json: missing 'winlog' field")
	}

	wl := envelope.Winlog

	event := &WinEvent{
		Provider:     wl.ProviderName,
		ProviderGUID: wl.ProviderGUID,
		EventID:      wl.EventID.Value,
		Version:      wl.Version,
		Level:        winlogLevelToInt(wl.Level),
		RecordID:     wl.RecordID,
		Channel:      wl.Channel,
		Computer:     wl.ComputerName,
		EventData:    make(map[string]string),
	}

	// Keywords: join as comma-separated hex-like string for parity with XML.
	if len(wl.Keywords) > 0 {
		event.Keywords = strings.Join(wl.Keywords, ",")
	}

	// User ID.
	if wl.User != nil {
		event.UserID = wl.User.Identifier
	}

	// Timestamp.
	if envelope.Timestamp != "" {
		ts, err := parseWinTimestamp(envelope.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("winevt_json: invalid @timestamp %q: %w", envelope.Timestamp, err)
		}
		event.TimeCreated = ts
	}

	// EventData — copy from winlog.event_data.
	if wl.EventData != nil {
		for k, v := range wl.EventData {
			event.EventData[k] = v
		}
	}

	// UserData fallback — same as XML parser behavior.
	if wl.EventData == nil && wl.UserData != nil {
		for k, v := range wl.UserData {
			event.EventData[k] = v
		}
	}

	return event, nil
}

// ParseWinEventJSONBatch parses multiple Winlogbeat JSON documents.
// Continues past individual errors, returning partial results.
func ParseWinEventJSONBatch(documents []json.RawMessage) ([]*WinEvent, []error) {
	events := make([]*WinEvent, 0, len(documents))
	var errs []error

	for _, doc := range documents {
		event, err := ParseWinEventJSON(doc)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		events = append(events, event)
	}

	return events, errs
}

// winlogLevelToInt maps Winlogbeat level strings to Windows Event Log level integers.
// See: https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-leveltype-complextype
func winlogLevelToInt(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 1
	case "error":
		return 2
	case "warning":
		return 3
	case "information", "info":
		return 4
	case "verbose":
		return 5
	case "audit success", "audit_success":
		return 0 // Security audit events use Level 0
	case "audit failure", "audit_failure":
		return 0
	default:
		return 0
	}
}

// DetectWinEventFormat inspects raw JSON to determine if it's Winlogbeat JSON
// (has "winlog" key) or WEF XML wrapped in JSON (has "xml" or "Event" key).
// Returns "winlogbeat", "xml", or "unknown".
func DetectWinEventFormat(raw json.RawMessage) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "unknown"
	}
	if _, ok := probe["winlog"]; ok {
		return "winlogbeat"
	}
	if _, ok := probe["xml"]; ok {
		return "xml"
	}
	if _, ok := probe["Event"]; ok {
		return "xml"
	}
	return "unknown"
}

// winlogTimestampFallback attempts to extract timestamp from winlog.event_data
// if @timestamp is missing (some forwarders omit the top-level field).
func winlogTimestampFallback(eventData map[string]string) time.Time {
	for _, key := range []string{"UtcTime", "TimeGenerated", "SystemTime"} {
		if v, ok := eventData[key]; ok && v != "" {
			if ts, err := parseWinTimestamp(v); err == nil {
				return ts
			}
		}
	}
	return time.Time{}
}
