package parsers

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WinEvent is the intermediate representation after XML parsing.
// Per-EventID ECS mappers (P2-T3) consume this struct.
type WinEvent struct {
	// System fields
	Provider     string            // System/Provider/@Name
	ProviderGUID string            // System/Provider/@Guid
	EventID      int               // System/EventID
	Version      int               // System/Version
	Level        int               // System/Level
	Task         int               // System/Task
	Opcode       int               // System/Opcode
	Keywords     string            // System/Keywords (hex string)
	TimeCreated  time.Time         // System/TimeCreated/@SystemTime
	RecordID     int64             // System/EventRecordID
	Channel      string            // System/Channel
	Computer     string            // System/Computer
	UserID       string            // System/Security/@UserID

	// EventData or UserData key/value pairs.
	EventData map[string]string
}

// xmlEvent is the top-level XML structure for Windows Event Log entries.
// Uses local name matching to handle the Microsoft namespace.
type xmlEvent struct {
	XMLName xml.Name   `xml:"Event"`
	System  xmlSystem  `xml:"System"`
	EventData *xmlEventData `xml:"EventData"`
	UserData  *xmlUserData  `xml:"UserData"`
}

type xmlSystem struct {
	Provider     xmlProvider     `xml:"Provider"`
	EventID      xmlEventID      `xml:"EventID"`
	Version      int             `xml:"Version"`
	Level        int             `xml:"Level"`
	Task         int             `xml:"Task"`
	Opcode       int             `xml:"Opcode"`
	Keywords     string          `xml:"Keywords"`
	TimeCreated  xmlTimeCreated  `xml:"TimeCreated"`
	EventRecordID int64          `xml:"EventRecordID"`
	Channel      string          `xml:"Channel"`
	Computer     string          `xml:"Computer"`
	Security     xmlSecurity     `xml:"Security"`
}

type xmlProvider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

// xmlEventID handles both simple <EventID>4624</EventID> and
// qualified <EventID Qualifiers="0">4624</EventID>.
type xmlEventID struct {
	Qualifiers string `xml:"Qualifiers,attr"`
	Value      string `xml:",chardata"`
}

type xmlTimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type xmlSecurity struct {
	UserID string `xml:"UserID,attr"`
}

type xmlEventData struct {
	Data []xmlDataItem `xml:"Data"`
}

type xmlDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// xmlUserData captures arbitrary child elements under <UserData>.
// Windows events sometimes use UserData instead of EventData, with
// a single wrapper element containing named child elements.
type xmlUserData struct {
	Inner xmlUserDataInner `xml:",any"`
}

type xmlUserDataInner struct {
	XMLName  xml.Name
	Children []xmlUserDataChild `xml:",any"`
}

type xmlUserDataChild struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// ParseWinEventXML parses a single Windows Event XML document into a WinEvent.
func ParseWinEventXML(data []byte) (*WinEvent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("winevt_xml: empty input")
	}

	var raw xmlEvent
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("winevt_xml: %w", err)
	}

	event := &WinEvent{
		Provider:     raw.System.Provider.Name,
		ProviderGUID: raw.System.Provider.Guid,
		Version:      raw.System.Version,
		Level:        raw.System.Level,
		Task:         raw.System.Task,
		Opcode:       raw.System.Opcode,
		Keywords:     raw.System.Keywords,
		RecordID:     raw.System.EventRecordID,
		Channel:      raw.System.Channel,
		Computer:     raw.System.Computer,
		UserID:       raw.System.Security.UserID,
		EventData:    make(map[string]string),
	}

	// Parse EventID (chardata, may have leading/trailing whitespace).
	eventIDStr := strings.TrimSpace(raw.System.EventID.Value)
	if eventIDStr != "" {
		id, err := strconv.Atoi(eventIDStr)
		if err != nil {
			return nil, fmt.Errorf("winevt_xml: invalid EventID %q: %w", eventIDStr, err)
		}
		event.EventID = id
	}

	// Parse timestamp — support multiple formats Windows uses.
	if raw.System.TimeCreated.SystemTime != "" {
		ts, err := parseWinTimestamp(raw.System.TimeCreated.SystemTime)
		if err != nil {
			return nil, fmt.Errorf("winevt_xml: invalid TimeCreated %q: %w",
				raw.System.TimeCreated.SystemTime, err)
		}
		event.TimeCreated = ts
	}

	// Extract EventData.
	if raw.EventData != nil {
		positional := 0
		for _, d := range raw.EventData.Data {
			key := d.Name
			if key == "" {
				// Nameless <Data> elements get positional keys.
				key = fmt.Sprintf("_%d", positional)
				positional++
			}
			event.EventData[key] = d.Value
		}
	}

	// Extract UserData (alternative to EventData).
	// UserData has a wrapper element with named children.
	if raw.UserData != nil && raw.EventData == nil {
		for _, child := range raw.UserData.Inner.Children {
			event.EventData[child.XMLName.Local] = child.Value
		}
	}

	return event, nil
}

// ParseWinEventXMLBatch parses multiple Windows Event XML documents.
// Each document should be a complete <Event>...</Event> block.
// Continues past individual errors, returning partial results.
func ParseWinEventXMLBatch(documents [][]byte) ([]*WinEvent, []error) {
	events := make([]*WinEvent, 0, len(documents))
	var errs []error

	for _, doc := range documents {
		event, err := ParseWinEventXML(doc)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		events = append(events, event)
	}

	return events, errs
}

// parseWinTimestamp handles the various timestamp formats Windows Event Logs use:
//   - 2026-03-14T12:00:00.0000000Z    (7 fractional digits)
//   - 2026-03-14T12:00:00.000Z        (3 fractional digits)
//   - 2026-03-14T12:00:00Z            (no fractional)
//   - 2026-03-14T12:00:00.000000000Z  (9 fractional digits, nanoseconds)
//   - 2026-03-14 12:00:00             (space separator, no timezone)
func parseWinTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)

	// Try RFC3339Nano first (handles most formats with Z suffix).
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}

	// Try RFC3339 (no fractional seconds).
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}

	// Windows 7-digit fractional: 2026-03-14T12:00:00.0000000Z
	// Go can't parse 7 digits natively, so truncate to 6.
	if len(s) > 20 && s[len(s)-1] == 'Z' {
		dotIdx := strings.LastIndex(s, ".")
		if dotIdx > 0 {
			frac := s[dotIdx+1 : len(s)-1] // fractional digits without Z
			if len(frac) > 9 {
				frac = frac[:9]
			}
			// Pad to 9 digits for nanosecond precision.
			for len(frac) < 9 {
				frac += "0"
			}
			normalized := s[:dotIdx+1] + frac + "Z"
			if t, err := time.Parse("2006-01-02T15:04:05.000000000Z", normalized); err == nil {
				return t.UTC(), nil
			}
		}
	}

	// Space separator, no timezone — assume UTC.
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("unrecognized timestamp format: %q", s)
}

// EventDataGet is a convenience method to retrieve an EventData value with a default.
func (w *WinEvent) EventDataGet(key, defaultVal string) string {
	if v, ok := w.EventData[key]; ok && v != "" {
		return v
	}
	return defaultVal
}

// EventDataGetInt retrieves an EventData value as an integer, returning 0 on failure.
func (w *WinEvent) EventDataGetInt(key string) int {
	v, ok := w.EventData[key]
	if !ok || v == "" {
		return 0
	}
	// Handle hex values (e.g., "0xC0000064").
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, err := strconv.ParseInt(v[2:], 16, 64)
		if err != nil {
			return 0
		}
		return int(n)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}
