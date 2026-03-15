package parsers

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SyslogMessage represents a parsed syslog message (RFC 5424 or RFC 3164).
type SyslogMessage struct {
	Format         string                       // "rfc5424" or "rfc3164"
	Priority       int                          // raw PRI value
	Facility       int                          // derived: priority / 8
	Severity       int                          // derived: priority % 8
	Version        int                          // RFC 5424 only
	Timestamp      time.Time                    // parsed timestamp
	Hostname       string                       // originating host
	AppName        string                       // application name / tag
	ProcID         string                       // process ID
	MsgID          string                       // RFC 5424 only
	StructuredData map[string]map[string]string // RFC 5424 only
	Message        string                       // message body
}

// ParseSyslog auto-detects format (RFC 5424 vs 3164) and parses the raw message.
func ParseSyslog(raw string) (*SyslogMessage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("syslog: empty input")
	}

	// Strip BOM if present.
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		raw = raw[3:]
	}

	// Strip trailing newlines/carriage returns.
	raw = strings.TrimRight(raw, "\r\n")

	if len(raw) == 0 {
		return nil, fmt.Errorf("syslog: empty input after trimming")
	}

	// Extract PRI.
	priority, rest, err := parsePRI(raw)
	if err != nil {
		// No PRI — try to parse the whole thing as a raw message.
		return &SyslogMessage{
			Format:   "rfc3164",
			Message:  raw,
			Priority: -1,
			Facility: -1,
			Severity: -1,
		}, nil
	}

	facility := priority / 8
	severity := priority % 8

	// Detect format: after PRI, RFC 5424 starts with a version digit.
	format := detectSyslogFormat(rest)

	switch format {
	case "rfc5424":
		msg, err := parseRFC5424(rest)
		if err != nil {
			return nil, err
		}
		msg.Priority = priority
		msg.Facility = facility
		msg.Severity = severity
		return msg, nil
	default:
		msg, err := parseRFC3164(rest)
		if err != nil {
			return nil, err
		}
		msg.Priority = priority
		msg.Facility = facility
		msg.Severity = severity
		return msg, nil
	}
}

// parsePRI extracts the PRI value from <digits> at the start of a syslog message.
func parsePRI(raw string) (int, string, error) {
	if len(raw) < 3 || raw[0] != '<' {
		return 0, "", fmt.Errorf("syslog: missing PRI")
	}

	closeIdx := strings.IndexByte(raw, '>')
	if closeIdx < 0 || closeIdx > 5 { // PRI is at most 3 digits: <191>
		return 0, "", fmt.Errorf("syslog: malformed PRI")
	}

	priStr := raw[1:closeIdx]
	pri, err := strconv.Atoi(priStr)
	if err != nil {
		return 0, "", fmt.Errorf("syslog: invalid PRI value %q: %w", priStr, err)
	}

	// PRI range: 0-191 (facility 0-23, severity 0-7). Allow higher for robustness.
	if pri < 0 {
		return 0, "", fmt.Errorf("syslog: negative PRI value %d", pri)
	}

	return pri, raw[closeIdx+1:], nil
}

// detectSyslogFormat determines whether the post-PRI content is RFC 5424 or 3164.
func detectSyslogFormat(rest string) string {
	if len(rest) < 2 {
		return "rfc3164"
	}

	// RFC 5424: starts with version digit followed by space.
	if rest[0] >= '1' && rest[0] <= '9' && rest[1] == ' ' {
		return "rfc5424"
	}

	return "rfc3164"
}

// parseRFC5424 parses the body of an RFC 5424 syslog message (after PRI extraction).
// Format: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
func parseRFC5424(body string) (*SyslogMessage, error) {
	msg := &SyslogMessage{Format: "rfc5424"}

	// VERSION
	parts := strings.SplitN(body, " ", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("syslog rfc5424: truncated after version")
	}
	ver, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: invalid version %q", parts[0])
	}
	msg.Version = ver
	rest := parts[1]

	// TIMESTAMP
	ts, rest, err := parseRFC5424Field(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: missing timestamp")
	}
	if ts != "-" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			// Try RFC3339 without fractional seconds.
			t, err = time.Parse(time.RFC3339, ts)
			if err != nil {
				return nil, fmt.Errorf("syslog rfc5424: invalid timestamp %q: %w", ts, err)
			}
		}
		msg.Timestamp = t.UTC()
	}

	// HOSTNAME
	hostname, rest, err := parseRFC5424Field(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: missing hostname")
	}
	if hostname != "-" {
		msg.Hostname = hostname
	}

	// APP-NAME
	appName, rest, err := parseRFC5424Field(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: missing app-name")
	}
	if appName != "-" {
		msg.AppName = appName
	}

	// PROCID
	procID, rest, err := parseRFC5424Field(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: missing procid")
	}
	if procID != "-" {
		msg.ProcID = procID
	}

	// MSGID
	msgID, rest, err := parseRFC5424Field(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: missing msgid")
	}
	if msgID != "-" {
		msg.MsgID = msgID
	}

	// STRUCTURED-DATA
	sd, rest, err := parseStructuredData(rest)
	if err != nil {
		return nil, fmt.Errorf("syslog rfc5424: structured data: %w", err)
	}
	msg.StructuredData = sd

	// MSG (optional, after space)
	if len(rest) > 0 {
		if rest[0] == ' ' {
			rest = rest[1:]
		}
		// Strip BOM from message if present (RFC 5424 allows UTF-8 BOM before MSG).
		if len(rest) >= 3 && rest[0] == 0xEF && rest[1] == 0xBB && rest[2] == 0xBF {
			rest = rest[3:]
		}
		msg.Message = rest
	}

	return msg, nil
}

// parseRFC5424Field extracts the next space-delimited field.
func parseRFC5424Field(s string) (string, string, error) {
	if len(s) == 0 {
		return "", "", fmt.Errorf("unexpected end of input")
	}
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		return s, "", nil
	}
	return s[:idx], s[idx+1:], nil
}

// parseStructuredData parses RFC 5424 structured data elements.
// Format: NILVALUE ("-") or one or more [sdID param="value" ...] blocks.
func parseStructuredData(s string) (map[string]map[string]string, string, error) {
	if len(s) == 0 {
		return nil, "", nil
	}

	// NILVALUE
	if s[0] == '-' {
		rest := s[1:]
		return nil, rest, nil
	}

	if s[0] != '[' {
		return nil, "", fmt.Errorf("expected '[' or '-', got %q", string(s[0]))
	}

	sd := make(map[string]map[string]string)
	pos := 0

	for pos < len(s) && s[pos] == '[' {
		// Find the SD-ID (ends at first space or ']').
		endID := pos + 1
		for endID < len(s) && s[endID] != ' ' && s[endID] != ']' {
			endID++
		}
		if endID >= len(s) {
			return nil, "", fmt.Errorf("unterminated structured data element")
		}
		sdID := s[pos+1 : endID]
		params := make(map[string]string)

		// Parse params until ']'.
		cur := endID
		for cur < len(s) && s[cur] != ']' {
			// Skip whitespace.
			for cur < len(s) && s[cur] == ' ' {
				cur++
			}
			if cur >= len(s) || s[cur] == ']' {
				break
			}

			// paramName=
			eqIdx := cur
			for eqIdx < len(s) && s[eqIdx] != '=' && s[eqIdx] != ']' {
				eqIdx++
			}
			if eqIdx >= len(s) || s[eqIdx] != '=' {
				break
			}
			paramName := s[cur:eqIdx]
			cur = eqIdx + 1

			// "paramValue" with escape handling
			if cur >= len(s) || s[cur] != '"' {
				break
			}
			cur++ // skip opening quote
			var val strings.Builder
			for cur < len(s) && s[cur] != '"' {
				if s[cur] == '\\' && cur+1 < len(s) {
					cur++
					val.WriteByte(s[cur])
				} else {
					val.WriteByte(s[cur])
				}
				cur++
			}
			if cur < len(s) {
				cur++ // skip closing quote
			}
			params[paramName] = val.String()
		}

		if cur < len(s) && s[cur] == ']' {
			cur++ // skip ']'
		}

		sd[sdID] = params
		pos = cur
	}

	return sd, s[pos:], nil
}

// parseRFC3164 parses the body of an RFC 3164 (BSD) syslog message (after PRI extraction).
// Format: TIMESTAMP SP HOSTNAME SP MSG
func parseRFC3164(body string) (*SyslogMessage, error) {
	msg := &SyslogMessage{Format: "rfc3164"}

	if len(body) == 0 {
		return msg, nil
	}

	// Try to parse BSD timestamp: "Mmm dd HH:MM:SS" or "Mmm  d HH:MM:SS"
	ts, rest, err := parseRFC3164Timestamp(body)
	if err != nil {
		// No recognizable timestamp — treat entire body as message.
		msg.Message = body
		return msg, nil
	}
	msg.Timestamp = ts

	// Skip space after timestamp.
	rest = strings.TrimLeft(rest, " ")

	// HOSTNAME — next space-delimited token.
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		// No space — rest is either hostname or message.
		msg.Hostname = rest
		return msg, nil
	}
	msg.Hostname = rest[:spaceIdx]
	rest = rest[spaceIdx+1:]

	// MSG — may contain TAG[PID]: format.
	msg.Message = rest
	parseRFC3164Tag(msg)

	return msg, nil
}

// parseRFC3164Timestamp parses BSD syslog timestamps: "Mmm dd HH:MM:SS" or "Mmm  d HH:MM:SS"
// Returns the parsed time and the remaining string.
func parseRFC3164Timestamp(s string) (time.Time, string, error) {
	// Minimum length for "Mmm dd HH:MM:SS" is 15 chars.
	if len(s) < 15 {
		return time.Time{}, "", fmt.Errorf("too short for RFC 3164 timestamp")
	}

	// Validate month abbreviation.
	months := map[string]time.Month{
		"Jan": time.January, "Feb": time.February, "Mar": time.March,
		"Apr": time.April, "May": time.May, "Jun": time.June,
		"Jul": time.July, "Aug": time.August, "Sep": time.September,
		"Oct": time.October, "Nov": time.November, "Dec": time.December,
	}

	monthStr := s[:3]
	month, ok := months[monthStr]
	if !ok {
		return time.Time{}, "", fmt.Errorf("invalid month %q", monthStr)
	}

	// Space after month.
	if s[3] != ' ' {
		return time.Time{}, "", fmt.Errorf("expected space after month")
	}

	// Day: either " d" (space-padded) or "dd".
	dayStr := strings.TrimLeft(s[4:6], " ")
	day, err := strconv.Atoi(dayStr)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid day %q: %w", s[4:6], err)
	}

	if s[6] != ' ' {
		return time.Time{}, "", fmt.Errorf("expected space after day")
	}

	// Time: "HH:MM:SS"
	if len(s) < 15 {
		return time.Time{}, "", fmt.Errorf("truncated timestamp")
	}
	timeStr := s[7:15]
	parts := strings.Split(timeStr, ":")
	if len(parts) != 3 {
		return time.Time{}, "", fmt.Errorf("invalid time %q", timeStr)
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid hour: %w", err)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid minute: %w", err)
	}
	second, err := strconv.Atoi(parts[2])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid second: %w", err)
	}

	// RFC 3164 has no year — use current year.
	now := time.Now().UTC()
	year := now.Year()

	t := time.Date(year, month, day, hour, minute, second, 0, time.UTC)

	// Handle year boundary: if parsed time is >1 day in the future, use previous year.
	if t.After(now.Add(24 * time.Hour)) {
		t = time.Date(year-1, month, day, hour, minute, second, 0, time.UTC)
	}

	return t, s[15:], nil
}

// parseRFC3164Tag extracts TAG[PID] from the message body of an RFC 3164 message.
// Common formats: "sshd[1234]: message" or "sshd: message" or "CRON[5678]: message"
func parseRFC3164Tag(msg *SyslogMessage) {
	s := msg.Message
	if len(s) == 0 {
		return
	}

	// Find colon that separates tag from message.
	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 || colonIdx > 48 { // tag shouldn't be longer than 48 chars
		return
	}

	tag := s[:colonIdx]
	rest := s[colonIdx+1:]

	// Check for [PID] in tag.
	bracketIdx := strings.IndexByte(tag, '[')
	if bracketIdx >= 0 {
		closeBracket := strings.IndexByte(tag[bracketIdx:], ']')
		if closeBracket >= 0 {
			msg.AppName = tag[:bracketIdx]
			msg.ProcID = tag[bracketIdx+1 : bracketIdx+closeBracket]
		} else {
			msg.AppName = tag
		}
	} else {
		msg.AppName = tag
	}

	// Trim leading space from message.
	msg.Message = strings.TrimLeft(rest, " ")
}

// SyslogSeverityName returns the human-readable name for an RFC 5424 severity level.
func SyslogSeverityName(severity int) string {
	names := []string{
		"emergency", "alert", "critical", "error",
		"warning", "notice", "informational", "debug",
	}
	if severity >= 0 && severity < len(names) {
		return names[severity]
	}
	return "unknown"
}

// SyslogFacilityName returns the human-readable name for a syslog facility code.
func SyslogFacilityName(facility int) string {
	names := []string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
		"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
	if facility >= 0 && facility < len(names) {
		return names[facility]
	}
	return "unknown"
}
