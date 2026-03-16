package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
)

// WinEventMapper is a function that maps a parsed WinEvent to an ECSEvent.
type WinEventMapper func(w *WinEvent) *common.ECSEvent

// winEventMappers maps EventID → mapper function for non-Sysmon events.
var winEventMappers = map[int]WinEventMapper{
	4624: mapLogon4624,
	4625: mapLogonFailed4625,
	4688: mapProcessCreate4688,
	4768: mapKerberosTGT4768,
	4769: mapKerberosServiceTicket4769,
	7045: mapServiceInstall7045,
}

// sysmonMappers maps Sysmon EventID → mapper function.
// Kept separate to avoid EventID collisions with Security/System events.
var sysmonMappers = map[int]WinEventMapper{
	1:  mapSysmon1ProcessCreate,
	3:  mapSysmon3NetworkConnect,
	11: mapSysmon11FileCreate,
}

// MapWinEventToECS converts a parsed WinEvent to an ECSEvent using per-EventID mappers.
// Unknown EventIDs get a default mapping that preserves common fields.
func MapWinEventToECS(w *WinEvent) *common.ECSEvent {
	if w == nil {
		return &common.ECSEvent{
			Event: &common.EventFields{Kind: "event"},
		}
	}

	// Dispatch to EventID-specific mapper, or use default.
	mapper, ok := winEventMappers[w.EventID]
	if !ok {
		return mapDefault(w)
	}

	event := mapper(w)

	// Always set common fields.
	event.Timestamp = w.TimeCreated
	if event.Host == nil {
		event.Host = &common.HostFields{}
	}
	event.Host.Name = w.Computer
	event.WinEvt = &common.WinEvtFields{
		Channel:  w.Channel,
		Provider: w.Provider,
		EventID:  w.EventID,
	}

	return event
}

// isSysmonEvent checks if the WinEvent is from Sysmon based on channel or provider.
func isSysmonEvent(w *WinEvent) bool {
	return strings.Contains(w.Channel, "Sysmon") ||
		strings.Contains(w.Provider, "Sysmon")
}

// MapWinEventToECSWithSysmon dispatches Sysmon events by EventID within the
// Sysmon channel, while Security/System events use the standard registry.
// This avoids EventID collisions (e.g., Security EventID 1 vs Sysmon EventID 1).
func MapWinEventToECSWithSysmon(w *WinEvent) *common.ECSEvent {
	if w == nil {
		return &common.ECSEvent{
			Event: &common.EventFields{Kind: "event"},
		}
	}

	// Sysmon events use Sysmon-specific mappers.
	if isSysmonEvent(w) {
		if mapper, ok := sysmonMappers[w.EventID]; ok {
			return applySysmonCommon(w, mapper(w))
		}
		return applySysmonCommon(w, mapDefault(w))
	}

	// Non-Sysmon: use standard mapper.
	return MapWinEventToECS(w)
}

func applySysmonCommon(w *WinEvent, event *common.ECSEvent) *common.ECSEvent {
	event.Timestamp = w.TimeCreated
	if event.Host == nil {
		event.Host = &common.HostFields{}
	}
	event.Host.Name = w.Computer
	event.WinEvt = &common.WinEvtFields{
		Channel:  w.Channel,
		Provider: w.Provider,
		EventID:  w.EventID,
	}
	return event
}

// ============================================================================
// Per-EventID mappers
// ============================================================================

// mapLogon4624 maps Windows Security Event 4624 (successful logon).
func mapLogon4624(w *WinEvent) *common.ECSEvent {
	logonType := w.EventDataGet("LogonType", "0")
	logonTypeDesc := logonTypeToString(logonType)

	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"authentication"},
			Type:     []string{"start"},
			Action:   "logon-" + logonTypeDesc,
			Outcome:  "success",
		},
		User: &common.UserFields{
			Name:   w.EventDataGet("TargetUserName", ""),
			Domain: w.EventDataGet("TargetDomainName", ""),
			ID:     w.EventDataGet("TargetUserSid", ""),
		},
	}

	// Source IP/port (may be "-" or missing for local logons).
	ipAddr := w.EventDataGet("IpAddress", "")
	if ipAddr != "" && ipAddr != "-" {
		event.Source = &common.EndpointFields{
			IP:   ipAddr,
			Port: w.EventDataGetInt("IpPort"),
		}
	}

	return event
}

// mapLogonFailed4625 maps Windows Security Event 4625 (failed logon).
func mapLogonFailed4625(w *WinEvent) *common.ECSEvent {
	logonType := w.EventDataGet("LogonType", "0")
	logonTypeDesc := logonTypeToString(logonType)

	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"authentication"},
			Type:     []string{"start"},
			Action:   "logon-failed-" + logonTypeDesc,
			Outcome:  "failure",
		},
		User: &common.UserFields{
			Name:   w.EventDataGet("TargetUserName", ""),
			Domain: w.EventDataGet("TargetDomainName", ""),
			ID:     w.EventDataGet("TargetUserSid", ""),
		},
	}

	ipAddr := w.EventDataGet("IpAddress", "")
	if ipAddr != "" && ipAddr != "-" {
		event.Source = &common.EndpointFields{
			IP:   ipAddr,
			Port: w.EventDataGetInt("IpPort"),
		}
	}

	return event
}

// mapProcessCreate4688 maps Windows Security Event 4688 (new process created).
func mapProcessCreate4688(w *WinEvent) *common.ECSEvent {
	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "process-created",
		},
		Process: &common.ProcessFields{
			PID:         w.EventDataGetInt("NewProcessId"),
			Executable:  w.EventDataGet("NewProcessName", ""),
			CommandLine: w.EventDataGet("CommandLine", ""),
		},
		User: &common.UserFields{
			Name:   w.EventDataGet("SubjectUserName", ""),
			Domain: w.EventDataGet("SubjectDomainName", ""),
			ID:     w.EventDataGet("SubjectUserSid", ""),
		},
	}

	// Extract process name from full path.
	if event.Process.Executable != "" {
		event.Process.Name = fileNameFromPath(event.Process.Executable)
	}

	// Parent process.
	parentExe := w.EventDataGet("ParentProcessName", "")
	if parentExe != "" {
		event.Process.Parent = &common.ParentProcess{
			Executable: parentExe,
			Name:       fileNameFromPath(parentExe),
		}
	}

	return event
}

// mapKerberosTGT4768 maps Windows Security Event 4768 (Kerberos TGT request).
func mapKerberosTGT4768(w *WinEvent) *common.ECSEvent {
	status := w.EventDataGet("Status", "")
	outcome := kerberosStatusToOutcome(status)

	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"authentication"},
			Type:     []string{"start"},
			Action:   "kerberos-tgt-request",
			Outcome:  outcome,
		},
		User: &common.UserFields{
			Name:   w.EventDataGet("TargetUserName", ""),
			Domain: w.EventDataGet("TargetDomainName", ""),
			ID:     w.EventDataGet("TargetSid", ""),
		},
	}

	ipAddr := w.EventDataGet("IpAddress", "")
	if ipAddr != "" && ipAddr != "-" {
		// Kerberos IpAddress may have ::ffff: prefix.
		ipAddr = strings.TrimPrefix(ipAddr, "::ffff:")
		event.Source = &common.EndpointFields{
			IP: ipAddr,
		}
	}

	return event
}

// mapKerberosServiceTicket4769 maps Windows Security Event 4769 (Kerberos service ticket).
func mapKerberosServiceTicket4769(w *WinEvent) *common.ECSEvent {
	status := w.EventDataGet("Status", "")
	outcome := kerberosStatusToOutcome(status)

	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"authentication"},
			Type:     []string{"start"},
			Action:   "kerberos-service-ticket",
			Outcome:  outcome,
		},
		User: &common.UserFields{
			Name:   w.EventDataGet("TargetUserName", ""),
			Domain: w.EventDataGet("TargetDomainName", ""),
		},
	}

	serviceName := w.EventDataGet("ServiceName", "")
	if serviceName != "" {
		event.Destination = &common.EndpointFields{
			Domain: serviceName,
		}
	}

	ipAddr := w.EventDataGet("IpAddress", "")
	if ipAddr != "" && ipAddr != "-" {
		ipAddr = strings.TrimPrefix(ipAddr, "::ffff:")
		event.Source = &common.EndpointFields{
			IP: ipAddr,
		}
	}

	return event
}

// mapServiceInstall7045 maps Windows System Event 7045 (new service installed).
func mapServiceInstall7045(w *WinEvent) *common.ECSEvent {
	return &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"creation"},
			Action:   "service-install",
		},
		Process: &common.ProcessFields{
			Executable: w.EventDataGet("ImagePath", ""),
			Name:       w.EventDataGet("ServiceName", ""),
		},
	}
}

// mapSysmon1ProcessCreate maps Sysmon Event 1 (process creation).
func mapSysmon1ProcessCreate(w *WinEvent) *common.ECSEvent {
	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "process-created",
		},
		Process: &common.ProcessFields{
			PID:         w.EventDataGetInt("ProcessId"),
			Executable:  w.EventDataGet("Image", ""),
			CommandLine: w.EventDataGet("CommandLine", ""),
		},
	}

	// Process name from path.
	if event.Process.Executable != "" {
		event.Process.Name = fileNameFromPath(event.Process.Executable)
	}

	// Parent process.
	parentImage := w.EventDataGet("ParentImage", "")
	if parentImage != "" {
		event.Process.Parent = &common.ParentProcess{
			PID:         w.EventDataGetInt("ParentProcessId"),
			Executable:  parentImage,
			Name:        fileNameFromPath(parentImage),
			CommandLine: w.EventDataGet("ParentCommandLine", ""),
		}
	}

	// Parse hashes from Sysmon format: "SHA256=abc,MD5=def"
	hashes := parseSysmonHashes(w.EventDataGet("Hashes", ""))
	if hashes != nil {
		event.File = &common.FileFields{
			Hash: hashes,
		}
	}

	// User (Sysmon format: "DOMAIN\user").
	userField := w.EventDataGet("User", "")
	if userField != "" {
		user := parseDomainUser(userField)
		event.User = user
	}

	return event
}

// mapSysmon3NetworkConnect maps Sysmon Event 3 (network connection).
func mapSysmon3NetworkConnect(w *WinEvent) *common.ECSEvent {
	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"network"},
			Type:     []string{"connection"},
			Action:   "network-connection",
		},
		Process: &common.ProcessFields{
			PID:        w.EventDataGetInt("ProcessId"),
			Executable: w.EventDataGet("Image", ""),
		},
		Source: &common.EndpointFields{
			IP:   w.EventDataGet("SourceIp", ""),
			Port: w.EventDataGetInt("SourcePort"),
		},
		Destination: &common.EndpointFields{
			IP:   w.EventDataGet("DestinationIp", ""),
			Port: w.EventDataGetInt("DestinationPort"),
		},
		Network: &common.NetworkFields{
			Protocol: strings.ToLower(w.EventDataGet("Protocol", "")),
		},
	}

	if event.Process.Executable != "" {
		event.Process.Name = fileNameFromPath(event.Process.Executable)
	}

	// Direction: Sysmon reports "true"/"false" for Initiated field.
	initiated := w.EventDataGet("Initiated", "")
	if strings.EqualFold(initiated, "true") {
		event.Network.Direction = "outbound"
	} else if strings.EqualFold(initiated, "false") {
		event.Network.Direction = "inbound"
	}

	// User.
	userField := w.EventDataGet("User", "")
	if userField != "" {
		event.User = parseDomainUser(userField)
	}

	return event
}

// mapSysmon11FileCreate maps Sysmon Event 11 (file creation).
func mapSysmon11FileCreate(w *WinEvent) *common.ECSEvent {
	targetFilename := w.EventDataGet("TargetFilename", "")

	event := &common.ECSEvent{
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"file"},
			Type:     []string{"creation"},
			Action:   "file-created",
		},
		Process: &common.ProcessFields{
			PID:        w.EventDataGetInt("ProcessId"),
			Executable: w.EventDataGet("Image", ""),
		},
		File: &common.FileFields{
			Path: targetFilename,
		},
	}

	if targetFilename != "" {
		event.File.Name = fileNameFromPath(targetFilename)
	}

	if event.Process.Executable != "" {
		event.Process.Name = fileNameFromPath(event.Process.Executable)
	}

	// User.
	userField := w.EventDataGet("User", "")
	if userField != "" {
		event.User = parseDomainUser(userField)
	}

	return event
}

// mapDefault provides a catch-all mapping for unknown EventIDs.
func mapDefault(w *WinEvent) *common.ECSEvent {
	event := &common.ECSEvent{
		Timestamp: w.TimeCreated,
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"event"},
			Type:     []string{"info"},
			Action:   fmt.Sprintf("winevt-%d", w.EventID),
		},
		Host: &common.HostFields{
			Name: w.Computer,
		},
		WinEvt: &common.WinEvtFields{
			Channel:  w.Channel,
			Provider: w.Provider,
			EventID:  w.EventID,
		},
	}

	return event
}

// ============================================================================
// Helper functions
// ============================================================================

// parseSysmonHashes parses Sysmon hash strings like "SHA256=abc,MD5=def".
func parseSysmonHashes(s string) *common.HashFields {
	if s == "" {
		return nil
	}

	hashes := &common.HashFields{}
	found := false

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		algo := strings.ToUpper(part[:eqIdx])
		value := part[eqIdx+1:]
		if value == "" {
			continue
		}

		switch algo {
		case "MD5":
			hashes.MD5 = value
			found = true
		case "SHA1":
			hashes.SHA1 = value
			found = true
		case "SHA256":
			hashes.SHA256 = value
			found = true
		}
	}

	if !found {
		return nil
	}
	return hashes
}

// parseDomainUser splits "DOMAIN\user" or "user@domain" into UserFields.
func parseDomainUser(s string) *common.UserFields {
	user := &common.UserFields{}

	if idx := strings.Index(s, `\`); idx >= 0 {
		user.Domain = s[:idx]
		user.Name = s[idx+1:]
	} else if idx := strings.Index(s, "@"); idx >= 0 {
		user.Name = s[:idx]
		user.Domain = s[idx+1:]
	} else {
		user.Name = s
	}

	return user
}

// logonTypeToString maps Windows logon type numbers to human-readable names.
func logonTypeToString(logonType string) string {
	n, err := strconv.Atoi(strings.TrimSpace(logonType))
	if err != nil {
		return "unknown"
	}

	switch n {
	case 2:
		return "interactive"
	case 3:
		return "network"
	case 4:
		return "batch"
	case 5:
		return "service"
	case 7:
		return "unlock"
	case 8:
		return "networkcleartext"
	case 9:
		return "newcredentials"
	case 10:
		return "remoteinteractive"
	case 11:
		return "cachedinteractive"
	default:
		return fmt.Sprintf("type%d", n)
	}
}

// kerberosStatusToOutcome maps Kerberos Status hex codes to ECS outcome.
func kerberosStatusToOutcome(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return "unknown"
	}
	if status == "0x0" || status == "0x00000000" {
		return "success"
	}
	return "failure"
}

// ============================================================================
// normalize.Parser implementations
// ============================================================================

// WinEvtXMLParser implements normalize.Parser for source_type "winevt_xml".
type WinEvtXMLParser struct{}

func NewWinEvtXMLParser() *WinEvtXMLParser { return &WinEvtXMLParser{} }

func (p *WinEvtXMLParser) SourceType() string { return "winevt_xml" }

func (p *WinEvtXMLParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	// The raw JSON envelope wraps XML as a string or contains the XML directly.
	// Try extracting XML string from JSON envelope first.
	var envelope struct {
		SourceType string `json:"source_type"`
		XML        string `json:"xml"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("winevt_xml parser: %w", err)
	}

	var xmlBytes []byte
	if envelope.XML != "" {
		xmlBytes = []byte(envelope.XML)
	} else {
		// Try raw as direct XML (for WEF collector that wraps XML in JSON).
		xmlBytes = raw
	}

	winEvent, err := ParseWinEventXML(xmlBytes)
	if err != nil {
		return nil, fmt.Errorf("winevt_xml parser: %w", err)
	}

	event := MapWinEventToECSWithSysmon(winEvent)
	return event, nil
}

// WinEvtJSONParser implements normalize.Parser for source_type "winevt_json".
type WinEvtJSONParser struct{}

func NewWinEvtJSONParser() *WinEvtJSONParser { return &WinEvtJSONParser{} }

func (p *WinEvtJSONParser) SourceType() string { return "winevt_json" }

func (p *WinEvtJSONParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	winEvent, err := ParseWinEventJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("winevt_json parser: %w", err)
	}

	event := MapWinEventToECSWithSysmon(winEvent)
	return event, nil
}
