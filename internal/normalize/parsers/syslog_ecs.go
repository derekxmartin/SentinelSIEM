package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	syslogParser "github.com/derekxmartin/akeso-siem/parsers"
)

// SyslogECSParser normalizes syslog events into ECS format.
// It parses RFC 5424/3164 headers and applies YAML-configured sub-parsers
// for structured field extraction.
type SyslogECSParser struct {
	subParsers *SubParserRegistry
}

// syslogEnvelope is the JSON envelope created by the syslog listener.
type syslogEnvelope struct {
	SourceType string `json:"source_type"`
	RawMessage string `json:"raw_message"`
	Transport  string `json:"transport"`
	RemoteAddr string `json:"remote_addr"`
}

// NewSyslogECSParser creates a syslog parser. If subParserDir is non-empty,
// YAML sub-parsers are loaded from that directory.
func NewSyslogECSParser(subParserDir string) (*SyslogECSParser, error) {
	var subParsers *SubParserRegistry
	if subParserDir != "" {
		var err error
		subParsers, err = LoadSubParsers(subParserDir)
		if err != nil {
			return nil, fmt.Errorf("syslog parser: loading sub-parsers: %w", err)
		}
	}

	return &SyslogECSParser{subParsers: subParsers}, nil
}

// SourceType returns "syslog".
func (p *SyslogECSParser) SourceType() string {
	return "syslog"
}

// Parse normalizes a raw syslog event (JSON envelope) into an ECS event.
func (p *SyslogECSParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("syslog: empty input")
	}

	var env syslogEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("syslog: invalid JSON envelope: %w", err)
	}

	if env.RawMessage == "" {
		return nil, fmt.Errorf("syslog: empty raw_message")
	}

	// Parse syslog header.
	sysMsg, err := syslogParser.ParseSyslog(env.RawMessage)
	if err != nil {
		return nil, fmt.Errorf("syslog: parse error: %w", err)
	}

	// Build base ECS event.
	event := &common.ECSEvent{
		Timestamp: sysMsg.Timestamp,
		Event: &common.EventFields{
			Kind:     "event",
			Severity: mapSyslogSeverity(sysMsg.Severity),
		},
	}

	// Use current time if timestamp is zero.
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Host.
	if sysMsg.Hostname != "" {
		event.Host = &common.HostFields{
			Name: sysMsg.Hostname,
		}
	}

	// Process from syslog tag.
	if sysMsg.AppName != "" {
		event.Process = &common.ProcessFields{
			Name: sysMsg.AppName,
		}
		if sysMsg.ProcID != "" {
			if pid, err := strconv.Atoi(sysMsg.ProcID); err == nil {
				event.Process.PID = pid
			}
		}
	}

	// Syslog metadata.
	if sysMsg.Facility >= 0 && sysMsg.Severity >= 0 {
		event.Log = &common.LogFields{
			Syslog: &common.SyslogLogFields{
				Facility: &common.SyslogFacility{
					Code: sysMsg.Facility,
					Name: syslogParser.SyslogFacilityName(sysMsg.Facility),
				},
				Severity: &common.SyslogSeverity{
					Code: sysMsg.Severity,
					Name: syslogParser.SyslogSeverityName(sysMsg.Severity),
				},
			},
		}
	}

	// Apply sub-parsers to extract structured fields.
	if p.subParsers != nil {
		result, matched := p.subParsers.Parse(sysMsg.AppName, sysMsg.Message)
		if matched {
			applySubParserResult(event, result)
			return event, nil
		}
	}

	// No sub-parser matched — set defaults and preserve raw.
	event.Event.Category = []string{"host"}
	event.Event.Type = []string{"info"}

	return event, nil
}

// applySubParserResult applies extracted fields from a sub-parser match to the ECS event.
func applySubParserResult(event *common.ECSEvent, result *SubParserResult) {
	// Set category/type from sub-parser result.
	if len(result.Category) > 0 {
		event.Event.Category = result.Category
	}
	if len(result.Type) > 0 {
		event.Event.Type = result.Type
	}
	if result.Action != "" {
		event.Event.Action = result.Action
	}

	// Apply mapped fields.
	for path, value := range result.Fields {
		applyECSField(event, path, value)
	}
}

// applyECSField sets a single ECS field on the event by dot-notation path.
func applyECSField(event *common.ECSEvent, path string, value string) {
	switch path {
	// Source fields.
	case "source.ip":
		if event.Source == nil {
			event.Source = &common.EndpointFields{}
		}
		event.Source.IP = value
	case "source.port":
		if event.Source == nil {
			event.Source = &common.EndpointFields{}
		}
		if port, err := strconv.Atoi(value); err == nil {
			event.Source.Port = port
		}

	// Destination fields.
	case "destination.ip":
		if event.Destination == nil {
			event.Destination = &common.EndpointFields{}
		}
		event.Destination.IP = value
	case "destination.port":
		if event.Destination == nil {
			event.Destination = &common.EndpointFields{}
		}
		if port, err := strconv.Atoi(value); err == nil {
			event.Destination.Port = port
		}

	// Network fields.
	case "network.protocol":
		if event.Network == nil {
			event.Network = &common.NetworkFields{}
		}
		event.Network.Protocol = value
	case "network.direction":
		if event.Network == nil {
			event.Network = &common.NetworkFields{}
		}
		event.Network.Direction = value

	// Process fields.
	case "process.pid":
		if event.Process == nil {
			event.Process = &common.ProcessFields{}
		}
		if pid, err := strconv.Atoi(value); err == nil {
			event.Process.PID = pid
		}
	case "process.name":
		if event.Process == nil {
			event.Process = &common.ProcessFields{}
		}
		event.Process.Name = value
	case "process.executable":
		if event.Process == nil {
			event.Process = &common.ProcessFields{}
		}
		event.Process.Executable = value
	case "process.command_line":
		if event.Process == nil {
			event.Process = &common.ProcessFields{}
		}
		event.Process.CommandLine = value

	// User fields.
	case "user.name":
		if event.User == nil {
			event.User = &common.UserFields{}
		}
		event.User.Name = value
	case "user.id":
		if event.User == nil {
			event.User = &common.UserFields{}
		}
		event.User.ID = value

	// File fields.
	case "file.path":
		if event.File == nil {
			event.File = &common.FileFields{}
		}
		event.File.Path = value
	case "file.name":
		if event.File == nil {
			event.File = &common.FileFields{}
		}
		event.File.Name = value

	// Event fields.
	case "event.action":
		event.Event.Action = value
	case "event.outcome":
		event.Event.Outcome = value

	// Observer fields (firewall interfaces).
	case "observer.ingress.interface.name":
		if event.Observer == nil {
			event.Observer = &common.ObserverFields{}
		}
		if event.Observer.Ingress == nil {
			event.Observer.Ingress = &common.InterfaceFields{}
		}
		event.Observer.Ingress.Name = value
	case "observer.egress.interface.name":
		if event.Observer == nil {
			event.Observer = &common.ObserverFields{}
		}
		if event.Observer.Egress == nil {
			event.Observer.Egress = &common.InterfaceFields{}
		}
		event.Observer.Egress.Name = value
	}
}

// mapSyslogSeverity maps RFC 5424 severity (0=emergency..7=debug) to ECS event.severity.
// ECS uses a numeric scale where higher = more severe. We map:
//
//	0 (emergency) → 100
//	1 (alert)     → 90
//	2 (critical)  → 80
//	3 (error)     → 70
//	4 (warning)   → 60
//	5 (notice)    → 50
//	6 (info)      → 40
//	7 (debug)     → 20
func mapSyslogSeverity(severity int) int {
	switch severity {
	case 0:
		return 100
	case 1:
		return 90
	case 2:
		return 80
	case 3:
		return 70
	case 4:
		return 60
	case 5:
		return 50
	case 6:
		return 40
	case 7:
		return 20
	default:
		return 0
	}
}
