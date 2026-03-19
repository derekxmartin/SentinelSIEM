package parsers

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// AkesoNDRParser normalizes AkesoNDR JSON events into ECS.
// NDR events arrive pre-normalized — the parser validates ECS field presence,
// adds event.ingested, tags source_type, and ensures custom extension fields
// (ndr.*, dns.*, tls.*, smb.*, kerberos.*, ssh.*) are correctly preserved.
type AkesoNDRParser struct{}

// NewAkesoNDRParser creates a new AkesoNDR parser.
func NewAkesoNDRParser() *AkesoNDRParser {
	return &AkesoNDRParser{}
}

// SourceType returns the source_type this parser handles.
func (p *AkesoNDRParser) SourceType() string {
	return "akeso_ndr"
}

// --- NDR event envelope ---
// NDR events are pre-normalized to ECS by the AkesoNDR export pipeline.
// The envelope carries ECS fields directly at the top level.

type ndrEnvelope struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`

	// Pre-normalized ECS field groups.
	Event       *common.EventFields    `json:"event,omitempty"`
	Source      *common.EndpointFields `json:"source,omitempty"`
	Destination *common.EndpointFields `json:"destination,omitempty"`
	Network     *common.NetworkFields  `json:"network,omitempty"`
	Host        *common.HostFields     `json:"host,omitempty"`
	User        *common.UserFields     `json:"user,omitempty"`
	Threat      *common.ThreatFields   `json:"threat,omitempty"`
	Observer    *common.ObserverFields `json:"observer,omitempty"`
	Process     *common.ProcessFields  `json:"process,omitempty"`
	File        *common.FileFields     `json:"file,omitempty"`

	// Protocol-specific ECS fields.
	DNS       *common.DNSFields       `json:"dns,omitempty"`
	HTTP      *common.HTTPFields      `json:"http,omitempty"`
	TLS       *common.TLSFields       `json:"tls,omitempty"`
	URL       *common.URLFields       `json:"url,omitempty"`
	UserAgent *common.UserAgentFields `json:"user_agent,omitempty"`
	SMB       *common.SMBFields       `json:"smb,omitempty"`
	Kerberos  *common.KerberosFields  `json:"kerberos,omitempty"`
	SSH       *common.SSHFields       `json:"ssh,omitempty"`

	// NDR custom extension fields.
	NDR *common.NDRFields `json:"ndr,omitempty"`
}

// Parse validates and enriches a pre-normalized AkesoNDR event.
func (p *AkesoNDRParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	var env ndrEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("akeso_ndr: unmarshal: %w", err)
	}

	// Parse timestamp with RFC3339 fallback.
	ts, err := time.Parse(time.RFC3339Nano, env.Timestamp)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, env.Timestamp)
		if err != nil {
			ts = time.Now().UTC()
		}
	}

	now := time.Now().UTC()

	// Build ECSEvent by copying pre-normalized fields directly.
	event := &common.ECSEvent{
		Timestamp:   ts,
		Event:       env.Event,
		Source:      env.Source,
		Destination: env.Destination,
		Network:     env.Network,
		Host:        env.Host,
		User:        env.User,
		Threat:      env.Threat,
		Observer:    env.Observer,
		Process:     env.Process,
		File:        env.File,
		DNS:         env.DNS,
		HTTP:        env.HTTP,
		TLS:         env.TLS,
		URL:         env.URL,
		UserAgent:   env.UserAgent,
		SMB:         env.SMB,
		Kerberos:    env.Kerberos,
		SSH:         env.SSH,
		NDR:         env.NDR,
	}

	// Ensure event fields exist and stamp ingestion time.
	if event.Event == nil {
		event.Event = &common.EventFields{}
	}
	if event.Event.Kind == "" {
		event.Event.Kind = "event"
	}
	event.Event.Ingested = &now

	// Validate and enrich per event type.
	var warnings []string
	switch env.EventType {
	case "ndr:session":
		warnings = p.validateSession(event)
	case "ndr:dns":
		warnings = p.validateDNS(event)
	case "ndr:http":
		warnings = p.validateHTTP(event)
	case "ndr:tls":
		warnings = p.validateTLS(event)
	case "ndr:smb":
		warnings = p.validateSMB(event)
	case "ndr:kerberos":
		warnings = p.validateKerberos(event)
	case "ndr:ssh":
		warnings = p.validateSSH(event)
	case "ndr:smtp":
		warnings = p.validateSMTP(event)
	case "ndr:rdp":
		warnings = p.validateRDP(event)
	case "ndr:ntlm":
		warnings = p.validateNTLM(event)
	case "ndr:ldap":
		warnings = p.validateLDAP(event)
	case "ndr:dcerpc":
		warnings = p.validateDCERPC(event)
	case "ndr:detection":
		warnings = p.validateDetection(event)
	case "ndr:signature":
		warnings = p.validateSignature(event)
	case "ndr:host_score":
		warnings = p.validateHostScore(event)
	default:
		event.Event.Action = env.EventType
		warnings = append(warnings, fmt.Sprintf("unknown event_type %q", env.EventType))
	}

	// Log any validation warnings (non-fatal).
	for _, w := range warnings {
		log.Printf("akeso_ndr: %s: %s", env.EventType, w)
	}

	return event, nil
}

// --- Validation methods ---
// Each returns a list of non-fatal warnings. Missing required fields are
// warned about but do not cause parse failure — the event is preserved.

func (p *AkesoNDRParser) validateSession(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network_connection"})
	ensureType(e, []string{"connection"})
	if e.Event.Action == "" {
		e.Event.Action = "session"
	}

	if e.Source == nil {
		warnings = append(warnings, "missing source fields")
	}
	if e.Destination == nil {
		warnings = append(warnings, "missing destination fields")
	}
	if e.NDR == nil || e.NDR.Session == nil {
		warnings = append(warnings, "missing ndr.session fields")
	} else if e.NDR.Session.CommunityID == "" {
		warnings = append(warnings, "missing ndr.session.community_id")
	}
	// Sync community_id to network.community_id for cross-source correlation.
	if e.NDR != nil && e.NDR.Session != nil && e.NDR.Session.CommunityID != "" {
		if e.Network == nil {
			e.Network = &common.NetworkFields{}
		}
		if e.Network.CommunityID == "" {
			e.Network.CommunityID = e.NDR.Session.CommunityID
		}
	}
	return warnings
}

func (p *AkesoNDRParser) validateDNS(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "dns_query"
	}

	if e.DNS == nil {
		warnings = append(warnings, "missing dns fields")
	} else if e.DNS.Question == nil || e.DNS.Question.Name == "" {
		warnings = append(warnings, "missing dns.question.name")
	}
	return warnings
}

func (p *AkesoNDRParser) validateHTTP(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network", "web"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "http_request"
	}

	if e.HTTP == nil {
		warnings = append(warnings, "missing http fields")
	}
	return warnings
}

func (p *AkesoNDRParser) validateTLS(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "tls_handshake"
	}

	if e.TLS == nil {
		warnings = append(warnings, "missing tls fields")
	}
	return warnings
}

func (p *AkesoNDRParser) validateSMB(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		if e.SMB != nil && e.SMB.Action != "" {
			e.Event.Action = "smb_" + e.SMB.Action
		} else {
			e.Event.Action = "smb"
		}
	}

	if e.SMB == nil {
		warnings = append(warnings, "missing smb fields")
	}
	return warnings
}

func (p *AkesoNDRParser) validateKerberos(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network", "authentication"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "kerberos"
	}

	if e.Kerberos == nil {
		warnings = append(warnings, "missing kerberos fields")
	}
	return warnings
}

func (p *AkesoNDRParser) validateSSH(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "ssh_connection"
	}

	if e.SSH == nil {
		warnings = append(warnings, "missing ssh fields")
	}
	return warnings
}

func (p *AkesoNDRParser) validateSMTP(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "smtp"
	}
	return p.validateNetworkBase(e, warnings)
}

func (p *AkesoNDRParser) validateRDP(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "rdp"
	}
	return p.validateNetworkBase(e, warnings)
}

func (p *AkesoNDRParser) validateNTLM(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network", "authentication"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "ntlm"
	}
	return p.validateNetworkBase(e, warnings)
}

func (p *AkesoNDRParser) validateLDAP(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "ldap"
	}
	return p.validateNetworkBase(e, warnings)
}

func (p *AkesoNDRParser) validateDCERPC(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"network"})
	ensureType(e, []string{"protocol"})
	if e.Event.Action == "" {
		e.Event.Action = "dcerpc"
	}
	return p.validateNetworkBase(e, warnings)
}

func (p *AkesoNDRParser) validateDetection(e *common.ECSEvent) []string {
	var warnings []string
	e.Event.Kind = "alert"
	ensureCategory(e, []string{"intrusion_detection"})
	ensureType(e, []string{"info"})
	if e.Event.Action == "" {
		e.Event.Action = "detection"
	}

	if e.NDR == nil || e.NDR.Detection == nil {
		warnings = append(warnings, "missing ndr.detection fields")
	} else if e.NDR.Detection.Name == "" {
		warnings = append(warnings, "missing ndr.detection.name")
	}
	return warnings
}

func (p *AkesoNDRParser) validateSignature(e *common.ECSEvent) []string {
	var warnings []string
	e.Event.Kind = "alert"
	ensureCategory(e, []string{"intrusion_detection"})
	ensureType(e, []string{"info"})
	if e.Event.Action == "" {
		e.Event.Action = "signature"
	}

	if e.NDR == nil || e.NDR.Detection == nil {
		warnings = append(warnings, "missing ndr.detection fields for signature")
	}
	return warnings
}

func (p *AkesoNDRParser) validateHostScore(e *common.ECSEvent) []string {
	var warnings []string
	ensureCategory(e, []string{"host"})
	ensureType(e, []string{"info"})
	if e.Event.Action == "" {
		e.Event.Action = "host_score_update"
	}

	if e.NDR == nil || e.NDR.HostScore == nil {
		warnings = append(warnings, "missing ndr.host_score fields")
	} else {
		if e.NDR.HostScore.Quadrant == "" {
			warnings = append(warnings, "missing ndr.host_score.quadrant")
		}
	}
	return warnings
}

// --- Helpers ---

// validateNetworkBase checks that basic network fields (source, destination) are present.
func (p *AkesoNDRParser) validateNetworkBase(e *common.ECSEvent, warnings []string) []string {
	if e.Source == nil {
		warnings = append(warnings, "missing source fields")
	}
	if e.Destination == nil {
		warnings = append(warnings, "missing destination fields")
	}
	return warnings
}

// ensureCategory sets event.category if not already set by the pre-normalized event.
func ensureCategory(e *common.ECSEvent, categories []string) {
	if len(e.Event.Category) == 0 {
		e.Event.Category = categories
	}
}

// ensureType sets event.type if not already set by the pre-normalized event.
func ensureType(e *common.ECSEvent, types []string) {
	if len(e.Event.Type) == 0 {
		e.Event.Type = types
	}
}
