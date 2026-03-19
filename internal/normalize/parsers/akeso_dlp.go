package parsers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// AkesoDLPParser normalizes Akeso DLP JSON events into ECS.
// Events arrive via the same /api/v1/ingest endpoint with source_type: "akeso_dlp".
type AkesoDLPParser struct{}

// NewAkesoDLPParser creates a new Akeso DLP parser.
func NewAkesoDLPParser() *AkesoDLPParser {
	return &AkesoDLPParser{}
}

// SourceType returns the source_type this parser handles.
func (p *AkesoDLPParser) SourceType() string {
	return "akeso_dlp"
}

// --- DLP event envelope ---

type dlpEnvelope struct {
	Timestamp string          `json:"timestamp"`
	Hostname  string          `json:"hostname"`
	EventType string          `json:"event_type"`
	User      *dlpUser        `json:"user,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type dlpUser struct {
	SID  string `json:"sid,omitempty"`
	Name string `json:"name,omitempty"`
}

// --- Payload structs per event type ---

type dlpPolicyViolationPayload struct {
	FilePath       string `json:"file_path"`
	FileSize       int64  `json:"file_size,omitempty"`
	PolicyName     string `json:"policy_name"`
	PolicyAction   string `json:"policy_action,omitempty"` // alert, block, audit
	Classification string `json:"classification"`          // confidential, internal, public, restricted
	Channel        string `json:"channel"`                 // email, upload, usb, print, share
}

type dlpClassificationPayload struct {
	FilePath       string `json:"file_path"`
	FileSize       int64  `json:"file_size,omitempty"`
	Classification string `json:"classification"` // label assigned
	PreviousLabel  string `json:"previous_label,omitempty"`
}

type dlpBlockPayload struct {
	FilePath       string `json:"file_path"`
	FileSize       int64  `json:"file_size,omitempty"`
	PolicyName     string `json:"policy_name"`
	PolicyAction   string `json:"policy_action,omitempty"`
	Classification string `json:"classification"`
	Channel        string `json:"channel"`
	Reason         string `json:"reason,omitempty"`
}

type dlpAuditPayload struct {
	FilePath       string `json:"file_path"`
	FileSize       int64  `json:"file_size,omitempty"`
	PolicyName     string `json:"policy_name"`
	PolicyAction   string `json:"policy_action,omitempty"`
	Classification string `json:"classification"`
	Channel        string `json:"channel"`
}

type dlpRemovableMediaPayload struct {
	FilePath       string `json:"file_path"`
	FileSize       int64  `json:"file_size,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	DeviceLabel    string `json:"device_label,omitempty"`
	PolicyName     string `json:"policy_name,omitempty"`
	PolicyAction   string `json:"policy_action,omitempty"`
	Classification string `json:"classification,omitempty"`
	Channel        string `json:"channel,omitempty"` // typically "usb"
}

// Parse normalizes a raw Akeso DLP JSON event into an ECSEvent.
func (p *AkesoDLPParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	var env dlpEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("akeso_dlp: unmarshal envelope: %w", err)
	}

	// Parse timestamp.
	ts, err := time.Parse(time.RFC3339, env.Timestamp)
	if err != nil {
		ts = time.Now().UTC()
	}

	// Build base event with common fields.
	event := &common.ECSEvent{
		Timestamp: ts,
		Event: &common.EventFields{
			Kind: "event",
		},
		Host: &common.HostFields{
			Name: env.Hostname,
		},
	}

	// Map user if present.
	if env.User != nil && (env.User.SID != "" || env.User.Name != "") {
		event.User = &common.UserFields{
			ID:   env.User.SID,
			Name: env.User.Name,
		}
	}

	// Dispatch by event type.
	switch env.EventType {
	case "dlp:policy_violation":
		if err := p.mapPolicyViolation(event, env.Payload); err != nil {
			return nil, err
		}
	case "dlp:classification":
		if err := p.mapClassification(event, env.Payload); err != nil {
			return nil, err
		}
	case "dlp:block":
		if err := p.mapBlock(event, env.Payload); err != nil {
			return nil, err
		}
	case "dlp:audit":
		if err := p.mapAudit(event, env.Payload); err != nil {
			return nil, err
		}
	case "dlp:removable_media":
		if err := p.mapRemovableMedia(event, env.Payload); err != nil {
			return nil, err
		}
	default:
		// Unknown event type — preserve what we can.
		event.Event.Action = env.EventType
	}

	return event, nil
}

// mapPolicyViolation handles dlp:policy_violation events.
func (p *AkesoDLPParser) mapPolicyViolation(event *common.ECSEvent, payload json.RawMessage) error {
	var pl dlpPolicyViolationPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_dlp: unmarshal policy_violation payload: %w", err)
	}

	event.Event.Category = []string{"file"}
	event.Event.Type = []string{"access"}
	event.Event.Action = "violation"
	event.Event.Outcome = "success"

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}

	// DLP fields.
	event.DLP = &common.DLPFields{
		Policy: &common.DLPPolicy{
			Name:   pl.PolicyName,
			Action: pl.PolicyAction,
		},
		Classification: pl.Classification,
		Channel:        pl.Channel,
	}

	return nil
}

// mapClassification handles dlp:classification events.
func (p *AkesoDLPParser) mapClassification(event *common.ECSEvent, payload json.RawMessage) error {
	var pl dlpClassificationPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_dlp: unmarshal classification payload: %w", err)
	}

	event.Event.Category = []string{"file"}
	event.Event.Type = []string{"change"}
	event.Event.Action = "classification"
	event.Event.Outcome = "success"

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}

	// DLP fields.
	event.DLP = &common.DLPFields{
		Classification: pl.Classification,
	}

	return nil
}

// mapBlock handles dlp:block events.
func (p *AkesoDLPParser) mapBlock(event *common.ECSEvent, payload json.RawMessage) error {
	var pl dlpBlockPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_dlp: unmarshal block payload: %w", err)
	}

	event.Event.Category = []string{"file"}
	event.Event.Type = []string{"denied"}
	event.Event.Action = "block"
	event.Event.Outcome = "failure"

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}

	// DLP fields.
	event.DLP = &common.DLPFields{
		Policy: &common.DLPPolicy{
			Name:   pl.PolicyName,
			Action: pl.PolicyAction,
		},
		Classification: pl.Classification,
		Channel:        pl.Channel,
	}

	return nil
}

// mapAudit handles dlp:audit events.
func (p *AkesoDLPParser) mapAudit(event *common.ECSEvent, payload json.RawMessage) error {
	var pl dlpAuditPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_dlp: unmarshal audit payload: %w", err)
	}

	event.Event.Category = []string{"file"}
	event.Event.Type = []string{"access"}
	event.Event.Action = "audit"
	event.Event.Outcome = "success"

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}

	// DLP fields.
	event.DLP = &common.DLPFields{
		Policy: &common.DLPPolicy{
			Name:   pl.PolicyName,
			Action: pl.PolicyAction,
		},
		Classification: pl.Classification,
		Channel:        pl.Channel,
	}

	return nil
}

// mapRemovableMedia handles dlp:removable_media events.
func (p *AkesoDLPParser) mapRemovableMedia(event *common.ECSEvent, payload json.RawMessage) error {
	var pl dlpRemovableMediaPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_dlp: unmarshal removable_media payload: %w", err)
	}

	event.Event.Category = []string{"file"}
	event.Event.Type = []string{"creation"}
	event.Event.Action = "removable_media_write"
	event.Event.Outcome = "success"

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}

	// Destination address = device ID (per spec: destination.address for device info).
	if pl.DeviceID != "" {
		event.Destination = &common.EndpointFields{
			Address: pl.DeviceID,
			Domain:  pl.DeviceLabel,
		}
	}

	// DLP fields.
	channel := pl.Channel
	if channel == "" {
		channel = "usb" // Default for removable media.
	}

	event.DLP = &common.DLPFields{
		Channel:        channel,
		Classification: pl.Classification,
	}
	if pl.PolicyName != "" {
		event.DLP.Policy = &common.DLPPolicy{
			Name:   pl.PolicyName,
			Action: pl.PolicyAction,
		}
	}

	return nil
}
