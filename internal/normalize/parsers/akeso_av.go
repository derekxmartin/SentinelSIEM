package parsers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// AkesoAVParser normalizes Akeso AV JSON events into ECS.
// Events arrive via the same /api/v1/ingest endpoint with source_type: "akeso_av".
type AkesoAVParser struct{}

// NewAkesoAVParser creates a new Akeso AV parser.
func NewAkesoAVParser() *AkesoAVParser {
	return &AkesoAVParser{}
}

// SourceType returns the source_type this parser handles.
func (p *AkesoAVParser) SourceType() string {
	return "akeso_av"
}

// --- AV event envelope ---

type avEnvelope struct {
	Timestamp string          `json:"timestamp"`
	Hostname  string          `json:"hostname"`
	EventType string          `json:"event_type"`
	User      *avUser         `json:"user,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type avUser struct {
	SID  string `json:"sid,omitempty"`
	Name string `json:"name,omitempty"`
}

// --- Payload structs per event type ---

type avScanResultPayload struct {
	FilePath      string `json:"file_path"`
	FileSize      int64  `json:"file_size,omitempty"`
	HashMD5       string `json:"hash_md5,omitempty"`
	HashSHA1      string `json:"hash_sha1,omitempty"`
	HashSHA256    string `json:"hash_sha256,omitempty"`
	Verdict       string `json:"verdict"`        // clean, malicious, suspicious
	SignatureName string `json:"signature_name,omitempty"`
	Engine        string `json:"engine,omitempty"`
}

type avQuarantinePayload struct {
	FilePath     string `json:"file_path"`
	OriginalPath string `json:"original_path,omitempty"`
	HashMD5      string `json:"hash_md5,omitempty"`
	HashSHA1     string `json:"hash_sha1,omitempty"`
	HashSHA256   string `json:"hash_sha256,omitempty"`
	FileSize     int64  `json:"file_size,omitempty"`
	Rule         string `json:"rule,omitempty"`
}

type avRealtimeBlockPayload struct {
	FilePath   string `json:"file_path"`
	HashMD5    string `json:"hash_md5,omitempty"`
	HashSHA1   string `json:"hash_sha1,omitempty"`
	HashSHA256 string `json:"hash_sha256,omitempty"`
	FileSize   int64  `json:"file_size,omitempty"`
	ProcessPID int    `json:"process_pid,omitempty"`
	ProcessExe string `json:"process_executable,omitempty"`
	ProcessCmd string `json:"process_command_line,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type avSignatureUpdatePayload struct {
	Version        string `json:"version"`
	SignatureCount int    `json:"signature_count,omitempty"`
	Engine         string `json:"engine,omitempty"`
}

type avScanErrorPayload struct {
	FilePath string `json:"file_path,omitempty"`
	Reason   string `json:"reason"`
	Engine   string `json:"engine,omitempty"`
}

// Parse normalizes a raw Akeso AV JSON event into an ECSEvent.
func (p *AkesoAVParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	var env avEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("akeso_av: unmarshal envelope: %w", err)
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
	case "av:scan_result":
		if err := p.mapScanResult(event, env.Payload); err != nil {
			return nil, err
		}
	case "av:quarantine":
		if err := p.mapQuarantine(event, env.Payload); err != nil {
			return nil, err
		}
	case "av:realtime_block":
		if err := p.mapRealtimeBlock(event, env.Payload); err != nil {
			return nil, err
		}
	case "av:signature_update":
		if err := p.mapSignatureUpdate(event, env.Payload); err != nil {
			return nil, err
		}
	case "av:scan_error":
		if err := p.mapScanError(event, env.Payload); err != nil {
			return nil, err
		}
	default:
		// Unknown event type — preserve what we can.
		event.Event.Action = env.EventType
	}

	return event, nil
}

// mapScanResult handles av:scan_result events.
func (p *AkesoAVParser) mapScanResult(event *common.ECSEvent, payload json.RawMessage) error {
	var pl avScanResultPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_av: unmarshal scan_result payload: %w", err)
	}

	event.Event.Category = []string{"malware"}
	event.Event.Type = []string{"info"}
	event.Event.Action = "scan_result"

	// Set outcome based on verdict.
	switch pl.Verdict {
	case "clean":
		event.Event.Outcome = "success"
	case "malicious", "suspicious":
		event.Event.Outcome = "failure"
	}

	// File fields.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}
	if pl.HashMD5 != "" || pl.HashSHA1 != "" || pl.HashSHA256 != "" {
		event.File.Hash = &common.HashFields{
			MD5:    pl.HashMD5,
			SHA1:   pl.HashSHA1,
			SHA256: pl.HashSHA256,
		}
	}

	// AV fields.
	event.AV = &common.AVFields{
		Scan: &common.AVScan{
			Result: pl.Verdict,
			Engine: pl.Engine,
		},
	}
	if pl.SignatureName != "" {
		event.AV.Signature = &common.AVSignature{
			Name: pl.SignatureName,
		}
	}

	return nil
}

// mapQuarantine handles av:quarantine events.
func (p *AkesoAVParser) mapQuarantine(event *common.ECSEvent, payload json.RawMessage) error {
	var pl avQuarantinePayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_av: unmarshal quarantine payload: %w", err)
	}

	event.Event.Category = []string{"malware"}
	event.Event.Type = []string{"deletion"}
	event.Event.Action = "quarantine"

	// Use original_path if available, else file_path.
	filePath := pl.OriginalPath
	if filePath == "" {
		filePath = pl.FilePath
	}

	event.File = &common.FileFields{
		Path: filePath,
		Name: fileNameFromPath(filePath),
		Size: pl.FileSize,
	}
	if pl.HashMD5 != "" || pl.HashSHA1 != "" || pl.HashSHA256 != "" {
		event.File.Hash = &common.HashFields{
			MD5:    pl.HashMD5,
			SHA1:   pl.HashSHA1,
			SHA256: pl.HashSHA256,
		}
	}

	event.AV = &common.AVFields{
		Action: "quarantine",
	}
	if pl.Rule != "" {
		event.AV.Signature = &common.AVSignature{
			Name: pl.Rule,
		}
	}

	return nil
}

// mapRealtimeBlock handles av:realtime_block events.
func (p *AkesoAVParser) mapRealtimeBlock(event *common.ECSEvent, payload json.RawMessage) error {
	var pl avRealtimeBlockPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_av: unmarshal realtime_block payload: %w", err)
	}

	event.Event.Category = []string{"malware"}
	event.Event.Type = []string{"denied"}
	event.Event.Action = "realtime_block"

	// Blocked process.
	if pl.ProcessPID != 0 || pl.ProcessExe != "" {
		event.Process = &common.ProcessFields{
			PID:         pl.ProcessPID,
			Executable:  pl.ProcessExe,
			Name:        fileNameFromPath(pl.ProcessExe),
			CommandLine: pl.ProcessCmd,
		}
	}

	// Blocked file.
	event.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}
	if pl.HashMD5 != "" || pl.HashSHA1 != "" || pl.HashSHA256 != "" {
		event.File.Hash = &common.HashFields{
			MD5:    pl.HashMD5,
			SHA1:   pl.HashSHA1,
			SHA256: pl.HashSHA256,
		}
	}

	event.AV = &common.AVFields{
		Action: "block",
	}

	return nil
}

// mapSignatureUpdate handles av:signature_update events.
func (p *AkesoAVParser) mapSignatureUpdate(event *common.ECSEvent, payload json.RawMessage) error {
	var pl avSignatureUpdatePayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_av: unmarshal signature_update payload: %w", err)
	}

	event.Event.Category = []string{"configuration"}
	event.Event.Type = []string{"change"}
	event.Event.Action = "signature_update"
	event.Event.Outcome = "success"

	event.AV = &common.AVFields{
		Scan: &common.AVScan{
			Engine: pl.Engine,
		},
		Signature: &common.AVSignature{
			Name: fmt.Sprintf("v%s (%d signatures)", pl.Version, pl.SignatureCount),
		},
	}

	return nil
}

// mapScanError handles av:scan_error events.
func (p *AkesoAVParser) mapScanError(event *common.ECSEvent, payload json.RawMessage) error {
	var pl avScanErrorPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return fmt.Errorf("akeso_av: unmarshal scan_error payload: %w", err)
	}

	event.Event.Category = []string{"malware"}
	event.Event.Type = []string{"info"}
	event.Event.Action = "scan_error"
	event.Event.Outcome = "failure"

	if pl.FilePath != "" {
		event.File = &common.FileFields{
			Path: pl.FilePath,
			Name: fileNameFromPath(pl.FilePath),
		}
	}

	event.AV = &common.AVFields{
		Scan: &common.AVScan{
			Result: "error",
			Engine: pl.Engine,
		},
	}

	return nil
}

// fileNameFromPath is defined in akeso_edr.go (shared within the package).
