package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// akeso_edrParser normalizes SENTINEL_EVENT JSON from the akeso_edr agent
// into ECS events. Events arrive wrapped in the akeso/v1 SIEM envelope.
type akeso_edrParser struct{}

// Newakeso_edrParser creates a new akeso_edr parser.
func Newakeso_edrParser() *akeso_edrParser {
	return &akeso_edrParser{}
}

// SourceType returns the source_type this parser handles.
func (p *akeso_edrParser) SourceType() string {
	return "akeso_edr"
}

// --- SIEM envelope (outer wrapper from siem_serializer.cpp) ---

type siemEnvelope struct {
	Schema    string          `json:"schema"`
	Host      string          `json:"host"`
	AgentID   string          `json:"agent_id"`
	Timestamp string          `json:"timestamp"`
	Event     json.RawMessage `json:"event"`
}

// --- Inner event structure (from json_writer.cpp) ---

type edrEvent struct {
	EventID   string          `json:"eventId"`
	Timestamp string          `json:"timestamp"`
	Source    string          `json:"source"`
	Severity string          `json:"severity"`
	Process  *edrProcess     `json:"process"`
	Payload  json.RawMessage `json:"payload"`
}

type edrProcess struct {
	PID             int    `json:"pid"`
	ParentPID       int    `json:"parentPid"`
	ThreadID        int    `json:"threadId"`
	SessionID       int    `json:"sessionId"`
	ImagePath       string `json:"imagePath"`
	CommandLine     string `json:"commandLine"`
	UserSID         string `json:"userSid"`
	IntegrityLevel  int    `json:"integrityLevel"`
	IsElevated      bool   `json:"isElevated"`
	ParentImagePath string `json:"parentImagePath"`
}

// --- Payload structs per source type ---

type processPayload struct {
	IsCreate        bool   `json:"isCreate"`
	NewProcessID    int    `json:"newProcessId"`
	ParentProcessID int    `json:"parentProcessId"`
	ImagePath       string `json:"imagePath"`
	CommandLine     string `json:"commandLine"`
	IntegrityLevel  int    `json:"integrityLevel"`
	IsElevated      bool   `json:"isElevated"`
	ExitStatus      string `json:"exitStatus"`
}

type threadPayload struct {
	IsCreate          bool   `json:"isCreate"`
	ThreadID          int    `json:"threadId"`
	OwningProcessID   int    `json:"owningProcessId"`
	CreatingProcessID int    `json:"creatingProcessId"`
	StartAddress      string `json:"startAddress"`
	IsRemote          bool   `json:"isRemote"`
}

type objectPayload struct {
	Operation       string `json:"operation"`
	ObjectType      string `json:"objectType"`
	SourceProcessID int    `json:"sourceProcessId"`
	TargetProcessID int    `json:"targetProcessId"`
	TargetImagePath string `json:"targetImagePath"`
	DesiredAccess   string `json:"desiredAccess"`
	GrantedAccess   string `json:"grantedAccess"`
}

type imageLoadPayload struct {
	ProcessID        int    `json:"processId"`
	ImagePath        string `json:"imagePath"`
	ImageBase        string `json:"imageBase"`
	ImageSize        string `json:"imageSize"`
	IsKernelImage    bool   `json:"isKernelImage"`
	IsSigned         bool   `json:"isSigned"`
	IsSignatureValid bool   `json:"isSignatureValid"`
}

type registryPayload struct {
	Operation string `json:"operation"`
	KeyPath   string `json:"keyPath"`
	ValueName string `json:"valueName"`
	DataType  int    `json:"dataType"`
	DataSize  int    `json:"dataSize"`
}

type filePayload struct {
	Operation   string `json:"operation"`
	ProcessID   int    `json:"processId"`
	FilePath    string `json:"filePath"`
	NewFilePath string `json:"newFilePath"`
	FileSize    int64  `json:"fileSize"`
	SHA256      string `json:"sha256"`
	HashSkipped bool   `json:"hashSkipped"`
}

type pipePayload struct {
	PipeName          string `json:"pipeName"`
	CreatingProcessID int    `json:"creatingProcessId"`
	AccessMode        string `json:"accessMode"`
	IsSuspicious      bool   `json:"isSuspicious"`
}

type networkPayload struct {
	Direction  string `json:"direction"`
	ProcessID  int    `json:"processId"`
	Protocol   int    `json:"protocol"`
	LocalAddr  string `json:"localAddr"`
	LocalPort  int    `json:"localPort"`
	RemoteAddr string `json:"remoteAddr"`
	RemotePort int    `json:"remotePort"`
}

type hookPayload struct {
	Function      string `json:"function"`
	TargetPID     int    `json:"targetPid"`
	BaseAddress   string `json:"baseAddress"`
	RegionSize    string `json:"regionSize"`
	Protection    string `json:"protection"`
	ReturnAddress string `json:"returnAddress"`
	CallingModule string `json:"callingModule"`
	StackHash     string `json:"stackHash"`
	ReturnStatus  string `json:"returnStatus"`
}

type etwPayload struct {
	Provider        string `json:"provider"`
	EventID         int    `json:"eventId"`
	Level           int    `json:"level"`
	Keyword         string `json:"keyword"`
	ProcessID       int    `json:"processId"`
	ThreadID        int    `json:"threadId"`
	// DotNETRuntime
	AssemblyName string `json:"assemblyName"`
	ClassName    string `json:"className"`
	// DnsClient
	QueryName   string `json:"queryName"`
	QueryType   int    `json:"queryType"`
	QueryStatus int    `json:"queryStatus"`
	// PowerShell
	ScriptBlock   string `json:"scriptBlock"`
	ScriptBlockID int    `json:"scriptBlockId"`
	// Kerberos
	TargetName  string `json:"targetName"`
	Status      int    `json:"status"`
	TicketFlags int    `json:"ticketFlags"`
	// RPC
	InterfaceUUID string `json:"interfaceUuid"`
	OpNum         int    `json:"opNum"`
	// KernelProcess
	ParentProcessID int    `json:"parentProcessId"`
	ImageName       string `json:"imageName"`
}

type amsiPayload struct {
	AppName     string `json:"appName"`
	ContentSize int    `json:"contentSize"`
	ScanResult  string `json:"scanResult"`
	MatchedRule string `json:"matchedRule"`
}

type scannerPayload struct {
	ScanType        string `json:"scanType"`
	TargetPath      string `json:"targetPath"`
	TargetProcessID int    `json:"targetProcessId"`
	IsMatch         bool   `json:"isMatch"`
	YARARule        string `json:"yaraRule"`
	SHA256          string `json:"sha256"`
}

type alertPayload struct {
	RuleName       string `json:"ruleName"`
	Severity       string `json:"severity"`
	TriggerSource  string `json:"triggerSource"`
	TriggerEventID string `json:"triggerEventId"`
}

type tamperPayload struct {
	TamperType string `json:"tamperType"`
	ProcessID  int    `json:"processId"`
	Detail     string `json:"detail"`
}

// Parse normalizes a raw akeso_edr JSON event into an ECSEvent.
func (p *akeso_edrParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	// Unwrap SIEM envelope.
	var env siemEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("akeso_edr: unmarshal envelope: %w", err)
	}

	// Parse inner event.
	var inner edrEvent
	if err := json.Unmarshal(env.Event, &inner); err != nil {
		return nil, fmt.Errorf("akeso_edr: unmarshal inner event: %w", err)
	}

	// Build base ECS event with common fields.
	ecs := p.buildBase(&env, &inner)

	// Dispatch to source-specific mapper.
	switch inner.Source {
	case "DriverProcess":
		p.mapProcess(ecs, inner.Payload)
	case "DriverThread":
		p.mapThread(ecs, inner.Payload)
	case "DriverObject":
		p.mapObject(ecs, inner.Payload)
	case "DriverImageLoad":
		p.mapImageLoad(ecs, inner.Payload)
	case "DriverRegistry":
		p.mapRegistry(ecs, inner.Payload)
	case "DriverMinifilter":
		p.mapFile(ecs, inner.Payload)
	case "DriverPipe":
		p.mapPipe(ecs, inner.Payload)
	case "DriverNetwork":
		p.mapNetwork(ecs, inner.Payload)
	case "HookDll":
		p.mapHook(ecs, inner.Payload)
	case "Etw":
		p.mapETW(ecs, inner.Payload)
	case "Amsi":
		p.mapAMSI(ecs, inner.Payload)
	case "Scanner":
		p.mapScanner(ecs, inner.Payload)
	case "RuleEngine":
		p.mapAlert(ecs, inner.Payload)
	case "SelfProtect":
		p.mapTamper(ecs, inner.Payload)
	default:
		// Unknown source — set generic event fields, common fields already populated.
		ecs.Event.Category = []string{"host"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = inner.Source
	}

	return ecs, nil
}

// buildBase creates an ECSEvent with common fields populated from the envelope and inner event.
func (p *akeso_edrParser) buildBase(env *siemEnvelope, inner *edrEvent) *common.ECSEvent {
	ts := parseTimestamp(env.Timestamp)

	ecs := &common.ECSEvent{
		Timestamp: ts,
		Event: &common.EventFields{
			Kind:     "event",
			Severity: mapSeverity(inner.Severity),
		},
		Host: &common.HostFields{
			Name: env.Host,
		},
	}

	// Map process context (present on all events).
	if inner.Process != nil {
		proc := inner.Process
		ecs.Process = &common.ProcessFields{
			PID:         proc.PID,
			Executable:  proc.ImagePath,
			CommandLine: proc.CommandLine,
			Name:        fileNameFromPath(proc.ImagePath),
		}
		if proc.ParentPID > 0 || proc.ParentImagePath != "" {
			ecs.Process.Parent = &common.ParentProcess{
				PID:        proc.ParentPID,
				Executable: proc.ParentImagePath,
				Name:       fileNameFromPath(proc.ParentImagePath),
			}
		}
		if proc.UserSID != "" {
			ecs.User = &common.UserFields{
				ID: proc.UserSID,
			}
		}
	}

	return ecs
}

// --- Source-specific mappers ---

func (p *akeso_edrParser) mapProcess(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl processPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"process"}
	if pl.IsCreate {
		ecs.Event.Type = []string{"start"}
		ecs.Event.Action = "process_created"
		// Payload has richer info about the new process — override from payload.
		if pl.NewProcessID > 0 {
			ecs.Process.PID = pl.NewProcessID
		}
		if pl.ImagePath != "" {
			ecs.Process.Executable = pl.ImagePath
			ecs.Process.Name = fileNameFromPath(pl.ImagePath)
		}
		if pl.CommandLine != "" {
			ecs.Process.CommandLine = pl.CommandLine
		}
		if pl.ParentProcessID > 0 && ecs.Process.Parent != nil {
			ecs.Process.Parent.PID = pl.ParentProcessID
		}
	} else {
		ecs.Event.Type = []string{"end"}
		ecs.Event.Action = "process_terminated"
	}
}

func (p *akeso_edrParser) mapThread(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl threadPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"process"}
	if pl.IsCreate {
		ecs.Event.Type = []string{"start"}
	} else {
		ecs.Event.Type = []string{"end"}
	}

	if pl.IsRemote {
		ecs.Event.Action = "remote_thread_created"
	} else {
		ecs.Event.Action = "thread_created"
	}
}

func (p *akeso_edrParser) mapObject(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl objectPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"process"}
	ecs.Event.Type = []string{"access"}
	ecs.Event.Action = "object_handle_" + strings.ToLower(pl.Operation)
}

func (p *akeso_edrParser) mapImageLoad(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl imageLoadPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"process"}
	ecs.Event.Type = []string{"info"}
	ecs.Event.Action = "image_loaded"

	if pl.ImagePath != "" {
		ecs.File = &common.FileFields{
			Path: pl.ImagePath,
			Name: fileNameFromPath(pl.ImagePath),
		}
	}
}

func (p *akeso_edrParser) mapRegistry(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl registryPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"registry"}
	ecs.Event.Action = "registry_" + strings.ToLower(pl.Operation)

	switch pl.Operation {
	case "CreateKey":
		ecs.Event.Type = []string{"creation"}
	case "DeleteKey", "DeleteValue":
		ecs.Event.Type = []string{"deletion"}
	default: // SetValue, OpenKey, RenameKey
		ecs.Event.Type = []string{"change"}
	}

	ecs.Registry = &common.RegistryFields{
		Key:   pl.KeyPath,
		Value: pl.ValueName,
	}
}

func (p *akeso_edrParser) mapFile(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl filePayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"file"}
	ecs.Event.Action = "file_" + strings.ToLower(pl.Operation)

	switch pl.Operation {
	case "Create":
		ecs.Event.Type = []string{"creation"}
	case "Write":
		ecs.Event.Type = []string{"change"}
	case "Delete":
		ecs.Event.Type = []string{"deletion"}
	case "Rename":
		ecs.Event.Type = []string{"change"}
	case "SetInfo":
		ecs.Event.Type = []string{"change"}
	default:
		ecs.Event.Type = []string{"info"}
	}

	ecs.File = &common.FileFields{
		Path: pl.FilePath,
		Name: fileNameFromPath(pl.FilePath),
		Size: pl.FileSize,
	}
	if pl.SHA256 != "" {
		ecs.File.Hash = &common.HashFields{
			SHA256: pl.SHA256,
		}
	}
}

func (p *akeso_edrParser) mapPipe(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl pipePayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"file"}
	ecs.Event.Type = []string{"creation"}
	ecs.Event.Action = "named_pipe_created"

	ecs.File = &common.FileFields{
		Name: pl.PipeName,
	}
}

func (p *akeso_edrParser) mapNetwork(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl networkPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"network"}
	ecs.Event.Type = []string{"connection"}
	ecs.Event.Action = "network_" + strings.ToLower(pl.Direction)

	ecs.Source = &common.EndpointFields{
		IP:   pl.LocalAddr,
		Port: pl.LocalPort,
	}
	ecs.Destination = &common.EndpointFields{
		IP:   pl.RemoteAddr,
		Port: pl.RemotePort,
	}

	proto := "unknown"
	switch pl.Protocol {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	}

	ecs.Network = &common.NetworkFields{
		Protocol:  proto,
		Direction: strings.ToLower(pl.Direction),
	}
}

func (p *akeso_edrParser) mapHook(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl hookPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"process"}
	ecs.Event.Type = []string{"change"}
	ecs.Event.Action = pl.Function
}

func (p *akeso_edrParser) mapETW(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl etwPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	switch pl.Provider {
	case "DnsClient":
		ecs.Event.Category = []string{"network"}
		ecs.Event.Type = []string{"protocol"}
		ecs.Event.Action = "dns_query"
		ecs.Network = &common.NetworkFields{
			Protocol: "dns",
		}
		if pl.QueryName != "" {
			ecs.Destination = &common.EndpointFields{
				Domain: pl.QueryName,
			}
		}
	case "DotNETRuntime":
		ecs.Event.Category = []string{"process"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "dotnet_assembly_loaded"
	case "PowerShell":
		ecs.Event.Category = []string{"process"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "powershell_script_block"
	case "Kerberos", "Security-Kerberos":
		ecs.Event.Category = []string{"authentication"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "kerberos_ticket_request"
	case "Services":
		ecs.Event.Category = []string{"process"}
		ecs.Event.Type = []string{"change"}
		ecs.Event.Action = "service_state_change"
	case "RPC":
		ecs.Event.Category = []string{"process"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "rpc_call"
	case "KernelProcess":
		ecs.Event.Category = []string{"process"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "kernel_process_event"
	default:
		ecs.Event.Category = []string{"host"}
		ecs.Event.Type = []string{"info"}
		ecs.Event.Action = "etw_" + strings.ToLower(pl.Provider)
	}
}

func (p *akeso_edrParser) mapAMSI(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl amsiPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"intrusion_detection"}
	ecs.Event.Type = []string{"info"}
	ecs.Event.Action = "amsi_scan"

	switch pl.ScanResult {
	case "Malware", "Blocked":
		ecs.Event.Outcome = "failure" // malicious content detected
	case "Suspicious":
		ecs.Event.Outcome = "unknown"
	default: // Clean
		ecs.Event.Outcome = "success"
	}
}

func (p *akeso_edrParser) mapScanner(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl scannerPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"malware"}
	ecs.Event.Type = []string{"info"}
	ecs.Event.Action = "yara_scan_" + strings.ToLower(pl.ScanType)

	if pl.IsMatch {
		ecs.Event.Outcome = "failure" // threat found
	} else {
		ecs.Event.Outcome = "success" // clean
	}

	if pl.TargetPath != "" {
		ecs.File = &common.FileFields{
			Path: pl.TargetPath,
			Name: fileNameFromPath(pl.TargetPath),
		}
		if pl.SHA256 != "" {
			ecs.File.Hash = &common.HashFields{
				SHA256: pl.SHA256,
			}
		}
	}
}

func (p *akeso_edrParser) mapAlert(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl alertPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Kind = "alert"
	ecs.Event.Category = []string{"intrusion_detection"}
	ecs.Event.Type = []string{"indicator"}
	ecs.Event.Action = pl.RuleName

	// Override severity from the alert payload if present.
	if pl.Severity != "" {
		ecs.Event.Severity = mapSeverity(pl.Severity)
	}
}

func (p *akeso_edrParser) mapTamper(ecs *common.ECSEvent, payload json.RawMessage) {
	var pl tamperPayload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return
	}

	ecs.Event.Category = []string{"intrusion_detection"}
	ecs.Event.Type = []string{"info"}
	ecs.Event.Action = "tamper_" + strings.ToLower(pl.TamperType)
}

// --- Helpers ---

// mapSeverity converts EDR severity strings to ECS numeric severity.
func mapSeverity(s string) int {
	switch s {
	case "Informational":
		return 0
	case "Low":
		return 25
	case "Medium":
		return 50
	case "High":
		return 75
	case "Critical":
		return 100
	default:
		return 0
	}
}

// parseTimestamp parses an ISO8601 timestamp, falling back to time.Now() on failure.
func parseTimestamp(s string) time.Time {
	// Try RFC3339 (ISO8601 with timezone).
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	// Try RFC3339Nano.
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

// fileNameFromPath extracts the file name from a full path.
func fileNameFromPath(path string) string {
	if path == "" {
		return ""
	}
	// Handle both Windows and Unix paths.
	name := filepath.Base(path)
	// filepath.Base on Linux won't split backslash paths — handle manually.
	if idx := strings.LastIndexAny(path, `\/`); idx >= 0 {
		name = path[idx+1:]
	}
	return name
}
