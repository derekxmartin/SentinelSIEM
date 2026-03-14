package common

import (
	"encoding/json"
	"time"
)

// ECSEvent is the core normalized event structure used throughout SentinelSIEM.
// All ingested events are normalized into this schema before storage and correlation.
// Field groups follow the Elastic Common Schema (ECS) specification.
type ECSEvent struct {
	// Timestamp is the primary event time (ECS @timestamp).
	Timestamp time.Time `json:"@timestamp"`

	// ECS field groups — pointer types so empty groups are omitted from JSON.
	Event       *EventFields       `json:"event,omitempty"`
	Process     *ProcessFields     `json:"process,omitempty"`
	Source      *EndpointFields    `json:"source,omitempty"`
	Destination *EndpointFields    `json:"destination,omitempty"`
	User        *UserFields        `json:"user,omitempty"`
	Host        *HostFields        `json:"host,omitempty"`
	File        *FileFields        `json:"file,omitempty"`
	Registry    *RegistryFields    `json:"registry,omitempty"`
	Network     *NetworkFields     `json:"network,omitempty"`
	Threat      *ThreatFields      `json:"threat,omitempty"`
	DLP         *DLPFields         `json:"dlp,omitempty"`
	AV          *AVFields          `json:"av,omitempty"`

	// Raw preserves the original event payload before normalization.
	Raw json.RawMessage `json:"raw,omitempty"`
}

// EventFields captures event metadata (ECS event.* field set).
type EventFields struct {
	Kind     string   `json:"kind,omitempty"`
	Category []string `json:"category,omitempty"`
	Type     []string `json:"type,omitempty"`
	Action   string   `json:"action,omitempty"`
	Outcome  string   `json:"outcome,omitempty"`
	Severity int      `json:"severity,omitempty"`
}

// ProcessFields captures process information (ECS process.* field set).
type ProcessFields struct {
	PID         int            `json:"pid,omitempty"`
	Name        string         `json:"name,omitempty"`
	Executable  string         `json:"executable,omitempty"`
	CommandLine string         `json:"command_line,omitempty"`
	Parent      *ParentProcess `json:"parent,omitempty"`
}

// ParentProcess captures parent process info without further recursion.
type ParentProcess struct {
	PID         int    `json:"pid,omitempty"`
	Name        string `json:"name,omitempty"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// EndpointFields is used for both source.* and destination.* (ECS source/destination field sets).
type EndpointFields struct {
	IP     string     `json:"ip,omitempty"`
	Port   int        `json:"port,omitempty"`
	Domain string     `json:"domain,omitempty"`
	User   *UserFields `json:"user,omitempty"`
}

// UserFields captures user identity (ECS user.* field set).
type UserFields struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	ID     string `json:"id,omitempty"`
}

// HostFields captures host information (ECS host.* field set).
type HostFields struct {
	Name string   `json:"name,omitempty"`
	IP   []string `json:"ip,omitempty"`
	OS   *OSFields `json:"os,omitempty"`
}

// OSFields captures operating system information (ECS host.os.* field set).
type OSFields struct {
	Name     string `json:"name,omitempty"`
	Platform string `json:"platform,omitempty"`
	Version  string `json:"version,omitempty"`
}

// FileFields captures file information (ECS file.* field set).
type FileFields struct {
	Name string     `json:"name,omitempty"`
	Path string     `json:"path,omitempty"`
	Hash *HashFields `json:"hash,omitempty"`
	Size int64      `json:"size,omitempty"`
}

// HashFields captures file hash values (ECS file.hash.* field set).
type HashFields struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// RegistryFields captures Windows registry information (ECS registry.* field set).
type RegistryFields struct {
	Key   string             `json:"key,omitempty"`
	Value string             `json:"value,omitempty"`
	Data  *RegistryDataFields `json:"data,omitempty"`
}

// RegistryDataFields captures registry value data (ECS registry.data.* field set).
type RegistryDataFields struct {
	Type    string   `json:"type,omitempty"`
	Strings []string `json:"strings,omitempty"`
}

// NetworkFields captures network metadata (ECS network.* field set).
type NetworkFields struct {
	Protocol  string `json:"protocol,omitempty"`
	Direction string `json:"direction,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
}

// ThreatFields captures threat intelligence and MITRE ATT&CK mapping (ECS threat.* field set).
type ThreatFields struct {
	Technique []ThreatTechnique `json:"technique,omitempty"`
}

// ThreatTechnique represents a single MITRE ATT&CK technique reference.
type ThreatTechnique struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// DLPFields captures Data Loss Prevention event details (custom extension for Sentinel DLP).
type DLPFields struct {
	Policy         *DLPPolicy `json:"policy,omitempty"`
	Classification string     `json:"classification,omitempty"`
	Channel        string     `json:"channel,omitempty"`
}

// DLPPolicy captures DLP policy metadata.
type DLPPolicy struct {
	Name   string `json:"name,omitempty"`
	Action string `json:"action,omitempty"`
}

// AVFields captures antivirus event details (custom extension for Sentinel AV).
type AVFields struct {
	Scan      *AVScan `json:"scan,omitempty"`
	Signature *AVSignature `json:"signature,omitempty"`
	Action    string  `json:"action,omitempty"`
}

// AVScan captures AV scan result metadata.
type AVScan struct {
	Result string `json:"result,omitempty"`
	Engine string `json:"engine,omitempty"`
}

// AVSignature captures matched AV signature details.
type AVSignature struct {
	Name string `json:"name,omitempty"`
}
