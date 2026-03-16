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
	DNS         *DNSFields         `json:"dns,omitempty"`
	HTTP        *HTTPFields        `json:"http,omitempty"`
	TLS         *TLSFields         `json:"tls,omitempty"`
	URL         *URLFields         `json:"url,omitempty"`
	UserAgent   *UserAgentFields   `json:"user_agent,omitempty"`
	SMB         *SMBFields         `json:"smb,omitempty"`
	Kerberos    *KerberosFields    `json:"kerberos,omitempty"`
	SSH         *SSHFields         `json:"ssh,omitempty"`
	NDR         *NDRFields         `json:"ndr,omitempty"`
	Observer    *ObserverFields    `json:"observer,omitempty"`
	Rule        *RuleFields        `json:"rule,omitempty"`
	Log         *LogFields         `json:"log,omitempty"`
	WinEvt      *WinEvtFields      `json:"winevt,omitempty"`

	// SourceType identifies the originating source (e.g., "sentinel_edr", "sentinel_av").
	// Used by the pipeline to route events to the correct ES index.
	// Not part of ECS — excluded from JSON sent to Elasticsearch.
	SourceType string `json:"-"`

	// Raw preserves the original event payload before normalization.
	Raw json.RawMessage `json:"raw,omitempty"`
}

// EventFields captures event metadata (ECS event.* field set).
type EventFields struct {
	Kind     string     `json:"kind,omitempty"`
	Category []string   `json:"category,omitempty"`
	Type     []string   `json:"type,omitempty"`
	Action   string     `json:"action,omitempty"`
	Outcome  string     `json:"outcome,omitempty"`
	Severity int        `json:"severity,omitempty"`
	Ingested *time.Time `json:"ingested,omitempty"`
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
	IP      string      `json:"ip,omitempty"`
	Port    int         `json:"port,omitempty"`
	Domain  string      `json:"domain,omitempty"`
	Address string      `json:"address,omitempty"`
	User    *UserFields `json:"user,omitempty"`
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
	Protocol    string `json:"protocol,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Packets     int64  `json:"packets,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
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

// ObserverFields captures observer/sensor information (ECS observer.* field set).
// Used for network devices (firewalls, IDS) that report events about other hosts.
type ObserverFields struct {
	Name    string           `json:"name,omitempty"`
	Type    string           `json:"type,omitempty"`
	Ingress *InterfaceFields `json:"ingress,omitempty"`
	Egress  *InterfaceFields `json:"egress,omitempty"`
}

// InterfaceFields captures network interface information.
type InterfaceFields struct {
	Name string `json:"name,omitempty"`
}

// RuleFields captures detection rule metadata (ECS rule.* field set).
// Used for alert documents to record which rule triggered the alert.
type RuleFields struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category,omitempty"`
	Ruleset     string   `json:"ruleset,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   string   `json:"reference,omitempty"`
	Author      string   `json:"author,omitempty"`
}

// WinEvtFields captures Windows Event Log metadata (custom extension for logsource routing).
type WinEvtFields struct {
	Channel  string `json:"channel,omitempty"`
	Provider string `json:"provider,omitempty"`
	EventID  int    `json:"event_id,omitempty"`
}

// LogFields captures log metadata (ECS log.* field set).
type LogFields struct {
	Syslog *SyslogLogFields `json:"syslog,omitempty"`
}

// SyslogLogFields captures syslog-specific metadata (ECS log.syslog.* field set).
type SyslogLogFields struct {
	Facility *SyslogFacility `json:"facility,omitempty"`
	Severity *SyslogSeverity `json:"severity,omitempty"`
}

// SyslogFacility captures syslog facility information.
type SyslogFacility struct {
	Code int    `json:"code"`
	Name string `json:"name,omitempty"`
}

// SyslogSeverity captures syslog severity information.
type SyslogSeverity struct {
	Code int    `json:"code"`
	Name string `json:"name,omitempty"`
}

// DNSFields captures DNS query/response metadata (ECS dns.* field set).
type DNSFields struct {
	Question     *DNSQuestion `json:"question,omitempty"`
	Answers      []DNSAnswer  `json:"answers,omitempty"`
	ResponseCode string       `json:"response_code,omitempty"`
	HeaderFlags  []string     `json:"header_flags,omitempty"`
}

// DNSQuestion captures the DNS question section.
type DNSQuestion struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// DNSAnswer captures a single DNS answer record.
type DNSAnswer struct {
	Data string `json:"data,omitempty"`
	Type string `json:"type,omitempty"`
	TTL  int    `json:"ttl,omitempty"`
}

// HTTPFields captures HTTP request/response metadata (ECS http.* field set).
type HTTPFields struct {
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}

// HTTPRequest captures HTTP request metadata.
type HTTPRequest struct {
	Method string `json:"method,omitempty"`
}

// HTTPResponse captures HTTP response metadata.
type HTTPResponse struct {
	StatusCode int            `json:"status_code,omitempty"`
	Body       *HTTPBodyFields `json:"body,omitempty"`
}

// HTTPBodyFields captures HTTP body size metadata.
type HTTPBodyFields struct {
	Bytes int64 `json:"bytes,omitempty"`
}

// URLFields captures URL metadata (ECS url.* field set).
type URLFields struct {
	Full string `json:"full,omitempty"`
}

// UserAgentFields captures user agent metadata (ECS user_agent.* field set).
type UserAgentFields struct {
	Original string `json:"original,omitempty"`
}

// TLSFields captures TLS handshake metadata (ECS tls.* field set).
type TLSFields struct {
	Version string           `json:"version,omitempty"`
	Cipher  string           `json:"cipher,omitempty"`
	Client  *TLSClientFields `json:"client,omitempty"`
	Server  *TLSServerFields `json:"server,omitempty"`
}

// TLSClientFields captures TLS client-side metadata.
type TLSClientFields struct {
	JA3        string `json:"ja3,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

// TLSServerFields captures TLS server-side metadata.
type TLSServerFields struct {
	JA3S string `json:"ja3s,omitempty"`
	JA4S string `json:"ja4s,omitempty"`
}

// SMBFields captures SMB protocol metadata (custom extension for NDR events).
type SMBFields struct {
	Version  string `json:"version,omitempty"`
	Action   string `json:"action,omitempty"`
	Filename string `json:"filename,omitempty"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Username string `json:"username,omitempty"`
}

// KerberosFields captures Kerberos authentication metadata (custom extension for NDR events).
type KerberosFields struct {
	RequestType string `json:"request_type,omitempty"`
	Client      string `json:"client,omitempty"`
	Service     string `json:"service,omitempty"`
	Cipher      string `json:"cipher,omitempty"`
	Success     *bool  `json:"success,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// SSHFields captures SSH protocol metadata (ECS ssh.* field set).
type SSHFields struct {
	Client      string `json:"client,omitempty"`
	Server      string `json:"server,omitempty"`
	HASSH       string `json:"hassh,omitempty"`
	HASSHServer string `json:"hassh_server,omitempty"`
}

// NDRFields captures SentinelNDR-specific metadata (custom extension).
type NDRFields struct {
	Detection *NDRDetection `json:"detection,omitempty"`
	HostScore *NDRHostScore `json:"host_score,omitempty"`
	Beacon    *NDRBeacon    `json:"beacon,omitempty"`
	Session   *NDRSession   `json:"session,omitempty"`
}

// NDRDetection captures NDR behavioral detection metadata.
type NDRDetection struct {
	Name      string `json:"name,omitempty"`
	Severity  int    `json:"severity,omitempty"`
	Certainty int    `json:"certainty,omitempty"`
	Category  string `json:"category,omitempty"`
	PcapRef   string `json:"pcap_ref,omitempty"`
}

// NDRHostScore captures NDR per-host threat scoring.
type NDRHostScore struct {
	Threat    int    `json:"threat,omitempty"`
	Certainty int    `json:"certainty,omitempty"`
	Quadrant  string `json:"quadrant,omitempty"`
}

// NDRBeacon captures NDR beacon detection metadata.
type NDRBeacon struct {
	IntervalMean   float64 `json:"interval_mean,omitempty"`
	IntervalStddev float64 `json:"interval_stddev,omitempty"`
}

// NDRSession captures NDR session/connection metadata.
type NDRSession struct {
	ConnState   string  `json:"conn_state,omitempty"`
	CommunityID string  `json:"community_id,omitempty"`
	Duration    float64 `json:"duration,omitempty"`
	BytesOrig   int64   `json:"bytes_orig,omitempty"`
	BytesResp   int64   `json:"bytes_resp,omitempty"`
	PacketsOrig int64   `json:"packets_orig,omitempty"`
	PacketsResp int64   `json:"packets_resp,omitempty"`
}
