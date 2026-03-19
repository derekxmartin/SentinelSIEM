package sources

import "time"

// SourceConfig represents a registered log source in AkesoSIEM.
// Each source maps to a document in the akeso-sources ES index.
type SourceConfig struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`           // EDR, AV, DLP, NDR, Firewall, Syslog, Cloud, IAM, Email, Network, IDS
	Protocol      string    `json:"protocol"`       // http, syslog_tcp, syslog_udp, syslog_tls
	Port          int       `json:"port,omitempty"`  // listening port (syslog sources)
	Parser        string    `json:"parser"`          // source_type value for normalization engine
	ExpectedHosts []string  `json:"expected_hosts"`  // IPs/hostnames expected to send events
	APIKeyID      string    `json:"api_key_id"`      // linked API key for authentication
	Status        string    `json:"status"`          // active, disabled, decommissioned
	Description   string    `json:"description,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Valid source types.
var ValidSourceTypes = map[string]bool{
	"EDR": true, "AV": true, "DLP": true, "NDR": true,
	"Firewall": true, "Syslog": true, "Cloud": true,
	"IAM": true, "Email": true, "Network": true, "IDS": true,
}

// Valid protocols.
var ValidProtocols = map[string]bool{
	"http": true, "syslog_tcp": true, "syslog_udp": true, "syslog_tls": true,
}

// Valid statuses.
var ValidStatuses = map[string]bool{
	"active": true, "disabled": true, "decommissioned": true,
}

// CreateSourceRequest is the JSON body for POST /api/v1/sources.
type CreateSourceRequest struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Protocol      string   `json:"protocol"`
	Port          int      `json:"port,omitempty"`
	Parser        string   `json:"parser"`
	ExpectedHosts []string `json:"expected_hosts,omitempty"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// UpdateSourceRequest is the JSON body for PUT /api/v1/sources/{id}.
type UpdateSourceRequest struct {
	Name          *string  `json:"name,omitempty"`
	Protocol      *string  `json:"protocol,omitempty"`
	Port          *int     `json:"port,omitempty"`
	Parser        *string  `json:"parser,omitempty"`
	ExpectedHosts []string `json:"expected_hosts,omitempty"`
	Status        *string  `json:"status,omitempty"`
	Description   *string  `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// TestParserRequest is the JSON body for POST /api/v1/sources/{id}/test-parser.
type TestParserRequest struct {
	SampleLog string `json:"sample_log"`
}

// TestParserResponse is the JSON response for test-parser.
type TestParserResponse struct {
	Success bool   `json:"success"`
	ECSOutput any   `json:"ecs_output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SourceResponse wraps a source config for API responses.
type SourceResponse struct {
	Source      *SourceConfig `json:"source"`
	PlaintextKey string      `json:"plaintext_key,omitempty"` // only on create
}

// Validate checks a CreateSourceRequest for required fields.
func (r *CreateSourceRequest) Validate() string {
	if r.Name == "" {
		return "name is required"
	}
	if !ValidSourceTypes[r.Type] {
		return "invalid source type"
	}
	if !ValidProtocols[r.Protocol] {
		return "invalid protocol"
	}
	if r.Parser == "" {
		return "parser is required"
	}
	return ""
}
