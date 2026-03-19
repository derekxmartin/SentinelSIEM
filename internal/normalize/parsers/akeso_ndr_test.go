package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// makeNDRJSON builds a raw JSON payload for an NDR event.
// fields are merged at the top level (NDR events are pre-normalized).
func makeNDRJSON(eventType string, extra string) json.RawMessage {
	base := fmt.Sprintf(`{
		"source_type": "akeso_ndr",
		"timestamp": "2026-03-15T10:30:00Z",
		"event_type": %q`, eventType)
	if extra != "" {
		base += "," + extra
	}
	base += "}"
	return json.RawMessage(base)
}

func TestNDRSourceType(t *testing.T) {
	p := NewAkesoNDRParser()
	if got := p.SourceType(); got != "akeso_ndr" {
		t.Errorf("SourceType() = %q, want %q", got, "akeso_ndr")
	}
}

func TestNDREventIngested(t *testing.T) {
	p := NewAkesoNDRParser()
	before := time.Now().UTC()
	raw := makeNDRJSON("ndr:session", `
		"source":{"ip":"10.0.0.1","port":12345},
		"destination":{"ip":"10.0.0.2","port":80},
		"network":{"protocol":"tcp"},
		"ndr":{"session":{"community_id":"1:abc123","conn_state":"SF","duration":1.5}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	after := time.Now().UTC()

	if ev.Event.Ingested == nil {
		t.Fatal("event.ingested not set")
	}
	if ev.Event.Ingested.Before(before) || ev.Event.Ingested.After(after) {
		t.Errorf("event.ingested %v not between %v and %v", *ev.Event.Ingested, before, after)
	}
}

// ============================================================
// Per-event-type round-trip tests
// ============================================================

func TestNDRSession(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:session", `
		"source":{"ip":"192.168.1.10","port":54321},
		"destination":{"ip":"10.0.0.5","port":443},
		"network":{"protocol":"tls","transport":"tcp","bytes":98765,"packets":42},
		"ndr":{"session":{"community_id":"1:abc/def+123","conn_state":"SF","duration":3.14,"bytes_orig":50000,"bytes_resp":48765,"packets_orig":20,"packets_resp":22}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network_connection")
	assertType(t, ev, "connection")
	assertNDREqual(t, "event.action", ev.Event.Action, "session")

	// Source/Destination.
	assertNDREqual(t, "source.ip", ev.Source.IP, "192.168.1.10")
	assertNDREqual(t, "source.port", fmt.Sprint(ev.Source.Port), "54321")
	assertNDREqual(t, "destination.ip", ev.Destination.IP, "10.0.0.5")
	assertNDREqual(t, "destination.port", fmt.Sprint(ev.Destination.Port), "443")

	// Network.
	assertNDREqual(t, "network.protocol", ev.Network.Protocol, "tls")
	assertNDREqual(t, "network.transport", ev.Network.Transport, "tcp")
	assertNDREqual(t, "network.community_id", ev.Network.CommunityID, "1:abc/def+123")

	// NDR session.
	if ev.NDR == nil || ev.NDR.Session == nil {
		t.Fatal("ndr.session is nil")
	}
	assertNDREqual(t, "ndr.session.community_id", ev.NDR.Session.CommunityID, "1:abc/def+123")
	assertNDREqual(t, "ndr.session.conn_state", ev.NDR.Session.ConnState, "SF")
	if ev.NDR.Session.Duration != 3.14 {
		t.Errorf("ndr.session.duration = %v, want 3.14", ev.NDR.Session.Duration)
	}
}

func TestNDRDNS(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:dns", `
		"source":{"ip":"10.0.0.1","port":53241},
		"destination":{"ip":"8.8.8.8","port":53},
		"dns":{
			"question":{"name":"evil.example.com","type":"A"},
			"answers":[{"data":"1.2.3.4","type":"A","ttl":300}],
			"response_code":"NOERROR",
			"header_flags":["QR","RD","RA"]
		}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "dns_query")

	if ev.DNS == nil {
		t.Fatal("dns is nil")
	}
	assertNDREqual(t, "dns.question.name", ev.DNS.Question.Name, "evil.example.com")
	assertNDREqual(t, "dns.question.type", ev.DNS.Question.Type, "A")
	assertNDREqual(t, "dns.response_code", ev.DNS.ResponseCode, "NOERROR")
	if len(ev.DNS.Answers) != 1 {
		t.Fatalf("dns.answers length = %d, want 1", len(ev.DNS.Answers))
	}
	assertNDREqual(t, "dns.answers[0].data", ev.DNS.Answers[0].Data, "1.2.3.4")
}

func TestNDRHTTP(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:http", `
		"source":{"ip":"10.0.0.1","port":50000},
		"destination":{"ip":"93.184.216.34","port":80},
		"http":{
			"request":{"method":"GET"},
			"response":{"status_code":200,"body":{"bytes":12345}}
		},
		"url":{"full":"http://example.com/page"},
		"user_agent":{"original":"Mozilla/5.0"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertCategory(t, ev, "web")
	assertNDREqual(t, "event.action", ev.Event.Action, "http_request")
	assertNDREqual(t, "http.request.method", ev.HTTP.Request.Method, "GET")
	if ev.HTTP.Response.StatusCode != 200 {
		t.Errorf("http.response.status_code = %d, want 200", ev.HTTP.Response.StatusCode)
	}
	assertNDREqual(t, "url.full", ev.URL.Full, "http://example.com/page")
	assertNDREqual(t, "user_agent.original", ev.UserAgent.Original, "Mozilla/5.0")
}

func TestNDRTLS(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:tls", `
		"source":{"ip":"10.0.0.1","port":50000},
		"destination":{"ip":"93.184.216.34","port":443},
		"tls":{
			"version":"1.3",
			"cipher":"TLS_AES_256_GCM_SHA384",
			"client":{"ja3":"abc123def456","ja4":"t13d1517h2_8daaf6152771_b0da82dd1658","server_name":"example.com"},
			"server":{"ja3s":"def789abc012","ja4s":"t130200_1301_234ea6891581"}
		}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "tls_handshake")
	assertNDREqual(t, "tls.version", ev.TLS.Version, "1.3")
	assertNDREqual(t, "tls.cipher", ev.TLS.Cipher, "TLS_AES_256_GCM_SHA384")
	assertNDREqual(t, "tls.client.ja3", ev.TLS.Client.JA3, "abc123def456")
	assertNDREqual(t, "tls.client.ja4", ev.TLS.Client.JA4, "t13d1517h2_8daaf6152771_b0da82dd1658")
	assertNDREqual(t, "tls.client.server_name", ev.TLS.Client.ServerName, "example.com")
	assertNDREqual(t, "tls.server.ja3s", ev.TLS.Server.JA3S, "def789abc012")
	assertNDREqual(t, "tls.server.ja4s", ev.TLS.Server.JA4S, "t130200_1301_234ea6891581")
}

func TestNDRSMB(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:smb", `
		"source":{"ip":"10.0.0.5","port":49152},
		"destination":{"ip":"10.0.0.10","port":445},
		"smb":{"version":"3.1.1","action":"read","filename":"secrets.docx","path":"\\\\DC01\\share","domain":"CORP","username":"admin"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "smb_read")
	assertNDREqual(t, "smb.version", ev.SMB.Version, "3.1.1")
	assertNDREqual(t, "smb.filename", ev.SMB.Filename, "secrets.docx")
	assertNDREqual(t, "smb.domain", ev.SMB.Domain, "CORP")
}

func TestNDRKerberos(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:kerberos", `
		"source":{"ip":"10.0.0.5","port":49200},
		"destination":{"ip":"10.0.0.1","port":88},
		"kerberos":{"request_type":"AS-REQ","client":"admin@CORP.LOCAL","service":"krbtgt/CORP.LOCAL","cipher":"AES256-CTS-HMAC-SHA1-96","success":true}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertCategory(t, ev, "authentication")
	assertNDREqual(t, "kerberos.request_type", ev.Kerberos.RequestType, "AS-REQ")
	assertNDREqual(t, "kerberos.client", ev.Kerberos.Client, "admin@CORP.LOCAL")
	assertNDREqual(t, "kerberos.cipher", ev.Kerberos.Cipher, "AES256-CTS-HMAC-SHA1-96")
	if ev.Kerberos.Success == nil || !*ev.Kerberos.Success {
		t.Error("kerberos.success should be true")
	}
}

func TestNDRKerberosFailure(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:kerberos", `
		"source":{"ip":"10.0.0.5","port":49200},
		"destination":{"ip":"10.0.0.1","port":88},
		"kerberos":{"request_type":"TGS-REQ","client":"user@CORP.LOCAL","service":"cifs/DC01","cipher":"RC4-HMAC","success":false,"error_code":"KDC_ERR_S_PRINCIPAL_UNKNOWN"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if ev.Kerberos.Success == nil || *ev.Kerberos.Success {
		t.Error("kerberos.success should be false")
	}
	assertNDREqual(t, "kerberos.error_code", ev.Kerberos.ErrorCode, "KDC_ERR_S_PRINCIPAL_UNKNOWN")
}

func TestNDRSSH(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:ssh", `
		"source":{"ip":"10.0.0.5","port":49300},
		"destination":{"ip":"10.0.0.20","port":22},
		"ssh":{"client":"SSH-2.0-OpenSSH_8.9","server":"SSH-2.0-OpenSSH_9.1","hassh":"abc123","hassh_server":"def456"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "ssh_connection")
	assertNDREqual(t, "ssh.client", ev.SSH.Client, "SSH-2.0-OpenSSH_8.9")
	assertNDREqual(t, "ssh.hassh", ev.SSH.HASSH, "abc123")
	assertNDREqual(t, "ssh.hassh_server", ev.SSH.HASSHServer, "def456")
}

func TestNDRSMTP(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:smtp", `
		"source":{"ip":"10.0.0.5","port":49400},
		"destination":{"ip":"10.0.0.25","port":25}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "smtp")
}

func TestNDRRDP(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:rdp", `
		"source":{"ip":"10.0.0.5","port":49500},
		"destination":{"ip":"10.0.0.30","port":3389}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "rdp")
}

func TestNDRNTLM(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:ntlm", `
		"source":{"ip":"10.0.0.5","port":49600},
		"destination":{"ip":"10.0.0.1","port":445}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertCategory(t, ev, "network")
	assertCategory(t, ev, "authentication")
	assertNDREqual(t, "event.action", ev.Event.Action, "ntlm")
}

func TestNDRLDAP(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:ldap", `
		"source":{"ip":"10.0.0.5","port":49700},
		"destination":{"ip":"10.0.0.1","port":389}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "ldap")
}

func TestNDRDCERPC(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:dcerpc", `
		"source":{"ip":"10.0.0.5","port":49800},
		"destination":{"ip":"10.0.0.1","port":135}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertCategory(t, ev, "network")
	assertNDREqual(t, "event.action", ev.Event.Action, "dcerpc")
}

func TestNDRDetection(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:detection", `
		"source":{"ip":"10.0.0.5","port":49900},
		"destination":{"ip":"198.51.100.1","port":443},
		"threat":{"technique":[{"id":"T1071","name":"Application Layer Protocol"}]},
		"ndr":{"detection":{"name":"C2 Beacon Detected","severity":8,"certainty":90,"category":"command_and_control","pcap_ref":"capture_20260315_001.pcap"}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertNDREqual(t, "event.kind", ev.Event.Kind, "alert")
	assertCategory(t, ev, "intrusion_detection")
	assertNDREqual(t, "ndr.detection.name", ev.NDR.Detection.Name, "C2 Beacon Detected")
	if ev.NDR.Detection.Severity != 8 {
		t.Errorf("ndr.detection.severity = %d, want 8", ev.NDR.Detection.Severity)
	}
	if ev.NDR.Detection.Certainty != 90 {
		t.Errorf("ndr.detection.certainty = %d, want 90", ev.NDR.Detection.Certainty)
	}
	assertNDREqual(t, "ndr.detection.pcap_ref", ev.NDR.Detection.PcapRef, "capture_20260315_001.pcap")

	// MITRE technique.
	if ev.Threat == nil || len(ev.Threat.Technique) == 0 {
		t.Fatal("threat.technique missing")
	}
	assertNDREqual(t, "threat.technique[0].id", ev.Threat.Technique[0].ID, "T1071")
}

func TestNDRSignature(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:signature", `
		"source":{"ip":"10.0.0.5","port":49950},
		"destination":{"ip":"198.51.100.5","port":80},
		"ndr":{"detection":{"name":"ET MALWARE Win32/Agent.XYZ CnC Beacon","severity":7,"certainty":95}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertNDREqual(t, "event.kind", ev.Event.Kind, "alert")
	assertCategory(t, ev, "intrusion_detection")
	assertNDREqual(t, "ndr.detection.name", ev.NDR.Detection.Name, "ET MALWARE Win32/Agent.XYZ CnC Beacon")
}

func TestNDRHostScore(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:host_score", `
		"host":{"name":"workstation-042","ip":["10.0.0.42"]},
		"ndr":{"host_score":{"threat":85,"certainty":92,"quadrant":"critical"}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	assertCategory(t, ev, "host")
	assertNDREqual(t, "event.action", ev.Event.Action, "host_score_update")
	assertNDREqual(t, "host.name", ev.Host.Name, "workstation-042")
	if ev.NDR.HostScore.Threat != 85 {
		t.Errorf("ndr.host_score.threat = %d, want 85", ev.NDR.HostScore.Threat)
	}
	if ev.NDR.HostScore.Certainty != 92 {
		t.Errorf("ndr.host_score.certainty = %d, want 92", ev.NDR.HostScore.Certainty)
	}
	assertNDREqual(t, "ndr.host_score.quadrant", ev.NDR.HostScore.Quadrant, "critical")
}

// ============================================================
// Adversarial / edge-case tests
// ============================================================

func TestNDRMalformedJSON(t *testing.T) {
	p := NewAkesoNDRParser()
	_, err := p.Parse(json.RawMessage(`{not json at all`))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestNDRBinaryGarbage(t *testing.T) {
	p := NewAkesoNDRParser()
	_, err := p.Parse(json.RawMessage([]byte{0xFF, 0xFE, 0x00, 0x01}))
	if err == nil {
		t.Error("expected error for binary garbage")
	}
}

func TestNDREmptyObject(t *testing.T) {
	p := NewAkesoNDRParser()
	ev, err := p.Parse(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still return an event with event.ingested set.
	if ev.Event == nil || ev.Event.Ingested == nil {
		t.Error("event.ingested should be set even for empty object")
	}
}

func TestNDRMissingEventType(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := json.RawMessage(`{"timestamp":"2026-03-15T10:00:00Z"}`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall through to default branch with empty event_type.
	if ev.Event.Action != "" {
		t.Errorf("event.action = %q, want empty for no event_type", ev.Event.Action)
	}
}

func TestNDRUnknownEventType(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:future_protocol", "")
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNDREqual(t, "event.action", ev.Event.Action, "ndr:future_protocol")
}

func TestNDRSessionMissingFields(t *testing.T) {
	p := NewAkesoNDRParser()
	// Session with no source, destination, or ndr fields.
	raw := makeNDRJSON("ndr:session", "")
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still parse — missing fields are warned, not errors.
	assertCategory(t, ev, "network_connection")
	if ev.Source != nil {
		t.Error("source should be nil when not provided")
	}
}

func TestNDRDetectionNoMITRE(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:detection", `
		"ndr":{"detection":{"name":"Suspicious Traffic","severity":5,"certainty":70}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNDREqual(t, "event.kind", ev.Event.Kind, "alert")
	// No threat techniques — should not error.
	if ev.Threat != nil && len(ev.Threat.Technique) > 0 {
		t.Error("threat.technique should be empty when not provided")
	}
}

func TestNDRHostScoreInvalidQuadrant(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:host_score", `
		"host":{"name":"host-1"},
		"ndr":{"host_score":{"threat":50,"certainty":50,"quadrant":"definitely_not_a_quadrant"}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Parser should accept any quadrant string (validation is advisory).
	assertNDREqual(t, "ndr.host_score.quadrant", ev.NDR.HostScore.Quadrant, "definitely_not_a_quadrant")
}

func TestNDRHostScoreMissingQuadrant(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:host_score", `
		"host":{"name":"host-1"},
		"ndr":{"host_score":{"threat":50,"certainty":50}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse with warning about missing quadrant.
	if ev.NDR.HostScore.Quadrant != "" {
		t.Error("quadrant should be empty when not provided")
	}
}

func TestNDRSessionZeroDuration(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:session", `
		"source":{"ip":"10.0.0.1","port":12345},
		"destination":{"ip":"10.0.0.2","port":80},
		"ndr":{"session":{"community_id":"1:zero","conn_state":"REJ","duration":0,"bytes_orig":0,"bytes_resp":0}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if ev.NDR.Session.Duration != 0 {
		t.Errorf("duration = %v, want 0", ev.NDR.Session.Duration)
	}
}

func TestNDRSessionCommunityIDSynced(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:session", `
		"source":{"ip":"10.0.0.1","port":12345},
		"destination":{"ip":"10.0.0.2","port":80},
		"ndr":{"session":{"community_id":"1:xyz789","conn_state":"SF"}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	// community_id should be synced to network.community_id.
	if ev.Network == nil {
		t.Fatal("network should be initialized for community_id sync")
	}
	assertNDREqual(t, "network.community_id", ev.Network.CommunityID, "1:xyz789")
}

func TestNDRSessionCommunityIDPreserved(t *testing.T) {
	p := NewAkesoNDRParser()
	// When network.community_id is already set, it should not be overwritten.
	raw := makeNDRJSON("ndr:session", `
		"source":{"ip":"10.0.0.1","port":12345},
		"destination":{"ip":"10.0.0.2","port":80},
		"network":{"community_id":"1:already_set"},
		"ndr":{"session":{"community_id":"1:different","conn_state":"SF"}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertNDREqual(t, "network.community_id", ev.Network.CommunityID, "1:already_set")
}

func TestNDRTimestampFallback(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := json.RawMessage(`{"event_type":"ndr:session","timestamp":"not-a-timestamp","source":{"ip":"1.2.3.4"},"destination":{"ip":"5.6.7.8"},"ndr":{"session":{"community_id":"1:x"}}}`)
	before := time.Now().UTC()
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	after := time.Now().UTC()
	if ev.Timestamp.Before(before) || ev.Timestamp.After(after) {
		t.Errorf("timestamp not set to now on parse failure: %v", ev.Timestamp)
	}
}

func TestNDRTimestampNano(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:dns", `
		"timestamp":"2026-03-15T10:30:00.123456789Z",
		"dns":{"question":{"name":"test.com","type":"A"}}
	`)
	// Override the timestamp in the JSON.
	raw = json.RawMessage(`{"event_type":"ndr:dns","timestamp":"2026-03-15T10:30:00.123456789Z","dns":{"question":{"name":"test.com","type":"A"}}}`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if ev.Timestamp.Nanosecond() != 123456789 {
		t.Errorf("timestamp nanoseconds = %d, want 123456789", ev.Timestamp.Nanosecond())
	}
}

func TestNDRPreNormalizedCategoryPreserved(t *testing.T) {
	p := NewAkesoNDRParser()
	// If the NDR export already set event.category, the parser should preserve it.
	raw := json.RawMessage(`{
		"event_type":"ndr:dns",
		"timestamp":"2026-03-15T10:00:00Z",
		"event":{"category":["network","dns"],"type":["protocol","info"]},
		"dns":{"question":{"name":"test.com"}}
	}`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	// Should preserve the pre-set category, not override.
	if len(ev.Event.Category) != 2 || ev.Event.Category[0] != "network" || ev.Event.Category[1] != "dns" {
		t.Errorf("event.category = %v, want [network dns]", ev.Event.Category)
	}
}

func TestNDRRoundTripJSON(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:tls", `
		"source":{"ip":"10.0.0.1","port":50000},
		"destination":{"ip":"93.184.216.34","port":443},
		"tls":{"version":"1.3","cipher":"TLS_AES_256_GCM_SHA384","client":{"ja3":"abc","server_name":"example.com"}},
		"ndr":{"beacon":{"interval_mean":60.5,"interval_stddev":2.1}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Marshal back to JSON and verify key fields survive.
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var roundTrip map[string]interface{}
	if err := json.Unmarshal(out, &roundTrip); err != nil {
		t.Fatalf("Unmarshal roundtrip: %v", err)
	}

	// Verify TLS fields survived.
	tls, ok := roundTrip["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("tls missing from round-trip JSON")
	}
	if v, _ := tls["version"].(string); v != "1.3" {
		t.Errorf("tls.version roundtrip = %q, want 1.3", v)
	}

	// Verify NDR beacon fields survived.
	ndr, ok := roundTrip["ndr"].(map[string]interface{})
	if !ok {
		t.Fatal("ndr missing from round-trip JSON")
	}
	beacon, ok := ndr["beacon"].(map[string]interface{})
	if !ok {
		t.Fatal("ndr.beacon missing from round-trip JSON")
	}
	if v, _ := beacon["interval_mean"].(float64); v != 60.5 {
		t.Errorf("ndr.beacon.interval_mean roundtrip = %v, want 60.5", v)
	}
}

func TestNDRSMBActionDerivation(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:smb", `
		"source":{"ip":"10.0.0.1"},
		"destination":{"ip":"10.0.0.2","port":445},
		"smb":{"action":"write","filename":"data.xlsx"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertNDREqual(t, "event.action", ev.Event.Action, "smb_write")
}

func TestNDRSMBNoAction(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:smb", `
		"source":{"ip":"10.0.0.1"},
		"destination":{"ip":"10.0.0.2","port":445},
		"smb":{"version":"2.1"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	assertNDREqual(t, "event.action", ev.Event.Action, "smb")
}

func TestNDRDNSMissingQuestionName(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:dns", `
		"dns":{"question":{"type":"A"},"response_code":"NOERROR"}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still parse — warning logged for missing question.name.
	assertCategory(t, ev, "network")
}

func TestNDRVeryLargePayload(t *testing.T) {
	p := NewAkesoNDRParser()
	// DNS with many answers.
	answers := make([]string, 100)
	for i := range answers {
		answers[i] = fmt.Sprintf(`{"data":"10.0.%d.%d","type":"A","ttl":300}`, i/256, i%256)
	}
	answersJSON := "[" + strings.Join(answers, ",") + "]"
	raw := json.RawMessage(fmt.Sprintf(`{
		"event_type":"ndr:dns",
		"timestamp":"2026-03-15T10:00:00Z",
		"dns":{"question":{"name":"bulk.example.com","type":"A"},"answers":%s,"response_code":"NOERROR"}
	}`, answersJSON))

	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(ev.DNS.Answers) != 100 {
		t.Errorf("dns.answers length = %d, want 100", len(ev.DNS.Answers))
	}
}

func TestNDRNullFields(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := json.RawMessage(`{
		"event_type":"ndr:session",
		"timestamp":"2026-03-15T10:00:00Z",
		"source":null,
		"destination":null,
		"network":null,
		"ndr":null
	}`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should handle null gracefully.
	assertCategory(t, ev, "network_connection")
	if ev.Source != nil {
		t.Error("source should be nil for null JSON value")
	}
}

func TestNDRExtraFieldsIgnored(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := json.RawMessage(`{
		"event_type":"ndr:session",
		"timestamp":"2026-03-15T10:00:00Z",
		"source":{"ip":"1.2.3.4"},
		"destination":{"ip":"5.6.7.8"},
		"ndr":{"session":{"community_id":"1:x","conn_state":"SF"}},
		"totally_unknown_field":"should not cause error",
		"another_field":{"nested":true}
	}`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCategory(t, ev, "network_connection")
}

func TestNDRDetectionMissingName(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:detection", `
		"ndr":{"detection":{"severity":5}}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse with warning, not error.
	assertNDREqual(t, "event.kind", ev.Event.Kind, "alert")
}

func TestNDRSignatureMissingDetection(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:signature", "")
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNDREqual(t, "event.kind", ev.Event.Kind, "alert")
}

func TestNDRHTTPMissingFields(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:http", `
		"source":{"ip":"10.0.0.1"},
		"destination":{"ip":"10.0.0.2","port":80}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse — warning about missing http fields.
	assertCategory(t, ev, "network")
	if ev.HTTP != nil {
		t.Error("http should be nil when not provided")
	}
}

func TestNDRBeaconFields(t *testing.T) {
	p := NewAkesoNDRParser()
	raw := makeNDRJSON("ndr:detection", `
		"ndr":{
			"detection":{"name":"C2 Beacon","severity":8,"certainty":85},
			"beacon":{"interval_mean":60.0,"interval_stddev":0.5}
		},
		"source":{"ip":"10.0.0.5"},
		"destination":{"ip":"198.51.100.1","port":443}
	`)
	ev, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if ev.NDR.Beacon == nil {
		t.Fatal("ndr.beacon should not be nil")
	}
	if ev.NDR.Beacon.IntervalMean != 60.0 {
		t.Errorf("ndr.beacon.interval_mean = %v, want 60.0", ev.NDR.Beacon.IntervalMean)
	}
	if ev.NDR.Beacon.IntervalStddev != 0.5 {
		t.Errorf("ndr.beacon.interval_stddev = %v, want 0.5", ev.NDR.Beacon.IntervalStddev)
	}
}

// ============================================================
// Test helpers
// ============================================================

func assertNDREqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func assertCategory(t *testing.T, ev *common.ECSEvent, want string) {
	t.Helper()
	if ev.Event == nil {
		t.Fatalf("event is nil, expected category %q", want)
	}
	for _, c := range ev.Event.Category {
		if c == want {
			return
		}
	}
	t.Errorf("event.category = %v, want to contain %q", ev.Event.Category, want)
}

func assertType(t *testing.T, ev *common.ECSEvent, want string) {
	t.Helper()
	if ev.Event == nil {
		t.Fatalf("event is nil, expected type %q", want)
	}
	for _, tp := range ev.Event.Type {
		if tp == want {
			return
		}
	}
	t.Errorf("event.type = %v, want to contain %q", ev.Event.Type, want)
}
