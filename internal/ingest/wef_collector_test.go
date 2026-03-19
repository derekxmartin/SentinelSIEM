package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/config"
)

// ============================================================================
// Test helpers
// ============================================================================

func makeWEFServer(handler EventHandler) (*httptest.Server, *HTTPListener) {
	cfg := config.IngestConfig{
		HTTPAddr: "127.0.0.1",
		HTTPPort: 0,
		APIKeys:  []string{"test-key"},
	}
	listener := NewHTTPListener(cfg, handler)
	srv := httptest.NewServer(listener.Router())
	return srv, listener
}

func wefPost(srv *httptest.Server, body string, contentType string, apiKey string) *http.Response {
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/ingest/wef", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func sampleXMLEvent(eventID int, channel string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>%d</EventID>
    <TimeCreated SystemTime="2026-03-14T12:00:00Z" />
    <Channel>%s</Channel>
    <Computer>DC01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>`, eventID, channel)
}

// ============================================================================
// Happy path: single XML event
// ============================================================================

func TestWEFSingleXMLEvent(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := sampleXMLEvent(4624, "Security")
	resp := wefPost(srv, body, "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["accepted"] != float64(1) {
		t.Errorf("accepted = %v, want 1", result["accepted"])
	}

	if len(received) != 1 {
		t.Fatalf("received %d events, want 1", len(received))
	}

	// Verify the event was wrapped in JSON envelope.
	var envelope map[string]string
	json.Unmarshal(received[0], &envelope)
	if envelope["source_type"] != "winevt_xml" {
		t.Errorf("source_type = %q, want %q", envelope["source_type"], "winevt_xml")
	}
	if !strings.Contains(envelope["xml"], "4624") {
		t.Error("xml should contain EventID 4624")
	}
}

// ============================================================================
// Happy path: batch XML (multiple <Event> blocks)
// ============================================================================

func TestWEFBatchXMLEvents(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := fmt.Sprintf(`<Events>
%s
%s
%s
</Events>`, sampleXMLEvent(4624, "Security"), sampleXMLEvent(4688, "Security"), sampleXMLEvent(7045, "System"))

	resp := wefPost(srv, body, "text/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	if len(received) != 3 {
		t.Fatalf("received %d events, want 3", len(received))
	}
}

// ============================================================================
// Happy path: multiple <Event> without wrapper
// ============================================================================

func TestWEFMultipleEventsNoWrapper(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := sampleXMLEvent(4624, "Security") + "\n" + sampleXMLEvent(4688, "Security")

	resp := wefPost(srv, body, "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 2 {
		t.Fatalf("received %d events, want 2", len(received))
	}
}

// ============================================================================
// Happy path: JSON-wrapped XML
// ============================================================================

func TestWEFJSONWrappedXML(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	envelope := map[string]string{
		"source_type": "winevt_xml",
		"xml":         sampleXMLEvent(4624, "Security"),
	}
	data, _ := json.Marshal(envelope)

	resp := wefPost(srv, string(data), "application/json", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Fatalf("received %d events, want 1", len(received))
	}
}

// ============================================================================
// Happy path: Winlogbeat JSON
// ============================================================================

func TestWEFWinlogbeatJSON(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := `{"winlog":{"event_id":4624,"channel":"Security","computer_name":"DC01"},"@timestamp":"2026-03-14T12:00:00Z"}`

	resp := wefPost(srv, body, "application/json", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Fatalf("received %d events, want 1", len(received))
	}

	// Should have been auto-tagged with source_type.
	var probe struct {
		SourceType string `json:"source_type"`
	}
	json.Unmarshal(received[0], &probe)
	if probe.SourceType != "winevt_json" {
		t.Errorf("source_type = %q, want %q", probe.SourceType, "winevt_json")
	}
}

// ============================================================================
// Happy path: large batch (100 events)
// ============================================================================

func TestWEFLargeBatch(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	var sb strings.Builder
	sb.WriteString("<Events>")
	for i := 0; i < 100; i++ {
		sb.WriteString(sampleXMLEvent(4624+i%10, "Security"))
		sb.WriteString("\n")
	}
	sb.WriteString("</Events>")

	resp := wefPost(srv, sb.String(), "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 100 {
		t.Errorf("received %d events, want 100", len(received))
	}
}

// ============================================================================
// Auth tests
// ============================================================================

func TestWEFMissingAPIKey(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	resp := wefPost(srv, sampleXMLEvent(4624, "Security"), "application/xml", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestWEFInvalidAPIKey(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	resp := wefPost(srv, sampleXMLEvent(4624, "Security"), "application/xml", "wrong-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// ============================================================================
// Adversarial: empty body
// ============================================================================

func TestWEFEmptyBody(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	resp := wefPost(srv, "", "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ============================================================================
// Adversarial: malformed XML
// ============================================================================

func TestWEFMalformedXML(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	cases := []struct {
		name string
		body string
	}{
		{"truncated", "<Event><System><EventID>4624</EventID></System>"},
		{"no_event_tags", "<Root><Something>data</Something></Root>"},
		{"empty_events", "<Events></Events>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := wefPost(srv, tc.body, "application/xml", "test-key")
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

// ============================================================================
// Adversarial: binary garbage
// ============================================================================

func TestWEFBinaryGarbage(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	resp := wefPost(srv, "\x00\x01\x02\x03\x04\x05", "", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ============================================================================
// Adversarial: wrong Content-Type with valid body (sniffing fallback)
// ============================================================================

func TestWEFWrongContentTypeXML(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	// Send XML with text/plain Content-Type — should still work via sniffing.
	resp := wefPost(srv, sampleXMLEvent(4624, "Security"), "text/plain", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
}

func TestWEFWrongContentTypeJSON(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	// Send JSON with no Content-Type — should work via sniffing.
	body := `{"winlog":{"event_id":4624,"channel":"Security","computer_name":"DC01"}}`
	resp := wefPost(srv, body, "", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
}

// ============================================================================
// Adversarial: XML with BOM
// ============================================================================

func TestWEFXMLWithBOM(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := "\xef\xbb\xbf" + sampleXMLEvent(4624, "Security")
	resp := wefPost(srv, body, "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
}

// ============================================================================
// Adversarial: Content-Type variations
// ============================================================================

func TestWEFContentTypeVariations(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	xmlBody := sampleXMLEvent(4624, "Security")
	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/xml; charset=utf-8",
		"TEXT/XML",
		"Application/XML",
	}

	for _, ct := range contentTypes {
		received = nil
		t.Run(ct, func(t *testing.T) {
			resp := wefPost(srv, xmlBody, ct, "test-key")
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusAccepted {
				t.Errorf("status = %d, want %d for Content-Type %q", resp.StatusCode, http.StatusAccepted, ct)
			}
			if len(received) != 1 {
				t.Errorf("received %d events, want 1 for Content-Type %q", len(received), ct)
			}
		})
	}
}

// ============================================================================
// Format detection unit tests
// ============================================================================

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{"xml_ct", "application/xml", "<Event>", "xml"},
		{"text_xml_ct", "text/xml", "<Event>", "xml"},
		{"json_ct", "application/json", "{}", "json"},
		{"xml_sniff", "", "<Event>test</Event>", "xml"},
		{"json_sniff_obj", "", `{"key":"val"}`, "json"},
		{"json_sniff_arr", "", `[1,2,3]`, "json"},
		{"xml_sniff_whitespace", "", "  \n  <Event>", "xml"},
		{"bom_xml", "", "\xef\xbb\xbf<Event>", "xml"},
		{"empty", "", "", "unknown"},
		{"binary", "", "\x00\x01", "unknown"},
		{"plain_text", "", "hello world", "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectFormat(tc.contentType, []byte(tc.body))
			if got != tc.want {
				t.Errorf("detectFormat(%q, ...) = %q, want %q", tc.contentType, got, tc.want)
			}
		})
	}
}

// ============================================================================
// XML splitting unit tests
// ============================================================================

func TestExtractEventBlocks(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"single", sampleXMLEvent(4624, "Security"), 1},
		{"two_no_wrapper", sampleXMLEvent(4624, "Security") + sampleXMLEvent(4688, "Security"), 2},
		{"wrapped", "<Events>" + sampleXMLEvent(4624, "Security") + sampleXMLEvent(4688, "Security") + "</Events>", 2},
		{"no_events", "<Root><Data>test</Data></Root>", 0},
		{"empty", "", 0},
		{"event_data_not_event", "<EventData><Data>test</Data></EventData>", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocks := extractEventBlocks([]byte(tc.input))
			if len(blocks) != tc.want {
				t.Errorf("got %d blocks, want %d", len(blocks), tc.want)
			}
		})
	}
}

func TestExtractEventBlocksDoesNotMatchEventData(t *testing.T) {
	// Ensure <EventData> is NOT mistakenly matched as <Event>.
	xml := `<Something>
  <EventData><Data Name="Field">value</Data></EventData>
  <EventRecordID>12345</EventRecordID>
</Something>`

	blocks := extractEventBlocks([]byte(xml))
	if len(blocks) != 0 {
		t.Errorf("should not match <EventData> or <EventRecordID>, got %d blocks", len(blocks))
	}
}

// ============================================================================
// Tag WEF events
// ============================================================================

func TestTagWEFEvents(t *testing.T) {
	// Winlogbeat JSON without source_type.
	raw := json.RawMessage(`{"winlog":{"event_id":4624},"@timestamp":"2026-03-14T12:00:00Z"}`)
	tagged := tagWEFEvents([]json.RawMessage{raw})

	if len(tagged) != 1 {
		t.Fatalf("got %d, want 1", len(tagged))
	}

	var probe struct {
		SourceType string `json:"source_type"`
	}
	json.Unmarshal(tagged[0], &probe)
	if probe.SourceType != "winevt_json" {
		t.Errorf("source_type = %q, want %q", probe.SourceType, "winevt_json")
	}
}

func TestTagWEFEventsPreservesExisting(t *testing.T) {
	raw := json.RawMessage(`{"source_type":"custom","data":"test"}`)
	tagged := tagWEFEvents([]json.RawMessage{raw})

	var probe struct {
		SourceType string `json:"source_type"`
	}
	json.Unmarshal(tagged[0], &probe)
	if probe.SourceType != "custom" {
		t.Errorf("source_type = %q, want %q (preserved)", probe.SourceType, "custom")
	}
}

func TestTagWEFEventsNoWinlog(t *testing.T) {
	raw := json.RawMessage(`{"data":"unknown format"}`)
	tagged := tagWEFEvents([]json.RawMessage{raw})

	var probe struct {
		SourceType string `json:"source_type"`
	}
	json.Unmarshal(tagged[0], &probe)
	if probe.SourceType != "" {
		t.Errorf("source_type = %q, want empty (no auto-tag)", probe.SourceType)
	}
}

// ============================================================================
// Adversarial: NDJSON batch via WEF endpoint
// ============================================================================

func TestWEFNDJSONBatch(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := `{"winlog":{"event_id":4624,"channel":"Security","computer_name":"DC01"}}
{"winlog":{"event_id":4688,"channel":"Security","computer_name":"WS01"}}
{"winlog":{"event_id":7045,"channel":"System","computer_name":"SRV01"}}`

	resp := wefPost(srv, body, "application/json", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 3 {
		t.Errorf("received %d events, want 3", len(received))
	}
}

// ============================================================================
// Adversarial: XML with extra whitespace and comments
// ============================================================================

func TestWEFXMLWithWhitespace(t *testing.T) {
	var received []json.RawMessage
	handler := func(events []json.RawMessage) {
		received = events
	}
	srv, _ := makeWEFServer(handler)
	defer srv.Close()

	body := "\n\n   " + sampleXMLEvent(4624, "Security") + "\n\n"
	resp := wefPost(srv, body, "", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
}

// ============================================================================
// Adversarial: truncated XML (no closing </Event>)
// ============================================================================

func TestWEFTruncatedXML(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	body := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID></System>
  <EventData><Data Name="User">jsmith</Data>`
	// No </Event>

	resp := wefPost(srv, body, "application/xml", "test-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for truncated XML", resp.StatusCode, http.StatusBadRequest)
	}
}

// ============================================================================
// Verify WEF route exists on main ingest router
// ============================================================================

func TestWEFRouteRegistered(t *testing.T) {
	srv, _ := makeWEFServer(nil)
	defer srv.Close()

	// GET should return 405 (method not allowed), proving the route exists.
	resp, err := http.Get(srv.URL + "/api/v1/ingest/wef")
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/v1/ingest/wef: status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}
