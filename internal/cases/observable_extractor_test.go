package cases

import (
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

func TestExtractNetworkAlert(t *testing.T) {
	event := &common.ECSEvent{
		Source:      &common.EndpointFields{IP: "192.168.1.100", Domain: "workstation.corp"},
		Destination: &common.EndpointFields{IP: "10.0.0.50", Domain: "server.corp"},
		Network:     &common.NetworkFields{CommunityID: "1:abc123"},
	}

	obs := ExtractObservables(event, "alert-001")

	assertHasObservable(t, obs, ObservableIP, "192.168.1.100")
	assertHasObservable(t, obs, ObservableIP, "10.0.0.50")
	assertHasObservable(t, obs, ObservableDomain, "workstation.corp")
	assertHasObservable(t, obs, ObservableDomain, "server.corp")
	assertHasObservable(t, obs, ObservableCommunityID, "1:abc123")

	// Verify all tagged with source alert ID.
	for _, o := range obs {
		if o.Source != "alert-001" {
			t.Errorf("expected source %q, got %q", "alert-001", o.Source)
		}
	}
}

func TestExtractFileAlert(t *testing.T) {
	event := &common.ECSEvent{
		File: &common.FileFields{
			Name: "malware.exe",
			Path: "C:\\Users\\jsmith\\malware.exe",
			Hash: &common.HashFields{
				MD5:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		Process: &common.ProcessFields{
			Name: "malware.exe",
			Parent: &common.ParentProcess{
				Name: "explorer.exe",
			},
		},
	}

	obs := ExtractObservables(event, "alert-002")

	assertHasObservable(t, obs, ObservableHash, "d41d8cd98f00b204e9800998ecf8427e")
	assertHasObservable(t, obs, ObservableHash, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
	assertHasObservable(t, obs, ObservableHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	assertHasObservable(t, obs, ObservableProcess, "malware.exe")
	assertHasObservable(t, obs, ObservableProcess, "explorer.exe")
}

func TestExtractDLPAlert(t *testing.T) {
	event := &common.ECSEvent{
		User: &common.UserFields{Name: "jsmith"},
		File: &common.FileFields{
			Path: "/data/sensitive/report.xlsx",
		},
	}

	obs := ExtractObservables(event, "alert-003")

	assertHasObservable(t, obs, ObservableUser, "jsmith")
	// File path without hashes shouldn't generate hash observables.
	assertNoObservable(t, obs, ObservableHash)
}

func TestExtractTLSObservables(t *testing.T) {
	event := &common.ECSEvent{
		TLS: &common.TLSFields{
			Client: &common.TLSClientFields{
				JA3:        "abc123ja3",
				JA4:        "def456ja4",
				ServerName: "evil.example.com",
			},
		},
	}

	obs := ExtractObservables(event, "alert-004")

	assertHasObservable(t, obs, ObservableJA3, "abc123ja3")
	assertHasObservable(t, obs, ObservableJA4, "def456ja4")
	assertHasObservable(t, obs, ObservableSNI, "evil.example.com")
}

func TestExtractDNSObservable(t *testing.T) {
	event := &common.ECSEvent{
		DNS: &common.DNSFields{
			Question: &common.DNSQuestion{Name: "c2.badguy.com"},
		},
	}

	obs := ExtractObservables(event, "alert-005")
	assertHasObservable(t, obs, ObservableDomain, "c2.badguy.com")
}

func TestExtractHostIPs(t *testing.T) {
	event := &common.ECSEvent{
		Host: &common.HostFields{
			IP: []string{"10.1.1.1", "fe80::1"},
		},
	}

	obs := ExtractObservables(event, "alert-006")
	assertHasObservable(t, obs, ObservableIP, "10.1.1.1")
	assertHasObservable(t, obs, ObservableIP, "fe80::1")
}

func TestExtractNDRSessionCommunityID(t *testing.T) {
	event := &common.ECSEvent{
		NDR: &common.NDRFields{
			Session: &common.NDRSession{CommunityID: "1:ndr-cid"},
		},
	}

	obs := ExtractObservables(event, "alert-007")
	assertHasObservable(t, obs, ObservableCommunityID, "1:ndr-cid")
}

func TestExtractEmptyEvent(t *testing.T) {
	event := &common.ECSEvent{}
	obs := ExtractObservables(event, "alert-empty")
	if len(obs) != 0 {
		t.Errorf("expected 0 observables from empty event, got %d", len(obs))
	}
}

func TestExtractInvalidIP(t *testing.T) {
	event := &common.ECSEvent{
		Source: &common.EndpointFields{IP: "not-an-ip"},
	}
	obs := ExtractObservables(event, "alert-008")
	assertNoObservable(t, obs, ObservableIP)
}

func TestExtractSourceDestUsers(t *testing.T) {
	event := &common.ECSEvent{
		Source: &common.EndpointFields{
			User: &common.UserFields{Name: "srcuser"},
		},
		Destination: &common.EndpointFields{
			User: &common.UserFields{Name: "dstuser"},
		},
	}

	obs := ExtractObservables(event, "alert-009")
	assertHasObservable(t, obs, ObservableUser, "srcuser")
	assertHasObservable(t, obs, ObservableUser, "dstuser")
}

func TestDeduplicateObservables(t *testing.T) {
	obs := []Observable{
		{Type: ObservableIP, Value: "192.168.1.1", Source: "alert-001"},
		{Type: ObservableIP, Value: "192.168.1.1", Source: "alert-002"},
		{Type: ObservableIP, Value: "10.0.0.1", Source: "alert-001"},
		{Type: ObservableDomain, Value: "evil.com", Source: "alert-001"},
		{Type: ObservableDomain, Value: "evil.com", Source: "alert-003"},
	}

	deduped := DeduplicateObservables(obs)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 unique observables, got %d", len(deduped))
	}

	// First occurrence should be kept.
	if deduped[0].Source != "alert-001" {
		t.Errorf("expected first IP to have source alert-001, got %q", deduped[0].Source)
	}
}

func TestMergeObservables(t *testing.T) {
	existing := []Observable{
		{Type: ObservableIP, Value: "192.168.1.1", Source: "alert-001"},
		{Type: ObservableHash, Value: "abc123", Source: "alert-001"},
	}
	incoming := []Observable{
		{Type: ObservableIP, Value: "192.168.1.1", Source: "alert-002"}, // dup
		{Type: ObservableIP, Value: "10.0.0.1", Source: "alert-002"},    // new
		{Type: ObservableDomain, Value: "evil.com", Source: "alert-002"},
	}

	merged := MergeObservables(existing, incoming)
	if len(merged) != 4 {
		t.Fatalf("expected 4 merged observables, got %d", len(merged))
	}

	assertHasObservable(t, merged, ObservableIP, "192.168.1.1")
	assertHasObservable(t, merged, ObservableHash, "abc123")
	assertHasObservable(t, merged, ObservableIP, "10.0.0.1")
	assertHasObservable(t, merged, ObservableDomain, "evil.com")
}

func TestExtractFromMultipleCrossSources(t *testing.T) {
	events := []*common.ECSEvent{
		{
			Source:      &common.EndpointFields{IP: "192.168.1.100"},
			Destination: &common.EndpointFields{IP: "10.0.0.50"},
		},
		{
			Source:      &common.EndpointFields{IP: "192.168.1.100"}, // dup
			Destination: &common.EndpointFields{IP: "172.16.0.1"},    // new
			User:        &common.UserFields{Name: "jsmith"},
		},
		{
			File: &common.FileFields{
				Hash: &common.HashFields{SHA256: "abc123"},
			},
			Process: &common.ProcessFields{Name: "cmd.exe"},
		},
	}

	obs := ExtractFromMultiple(events, "alert-multi")

	// 192.168.1.100 (deduped), 10.0.0.50, 172.16.0.1, jsmith, abc123, cmd.exe = 6
	if len(obs) != 6 {
		t.Fatalf("expected 6 deduplicated observables, got %d", len(obs))
	}

	assertHasObservable(t, obs, ObservableIP, "192.168.1.100")
	assertHasObservable(t, obs, ObservableIP, "10.0.0.50")
	assertHasObservable(t, obs, ObservableIP, "172.16.0.1")
	assertHasObservable(t, obs, ObservableUser, "jsmith")
	assertHasObservable(t, obs, ObservableHash, "abc123")
	assertHasObservable(t, obs, ObservableProcess, "cmd.exe")
}

// --- Test helpers ---

func assertHasObservable(t *testing.T, obs []Observable, typ, value string) {
	t.Helper()
	for _, o := range obs {
		if o.Type == typ && o.Value == value {
			return
		}
	}
	t.Errorf("expected observable {type: %q, value: %q} not found in %v", typ, value, obs)
}

func assertNoObservable(t *testing.T, obs []Observable, typ string) {
	t.Helper()
	for _, o := range obs {
		if o.Type == typ {
			t.Errorf("expected no observable of type %q, found value %q", typ, o.Value)
			return
		}
	}
}
